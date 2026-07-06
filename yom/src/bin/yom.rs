use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use yara_on_map::config::AppCfg;
use yara_on_map::engine::YaraExternal;
use yara_on_map::metrics::{serve_http, Registry};
use yara_on_map::pager::PageCache;
use yara_on_map::scheduler::Scheduler;
use yara_on_map::types::Finding;
use yara_on_map::watcher::build_tasks;

use crossbeam_channel::bounded;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "yom",
    version = "0.1.1",
    about = "YARA-on-Map: page-wise memory scanner for Windows"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run live scanner
    Run {
        #[arg(long, default_value = "config/default.yaml")]
        config: PathBuf,
        /// Path to YARA rules file
        #[arg(long, default_value = "examples/rules/mz.yar")]
        rules: PathBuf,
        /// PIDs to scan (comma-separated) or 'self' for current process, default: all
        #[arg(long, default_value = "")]
        pids: String,
        /// Duration to run in seconds (0 = one pass)
        #[arg(long, default_value_t = 0u64)]
        duration: u64,
        /// Address to expose /metrics and /healthz
        #[arg(long, default_value = "127.0.0.1:9207")]
        listen: String,
        /// JSONL output file
        #[arg(long)]
        jsonl: Option<PathBuf>,
        /// Enforce mode: quarantine pages
        #[arg(long, default_value_t = false)]
        enforce: bool,
    },
    /// Replay from a JSON mapping file with hex bytes (for CI/offline)
    Replay {
        /// Path to JSON replay file
        #[arg(long)]
        file: PathBuf,
        /// Path to YARA rules
        #[arg(long, default_value = "examples/rules/mz.yar")]
        rules: PathBuf,
        /// Path to YARA executable
        #[arg(long, default_value = "yara64.exe")]
        yara: String,
        /// YARA timeout per replay page
        #[arg(long, default_value_t = 500u64)]
        timeout_ms: u64,
    },
    /// Basic self-check
    SelfCheck,
}

#[derive(Debug, Deserialize)]
struct ReplayFile {
    pid: ReplayPid,
    pages: Vec<ReplayPage>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ReplayPid {
    Text(String),
    Number(u64),
}

#[derive(Debug, Deserialize)]
struct ReplayPage {
    base: String,
    data_hex: String,
}

fn parse_pids(s: &str) -> Result<Vec<u32>> {
    if s.trim().is_empty() {
        return Ok(vec![]);
    }
    if s.trim().eq_ignore_ascii_case("self") {
        return Ok(vec![std::process::id()]);
    }

    let mut pids = Vec::new();
    for raw in s.split(',') {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        let pid = value
            .parse::<u32>()
            .with_context(|| format!("invalid PID `{value}`"))?;
        pids.push(pid);
    }

    Ok(pids)
}

fn write_jsonl(out: &Option<PathBuf>, findings: &[Finding]) -> Result<()> {
    if let Some(p) = out {
        if let Some(parent) = p.parent().filter(|path| !path.as_os_str().is_empty()) {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create output directory {}", parent.display())
            })?;
        }

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .with_context(|| format!("failed to open JSONL output {}", p.display()))?;
        for finding in findings {
            serde_json::to_writer(&mut file, finding)
                .with_context(|| format!("failed to serialize finding for {}", p.display()))?;
            writeln!(file).with_context(|| format!("failed to write {}", p.display()))?;
        }
    }
    Ok(())
}

fn load_replay_file(path: &Path) -> Result<ReplayFile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read replay file {}", path.display()))?;
    let replay: ReplayFile = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse replay file {}", path.display()))?;
    if replay.pages.is_empty() {
        bail!("replay file {} has no pages", path.display());
    }
    Ok(replay)
}

fn resolve_replay_pid(pid: ReplayPid) -> Result<u32> {
    match pid {
        ReplayPid::Text(value) if value.trim().eq_ignore_ascii_case("self") => {
            Ok(std::process::id())
        }
        ReplayPid::Text(value) => parse_pid_text(&value),
        ReplayPid::Number(value) => u32::try_from(value)
            .with_context(|| format!("replay PID {value} is outside the u32 range")),
    }
}

fn parse_pid_text(value: &str) -> Result<u32> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("PID is empty");
    }

    trimmed
        .parse::<u32>()
        .with_context(|| format!("invalid PID `{trimmed}`"))
}

fn parse_base(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("base address is empty");
    }

    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16)
            .with_context(|| format!("invalid hex base address `{trimmed}`"));
    }

    trimmed
        .parse::<u64>()
        .with_context(|| format!("invalid base address `{trimmed}`"))
}

fn decode_hex_page(value: &str) -> Result<Vec<u8>> {
    let compact: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    hex::decode(&compact).with_context(|| "invalid replay page hex data".to_string())
}

fn replay_findings(replay: ReplayFile, eng: &YaraExternal) -> Result<Vec<Finding>> {
    let pid = resolve_replay_pid(replay.pid)?;
    let cache = PageCache::new(60_000);
    let mut findings = Vec::new();

    for (index, page) in replay.pages.into_iter().enumerate() {
        let base = parse_base(&page.base)
            .with_context(|| format!("invalid base on replay page {}", index + 1))?;
        let bytes = decode_hex_page(&page.data_hex)
            .with_context(|| format!("invalid data on replay page {}", index + 1))?;

        if cache.check(pid, base, &bytes) {
            continue;
        }

        let hits = eng
            .scan_bytes(&bytes)
            .with_context(|| format!("YARA scan failed for replay page 0x{base:x}"))?;
        for rule in hits {
            findings.push(Finding {
                pid,
                base,
                size: bytes.len(),
                rule: rule.clone(),
                severity: "high".into(),
                message: format!("match {} at 0x{:x}", rule, base),
            });
        }
    }

    Ok(findings)
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run {
            config,
            rules,
            pids,
            duration,
            listen,
            jsonl,
            enforce,
        } => {
            let cfg: AppCfg = if config.exists() {
                serde_yaml::from_str(&std::fs::read_to_string(&config)?)?
            } else {
                AppCfg::default()
            };
            let pid_filter = parse_pids(&pids)?;
            let eng = YaraExternal::new(
                cfg.engine.yara_path.clone(),
                rules.clone(),
                cfg.scan.timeout_ms,
            )?;
            let reg = Registry::new();
            let (tx_stop, rx_stop) = bounded::<()>(1);
            serve_http(listen, rx_stop, reg.clone());
            let cache = PageCache::new(cfg.scan.cache_ttl_ms);
            let sched = Scheduler::new(eng, cache, reg.clone(), cfg.scan.page_bytes);

            let start = std::time::Instant::now();
            loop {
                let tasks = build_tasks(
                    if pid_filter.is_empty() {
                        None
                    } else {
                        Some(pid_filter.clone())
                    },
                    &cfg.scan.priorities,
                );
                let findings = sched.run_once(tasks);
                if !findings.is_empty() {
                    reg.inc_findings();
                    if enforce || cfg.mode == "enforce" {
                        yara_on_map::quarantine::quarantine(&findings, &reg);
                    }
                    write_jsonl(&jsonl, &findings)?;
                }
                if duration == 0 {
                    break;
                }
                if start.elapsed().as_secs() >= duration {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            let _ = tx_stop.send(());
            Ok(())
        }
        Cmd::Replay {
            file,
            rules,
            yara,
            timeout_ms,
        } => {
            let replay = load_replay_file(&file)?;
            let eng = YaraExternal::new(yara, rules, timeout_ms)?;
            let findings = replay_findings(replay, &eng)?;
            for f in findings.iter() {
                println!("{}", serde_json::to_string(f)?);
            }
            Ok(())
        }
        Cmd::SelfCheck => {
            println!("OK");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding() -> Finding {
        Finding {
            pid: 7,
            base: 0x1000,
            size: 4,
            rule: "mz_header".to_string(),
            severity: "high".to_string(),
            message: "match mz_header at 0x1000".to_string(),
        }
    }

    #[test]
    fn parse_pids_accepts_lists_and_self() {
        assert_eq!(parse_pids("12, 34").expect("pid list"), vec![12, 34]);
        assert_eq!(
            parse_pids("self").expect("self pid"),
            vec![std::process::id()]
        );
    }

    #[test]
    fn parse_pids_rejects_bad_values() {
        let err = parse_pids("12, nope").unwrap_err();

        assert!(err.to_string().contains("invalid PID"));
    }

    #[test]
    fn replay_base_accepts_hex_and_decimal() {
        assert_eq!(parse_base("0x1000").expect("hex"), 0x1000);
        assert_eq!(parse_base("4096").expect("decimal"), 4096);
    }

    #[test]
    fn replay_hex_allows_whitespace() {
        assert_eq!(
            decode_hex_page("4D 5A\n90").expect("hex bytes"),
            vec![0x4d, 0x5a, 0x90]
        );
    }

    #[test]
    fn write_jsonl_creates_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("findings.jsonl");

        write_jsonl(&Some(path.clone()), &[sample_finding()]).expect("write jsonl");

        let content = fs::read_to_string(path).expect("read jsonl");
        assert!(content.contains("\"rule\":\"mz_header\""));
    }
}
