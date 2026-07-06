use anyhow::Result;
use clap::{Parser, Subcommand};
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
use std::path::PathBuf;

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
    },
    /// Basic self-check
    SelfCheck,
}

fn parse_pids(s: &str) -> Vec<u32> {
    if s.trim().is_empty() {
        return vec![];
    }
    if s == "self" {
        return vec![std::process::id()];
    }
    s.split(',')
        .filter_map(|x| x.trim().parse::<u32>().ok())
        .collect()
}

fn write_jsonl(out: &Option<PathBuf>, fs: &[Finding]) {
    if let Some(p) = out {
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
            for x in fs {
                let _ = writeln!(f, "{}", serde_json::to_string(x).unwrap());
            }
        }
    }
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
                let pid_list = parse_pids(&pids);
                let tasks = build_tasks(
                    if pid_list.is_empty() {
                        None
                    } else {
                        Some(pid_list)
                    },
                    &cfg.scan.priorities,
                );
                let findings = sched.run_once(tasks);
                if !findings.is_empty() {
                    reg.inc_findings();
                    if enforce || cfg.mode == "enforce" {
                        yara_on_map::quarantine::quarantine(&findings, &reg);
                    }
                    write_jsonl(&jsonl, &findings);
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
        Cmd::Replay { file, rules } => {
            let data = serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&file)?)?;
            let pid = if data["pid"].as_str() == Some("self") {
                std::process::id()
            } else {
                data["pid"].as_u64().unwrap_or(0) as u32
            };
            let eng = YaraExternal::new("yara64.exe".into(), rules, 500)?;
            let cache = yara_on_map::pager::PageCache::new(60_000);
            let mut findings = Vec::new();
            if let Some(arr) = data["pages"].as_array() {
                for it in arr {
                    let base = u64::from_str_radix(
                        it["base"].as_str().unwrap().trim_start_matches("0x"),
                        16,
                    )
                    .unwrap();
                    let bytes = hex::decode(it["data_hex"].as_str().unwrap()).unwrap();
                    if cache.check(pid, base, &bytes) {
                        continue;
                    }
                    match eng.scan_bytes(&bytes) {
                        Ok(hits) if !hits.is_empty() => {
                            for rule in hits {
                                findings.push(yara_on_map::types::Finding {
                                    pid,
                                    base,
                                    size: bytes.len(),
                                    rule: rule.clone(),
                                    severity: "high".into(),
                                    message: format!("match {} at 0x{:x}", rule, base),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
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
