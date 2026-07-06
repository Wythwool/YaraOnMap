use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct YaraExternal {
    exe: String,
    rules: PathBuf,
    timeout: Duration,
}

impl YaraExternal {
    pub fn new(exe: String, rules: PathBuf, timeout_ms: u64) -> Result<Self> {
        let meta = std::fs::metadata(&rules)
            .with_context(|| format!("YARA rules file is not readable: {}", rules.display()))?;
        if !meta.is_file() {
            bail!("YARA rules path is not a file: {}", rules.display());
        }

        let timeout = Duration::from_millis(timeout_ms.max(1));
        let mut cmd = Command::new(&exe);
        cmd.arg("-v").stdout(Stdio::piped()).stderr(Stdio::piped());

        let version = run_with_timeout(
            cmd.spawn()
                .with_context(|| format!("failed to start YARA executable `{exe}`"))?,
            timeout,
            "YARA version check",
        )?;
        if !version.status.success() {
            bail!(
                "YARA executable `{}` failed version check: {}",
                exe,
                command_message(&version)
            );
        }

        Ok(Self {
            exe,
            rules,
            timeout,
        })
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<String>> {
        let mut tmp = tempfile::Builder::new()
            .prefix("yom_page_")
            .suffix(".bin")
            .tempfile()?;
        tmp.write_all(data)?;

        let mut cmd = Command::new(&self.exe);
        cmd.arg(&self.rules)
            .arg(tmp.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let scan = run_with_timeout(
            cmd.spawn()
                .with_context(|| format!("failed to start YARA executable `{}`", self.exe))?,
            self.timeout,
            "YARA scan",
        )?;

        if !scan.status.success() {
            bail!("YARA scan failed: {}", command_message(&scan));
        }

        Ok(parse_rule_hits(&scan.stdout))
    }
}

struct CommandResult {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn run_with_timeout(mut child: Child, timeout: Duration, label: &str) -> Result<CommandResult> {
    let start = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            let out = child.wait_with_output()?;
            return Ok(CommandResult {
                status: out.status,
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let out = child.wait_with_output()?;
            return Err(anyhow!(
                "{} timed out after {} ms: {}",
                label,
                timeout.as_millis(),
                command_message(&CommandResult {
                    status: out.status,
                    stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                })
            ));
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

fn parse_rule_hits(stdout: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let mut seen = HashSet::new();

    for line in stdout.lines() {
        let first = line.split_whitespace().next().unwrap_or_default();
        if !is_rule_label(first) {
            continue;
        }

        if seen.insert(first.to_string()) {
            hits.push(first.to_string());
        }
    }

    hits
}

fn is_rule_label(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    value.split(':').all(|part| {
        let mut chars = part.chars();
        matches!(chars.next(), Some('_') | Some('a'..='z') | Some('A'..='Z'))
            && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
    })
}

fn command_message(result: &CommandResult) -> String {
    let stderr = result.stderr.trim();
    if !stderr.is_empty() {
        return trim_message(stderr);
    }

    let stdout = result.stdout.trim();
    if !stdout.is_empty() {
        return trim_message(stdout);
    }

    result.status.to_string()
}

fn trim_message(value: &str) -> String {
    const LIMIT: usize = 600;
    let single_line = value.lines().collect::<Vec<_>>().join(" ");
    if single_line.len() <= LIMIT {
        single_line
    } else {
        let trimmed: String = single_line.chars().take(LIMIT).collect();
        format!("{trimmed}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_yara_hits() {
        let out = "mz_header C:\\sample.bin\nnamespace:packed C:\\sample.bin\n";

        assert_eq!(
            parse_rule_hits(out),
            vec!["mz_header".to_string(), "namespace:packed".to_string()]
        );
    }

    #[test]
    fn ignores_non_rule_output() {
        let out = "\n0x10:$mz: 4D 5A\nwarning: slow atom\nbad-rule C:\\sample.bin\n";

        assert!(parse_rule_hits(out).is_empty());
    }

    #[test]
    fn keeps_first_hit_order_and_deduplicates() {
        let out = "one C:\\a.bin\ntwo C:\\a.bin\none C:\\a.bin\n";

        assert_eq!(
            parse_rule_hits(out),
            vec!["one".to_string(), "two".to_string()]
        );
    }

    #[test]
    fn rejects_missing_rules_before_starting_yara() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing.yar");
        let err = YaraExternal::new("missing-yara.exe".to_string(), missing, 50).unwrap_err();

        assert!(err.to_string().contains("YARA rules file"));
    }
}
