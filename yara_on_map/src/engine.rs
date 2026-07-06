use anyhow::{anyhow, Result};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

pub struct YaraExternal {
    exe: String,
    rules: PathBuf,
    timeout: Duration,
}

impl YaraExternal {
    pub fn new(exe: String, rules: PathBuf, timeout_ms: u64) -> Result<Self> {
        // quick check
        let _ = Command::new(&exe)
            .arg("-v")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        Ok(Self {
            exe,
            rules,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<String>> {
        // Write to a temp file and call yara.exe rules file.bin
        let mut tmp = tempfile::Builder::new()
            .prefix("yom_page_")
            .suffix(".bin")
            .tempfile()?;
        tmp.write_all(data)?;
        let bin_path = tmp.path().to_path_buf();

        let mut cmd = Command::new(&self.exe);
        cmd.args([
            self.rules.to_string_lossy().to_string(),
            bin_path.to_string_lossy().to_string(),
        ]);
        cmd.arg("-n"); // print only rule names
        cmd.arg("-s"); // include strings (we ignore, just presence enough)
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn()?;

        let start = std::time::Instant::now();
        while start.elapsed() < self.timeout {
            match child.try_wait()? {
                Some(status) => {
                    let out = child
                        .stdout
                        .take()
                        .map(|mut s| {
                            let mut buf = String::new();
                            let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                            buf
                        })
                        .unwrap_or_default();
                    if !status.success() && out.trim().is_empty() {
                        let err = child
                            .stderr
                            .take()
                            .map(|mut s| {
                                let mut buf = String::new();
                                let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                                buf
                            })
                            .unwrap_or_default();
                        if err.to_lowercase().contains("no rules")
                            || err.to_lowercase().contains("error")
                        {
                            return Err(anyhow!("yara failed: {}", err.trim()));
                        }
                    }
                    let mut hits = Vec::new();
                    for line in out.lines() {
                        let name = line.split_whitespace().next().unwrap_or("").trim();
                        if !name.is_empty() {
                            hits.push(name.to_string());
                        }
                    }
                    return Ok(hits);
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        // timeout
        let _ = child.kill();
        Err(anyhow!("yara timeout"))
    }
}
