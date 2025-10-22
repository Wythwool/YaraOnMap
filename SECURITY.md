# Security

- No telemetry. No network calls.
- Process access is least-privilege; operations requiring `PROCESS_VM_OPERATION` are gated by `--mode enforce`.
- Timeouts per page and global per-process budget; watchdog kills external `yara.exe` if it misbehaves.
- Paths normalized; no writing under system directories. Temp files use secure flags and are wiped.
- Supply-chain: pinned dependencies; CodeQL + cargo-audit in CI.
