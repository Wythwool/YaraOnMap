# YaraOnMap (yom) — YARA-on-Map Memory Scanner (Windows)

Fast user-mode scanner for newly mapped pages (MEM_IMAGE/MEM_MAPPED/EXEC|WRITABLE). Runs YARA on page data right after mapping, caches page digests, and can quarantine suspicious mappings by downgrading protections.

## Quickstart (Windows x64)

```powershell
# 1) Bootstrap (Rust + YARA)
scripts/bootstrap.ps1

# 2) Build
cargo build --release

# 3) Smoke (replay, no privileges)
cargo run --release --bin yom -- replay --file examples/replay/mapping_sample.json --rules examples/rules/mz.yar

# 4) Live scan current process for 5s, metrics on 127.0.0.1:9207
scripts/dev-run.ps1
```

## CLI

```
yom run    --config config/default.yaml --rules examples/rules/mz.yar --pids self --duration 5 --listen 127.0.0.1:9207 [--jsonl out/findings.jsonl] [--enforce]
yom replay --file examples/replay/mapping_sample.json --rules examples/rules/mz.yar
yom self-check
```

- `--pids`: `self` or comma-separated PIDs. Empty = all.
- `--enforce`: set `PAGE_READONLY` on matched pages (best effort, requires `PROCESS_VM_OPERATION`).
- Metrics: `/metrics`, health: `/healthz`.

## Config (`config/default.yaml`)

- Engine: `external` via `yara64.exe` (from Chocolatey). Timeout per page and per-process budget.
- Scan: `page_bytes` (default 64KiB), cache TTL, workers, priorities by protection.
- Mode: `audit` or `enforce`.

## Notes

- ETW is not required; the watcher polls `VirtualQueryEx` for deterministic new regions.
- Quarantine is in-memory only, no file changes.
- Rules are standard YARA. Example provided: `examples/rules/mz.yar`.

License: MIT.




