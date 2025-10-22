# Architecture

```
[yom.exe]
  ├─ Watcher (poll, optional ETW off by default)
  │    └─ discovers new mappings via VirtualQueryEx (MEM_IMAGE/MEM_MAPPED/EXEC|WRITABLE)
  ├─ Scheduler
  │    └─ priority queue: EXEC>WRITABLE>READONLY; per-process budgets
  ├─ Scanner
  │    ├─ PageReader(ReadProcessMemory 64K pages)
  │    ├─ PageCache(CRC32/mtime; TTL)
  │    └─ YaraEngine (external yara.exe) -> parse stdout
  ├─ Quarantine (enforce mode only)
  │    └─ VirtualProtectEx to READONLY for suspicious pages (best effort)
  └─ HTTP (/metrics,/healthz) + JSONL sink

Data flow: Watcher -> (regions) -> Scheduler -> (pages) -> Scanner -> (findings) -> Sink/Quarantine -> Metrics
```
Design choices are documented in ADR/0001-initial-architecture.md.
