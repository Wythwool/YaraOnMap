# Changelog

## v0.1.1 - 2026-07-06
- Added Cargo lockfile and GitHub Actions CI for format, lint, test, and release build.
- Added repository ignore rules for Rust build output and local editor files.
- Moved tests into package-level Cargo test targets.
- Fixed the CLI JSONL writer to use the standard library file appender.
- Hardened external YARA startup checks, scan timeouts, output parsing, and related unit tests.
- Hardened CLI replay parsing, PID validation, JSONL output errors, and replay YARA options.
- Added configuration validation and a useful self-check command for config, rules, and optional YARA startup checks.

## v0.1.0 - 2025-10-22
- First release. User-mode Windows memory map scanner with page-wise YARA, caching, priorities, timeouts, and quarantine.
