# Operations

- Service runs as LOCAL SERVICE or a dedicated unprivileged user with SeDebugPrivilege if needed.
- Metrics at `/metrics`, liveness at `/healthz` on the configured address (default `127.0.0.1:9207`).
- Rolling logs in JSON to stdout; use Windows service wrapper (nssm or sc.exe) to daemonize.
- Quarantine changes memory protections only; no file tampering. Restore is the target process' responsibility.
