# ADR 0001: Engine and Watcher choices

We need YARA in user-mode without shipping kernel drivers. Native libyara on Windows requires a proper toolchain on CI. To keep builds reproducible we default to the official `yara.exe` binary (installed via Chocolatey on CI) and call it with timeouts per page. This gives accurate YARA semantics today. The engine layer is pluggable; adding a pure-Rust backend (yara-x) later is trivial.

For discovery, ETW `Kernel-Image`/`Kernel-Memory` would be ideal but complex to ship robustly. We start with a poller using `VirtualQueryEx`, which is deterministic and requires only PROCESS_QUERY_INFORMATION. ETW can be enabled later behind a flag without changing the scheduler.
