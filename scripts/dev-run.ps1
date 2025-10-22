$ErrorActionPreference = "Stop"
cargo run --release --bin yom -- run --rules examples/rules/mz.yar --pids self --duration 5 --listen 127.0.0.1:9207
