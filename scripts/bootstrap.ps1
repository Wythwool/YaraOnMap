$ErrorActionPreference = "Stop"
choco install -y git rustup.install yara
rustup toolchain install stable
rustup default stable
cargo fetch
Write-Host "Bootstrap done."
