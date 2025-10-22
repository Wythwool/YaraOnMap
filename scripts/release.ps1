$ErrorActionPreference = "Stop"
cargo build --release
$bin = "target\release\yom.exe"
if (!(Test-Path $bin)) { throw "build failed" }
Write-Host "Built $bin"
