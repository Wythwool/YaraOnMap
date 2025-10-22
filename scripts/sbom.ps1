$ErrorActionPreference = "Stop"
if (-not (Get-Command syft -ErrorAction SilentlyContinue)) {
  iwr -useb https://raw.githubusercontent.com/anchore/syft/main/install.ps1 | iex
}
syft packages dir:. -o cyclonedx-json > sbom\cyclonedx.json
Write-Host "SBOM in sbom\cyclonedx.json"
