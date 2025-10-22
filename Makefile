SHELL := pwsh

.PHONY: bootstrap build test fmt lint audit run release sbom

bootstrap:
	choco install -y git rustup.install yara || echo "ensure installed"
	rustup toolchain install stable
	rustup default stable
	cargo fetch

build:
	cargo build --release

test:
	cargo test --all -- --nocapture

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets -- -D warnings

audit:
	cargo install cargo-audit -q || true
	cargo audit -q || true

run:
	cargo run --release --bin yom -- run --rules examples/rules/mz.yar --pids self --duration 3

release: build
	@echo "Artifacts in target/release"

sbom:
	./scripts/sbom.ps1
