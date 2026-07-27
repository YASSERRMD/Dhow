# Dhow Makefile - convenience targets

.PHONY: build test lint gate clean audit deny govulncheck fmt clippy

build:
	cd core && cargo build
	cd cli && go build ./...

test:
	cd core && cargo test --all-targets
	cd cli && go test ./...

lint:
	./scripts/gate.sh

gate:
	./scripts/gate.sh

audit:
	cargo audit

deny:
	cargo deny check

govulncheck:
	cd cli && govulncheck ./...

fmt:
	cd core && cargo fmt --all --check

clippy:
	cd core && cargo clippy --all-targets -- -D warnings

clean:
	cd core && cargo clean
