# Dhow Makefile - convenience targets

.PHONY: build test lint gate clean audit deny govulncheck fmt clippy spec-check vectors fuzz bench rss release release-check

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

spec-check:
	python3 scripts/check_spec.py
	python3 scripts/conformance_test.py

vectors:
	python3 scripts/gen_vectors.py

fuzz:
	scripts/fuzz.sh 60

bench:
	cd core && cargo bench --bench data_path
	cd cli && go test ./internal/pack/ -run '^$$' -bench . -benchmem

rss:
	scripts/rss.sh

release:
	scripts/release.sh

release-check:
	scripts/release.sh --check
