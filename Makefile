# Dhow Makefile - convenience targets

.PHONY: build test lint gate clean

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

clean:
	cd core && cargo clean
