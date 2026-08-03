#!/usr/bin/env bash
#
# gate.sh - Dhow build gate
#
# Runs all formatting, linting, test, and audit checks.
# Exits 0 if all gates pass, non-zero otherwise.
#
# Usage: ./scripts/gate.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE_DIR="$ROOT/core"
CLI_DIR="$ROOT/cli"

# Ensure Go bin directory is in PATH (for govulncheck, etc.)
export PATH="$HOME/go/bin:$PATH"

PASS=0
FAIL=0

run_gate() {
    local name="$1"
    shift
    echo "=== GATE: $name ==="
    if "$@"; then
        echo "  PASS"
        PASS=$((PASS + 1))
    else
        echo "  FAIL"
        FAIL=$((FAIL + 1))
    fi
}

# --- Rust gates ---

run_gate "cargo fmt --check" \
    bash -c "cd '$CORE_DIR' && cargo fmt --all --check"

run_gate "cargo clippy -D warnings" \
    cargo clippy --manifest-path "$CORE_DIR/Cargo.toml" --all-targets -- -D warnings

run_gate "cargo test" \
    cargo test --manifest-path "$CORE_DIR/Cargo.toml" --all-targets

run_gate "cargo audit" \
    bash -c "cd '$CORE_DIR' && cargo audit"

run_gate "cargo deny" \
    bash -c "cd '$CORE_DIR' && cargo deny check"

# --- ABI gates ---

run_gate "ABI drift" \
    bash -c "'$ROOT/scripts/check_abi.sh'"

# --- Go gates ---
#
# The Go package links against the Rust staticlib, so the core must be built
# before anything Go runs. Without this a clean clone fails at the linker with
# an error that says nothing about the real cause.

run_gate "build rust core for cgo" \
    bash -c "cd '$CORE_DIR' && cargo build --release -p dhow-ffi"

run_gate "gofmt --check" \
    bash -c "cd '$CLI_DIR' && test -z \"\$(gofmt -l .)\" || { gofmt -l .; false; }"

run_gate "go vet" \
    bash -c "cd '$CLI_DIR' && go vet ./..."

run_gate "go test -race" \
    bash -c "cd '$CLI_DIR' && go test -race ./..."

run_gate "go build" \
    bash -c "cd '$CLI_DIR' && go build ./..."

run_gate "golangci-lint" \
    bash -c "cd '$CLI_DIR' && golangci-lint run ./..."

run_gate "govulncheck" \
    bash -c "cd '$CLI_DIR' && govulncheck ./..."

# --- End-to-end ---
#
# A small dataset so the gate stays fast; scripts/loopback.sh takes a size
# argument for a longer soak.

run_gate "loopback end-to-end" \
    bash -c "'$ROOT/scripts/loopback.sh' 2 20 >/dev/null"

# --- Operations guide ---
#
# Follows docs/OPERATIONS.md from a cold start, so the guide fails the build
# when it drifts from the tool rather than when an operator discovers it.

run_gate "operations guide drill" \
    bash -c "'$ROOT/scripts/drill.sh' >/dev/null"

# --- Chaos ---
#
# A fixed seed so the gate is reproducible; the point of the gate run is that
# the harness itself still works and the invariants still hold, not to search.
# Searching is `scripts/chaos.sh 500` with a fresh seed, which is where a new
# failure is actually found.

run_gate "chaos soak (12 rounds)" \
    bash -c "'$ROOT/scripts/chaos.sh' 12 20260803 >/dev/null"

# --- Summary ---

echo ""
echo "=== GATE SUMMARY ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo "GATES FAILED"
    exit 1
fi

echo "ALL GATES PASSED"
exit 0
