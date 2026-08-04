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
SKIP=0
SKIPPED_NAMES=()

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

# skip_gate records a gate that could not run, loudly and by name.
#
# A gate that silently reports PASS when its tooling is missing is worse than
# no gate: it is a green summary that means nothing, and this repository has
# already shipped one of those. A skip is counted separately, listed in the
# summary, and never folded into the pass count.
skip_gate() {
    local name="$1" reason="$2"
    echo "=== GATE: $name ==="
    echo "  SKIP: $reason"
    SKIP=$((SKIP + 1))
    SKIPPED_NAMES+=("$name")
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

# --- Security lint ---
#
# The Phase 32 traceability table found six threat-model controls that nothing
# enforced. Four of them are a scan over a small surface and this is that scan:
# no secret-dependent branching in dhow-crypt, no raw key bytes across the C
# ABI, an unwind guard at every FFI entry point, and a networking denylist.
# Added in Phase 39, where it immediately found fifteen unguarded entry points.

run_gate "security lint" \
    python3 "$ROOT/scripts/security_lint.py"

# --- ABI gates ---

run_gate "ABI drift" \
    bash -c "'$ROOT/scripts/check_abi.sh'"

# --- Wire-format gates ---
#
# check_spec.py has run in CI since Phase 3 and never in this gate, and
# conformance_test.py has never run anywhere. A conformance suite nothing runs
# is a suite that rots: its manifest checks are keyed by vector name, and when
# the manifest went to v2 every one of them stopped matching while the suite
# still reported PASS. Both run here now.

run_gate "wire-format spec consistency" \
    python3 "$ROOT/scripts/check_spec.py"

run_gate "golden vector conformance" \
    python3 "$ROOT/scripts/conformance_test.py"

# The two checks above compare generated files against the documents that
# describe them, and would not notice if the *implementation* had drifted from
# both. This one builds dhow, runs a transfer, and reads the bytes it produced
# at the offsets proto/ declares. Demonstrated in Phase 34: changing
# MANIFEST_VERSION to 3 left all 37 manifest unit tests passing and failed here.

run_gate "CLI conformance against proto/" \
    python3 "$ROOT/scripts/conformance_cli.py"

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

# The loopback moves frames between the two halves as files, which exercises
# everything above the optical layer and nothing in it. This one moves them as
# pictures, through the same binary's own command line: rendered, located,
# sampled, decoded. Added in Phase 37 with the camera path; before it, the
# tool's stated purpose had no end-to-end check at all.

run_gate "optical end-to-end" \
    bash -c "'$ROOT/scripts/optical.sh' 8 25 >/dev/null"

# --- README ---
#
# A quickstart that does not work is the first thing a reader tries and the
# first impression the project makes. Same idea as the drill below: the only
# way to notice documentation drifting from code is to execute it.

run_gate "README quickstart" \
    bash -c "'$ROOT/scripts/quickstart.sh' >/dev/null"

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

# --- Performance and memory ---
#
# The benchmarks are built but not run to completion: a full criterion pass is
# minutes, and a gate that takes minutes is a gate people skip. Building them
# proves they have not rotted against the code they measure, which is the
# failure that actually happens. Running them is `make bench`.
#
# The RSS budget is different: it is a *threshold*, so it has to run. It is
# measured at 16 MiB rather than the 1 GiB the phase pack names, because what
# the design fixes is a ratio and a ratio is the same at both sizes. See
# docs/BENCHMARKS.md.

run_gate "benchmarks build" \
    bash -c "cd '$CORE_DIR' && cargo bench --bench data_path --no-run >/dev/null 2>&1 \
             && cd '$CLI_DIR' && go test ./internal/pack/ -run '^\$' -bench . -benchtime 1x >/dev/null"

run_gate "peak RSS budget" \
    bash -c "'$ROOT/scripts/rss.sh' 16 9 6 >/dev/null"

# --- Marker triage ---
#
# "Zero TODOs without a backlog entry" is a release gate that a plain grep
# cannot enforce: this tree has fourteen strings matching TODO that are not
# markers, and a gate reporting fourteen findings on a clean tree is one people
# learn to ignore. scripts/triage.sh writes the exclusions down with reasons.

run_gate "marker triage" \
    bash -c "'$ROOT/scripts/triage.sh' >/dev/null"

# --- Release ---
#
# The reproducibility check is two full builds and takes about a minute, which
# is the cost of the only claim about reproducibility worth making: not that the
# flags look right, but that a second build produced the same bytes. It also
# runs the binary it built, which is what catches a release that links the Rust
# core dynamically from a build directory.
#
# The SBOM tools are not needed to build or test dhow, so a machine without them
# skips - counted and named, never reported as a pass.

if command -v cargo-cyclonedx >/dev/null 2>&1 && command -v cyclonedx-gomod >/dev/null 2>&1; then
    run_gate "release build and SBOM" \
        bash -c "'$ROOT/scripts/release.sh' \"\$(mktemp -d)/dist\" >/dev/null 2>&1"
else
    skip_gate "release build and SBOM" \
        "cargo-cyclonedx or cyclonedx-gomod is not installed; see docs/RELEASE.md"
fi

run_gate "reproducible build" \
    bash -c "'$ROOT/scripts/release.sh' --check >/dev/null 2>&1"

# --- Fuzzing ---
#
# Seconds per target, not minutes: a gate that takes an hour is a gate people
# skip. Its job is to prove the targets still build and still run against the
# current wire formats, not to search. Searching is scripts/fuzz.sh 3600.
#
# The fuzz toolchain is a second pinned nightly and is not required to build or
# test dhow, so a machine without it skips this rather than failing - but the
# skip is counted and named, never reported as a pass.

FUZZ_TOOLCHAIN="nightly-2025-12-14"
if ! command -v cargo-fuzz >/dev/null 2>&1; then
    skip_gate "fuzz targets (10s each)" \
        "cargo-fuzz is not installed; see docs/FUZZING.md"
elif ! rustup toolchain list 2>/dev/null | grep -q "^${FUZZ_TOOLCHAIN}"; then
    skip_gate "fuzz targets (10s each)" \
        "the ${FUZZ_TOOLCHAIN} toolchain is not installed; see docs/FUZZING.md"
else
    run_gate "fuzz targets (10s each)" \
        bash -c "'$ROOT/scripts/fuzz.sh' 10 >/dev/null"
fi

# --- Summary ---

echo ""
echo "=== GATE SUMMARY ==="
echo "  Passed:  $PASS"
echo "  Failed:  $FAIL"
echo "  Skipped: $SKIP"
for name in ${SKIPPED_NAMES+"${SKIPPED_NAMES[@]}"}; do
    echo "    - $name"
done

if [ "$FAIL" -gt 0 ]; then
    echo "GATES FAILED"
    exit 1
fi

if [ "$SKIP" -gt 0 ]; then
    echo "ALL GATES PASSED (${SKIP} skipped)"
    exit 0
fi

echo "ALL GATES PASSED"
exit 0
