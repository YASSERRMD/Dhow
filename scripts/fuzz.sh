#!/usr/bin/env bash
#
# fuzz.sh - run the cargo-fuzz targets.
#
# Usage:
#   scripts/fuzz.sh [seconds-per-target] [target]
#
# Defaults to 60 seconds per target across every target. The gate runs a much
# shorter pass; a real search is `scripts/fuzz.sh 3600`.
#
# The corpus is seeded from proto/vectors.json before each run. A parser behind
# a magic string, a version byte, and a CRC is not reachable from random bytes
# in any useful time, so a fuzzer that starts from noise spends its whole budget
# on the front door.
#
# See docs/FUZZING.md for why this needs a second toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECONDS_PER_TARGET="${1:-60}"
ONLY="${2:-}"

# Kept in step with fuzz/rust-toolchain.toml. Both are stated because the
# script names the toolchain in its error message, and an error that says
# "install nightly" without saying which one is an error that costs an hour.
TOOLCHAIN="nightly-2025-12-14"

TARGETS=(frame_decode session_header manifest_entry manifest_verify resume_load)

# AddressSanitizer is on everywhere it works, and does not work here.
#
# On macOS 26 (Darwin 25) the ASan runtime shipped with the pinned nightly
# hangs inside __asan::InitializeShadowMemory, spinning at 100% CPU in
# get_dyld_hdr() before a single input is executed. A ten-second run does not
# terminate; the process was sampled and the stack confirms it never leaves
# dyld initialisation. That is a host incompatibility between the sanitizer
# runtime and this operating system, not a defect in this code.
#
# What it costs is small and worth naming. Every target here exercises
# dhow-codec and dhow-crypt, both of which carry #![forbid(unsafe_code)], so
# the memory errors ASan exists to catch cannot be written in them: an
# out-of-bounds index panics, and libFuzzer catches a panic. ASan would earn
# its keep against dhow-ffi, which is the one crate allowed unsafe, and no
# target here reaches it. See docs/FUZZING.md.
SANITIZER="${DHOW_FUZZ_SANITIZER:-}"
if [ -z "$SANITIZER" ]; then
    case "$(uname -s)" in
        Darwin) SANITIZER=none ;;
        *)      SANITIZER=address ;;
    esac
fi

if ! command -v cargo-fuzz >/dev/null 2>&1; then
    cat >&2 <<EOF
cargo-fuzz is not installed. Install it with:

    cargo install cargo-fuzz --locked

See docs/FUZZING.md.
EOF
    exit 1
fi

if ! rustup toolchain list 2>/dev/null | grep -q "^${TOOLCHAIN}"; then
    cat >&2 <<EOF
The pinned fuzzing toolchain ${TOOLCHAIN} is not installed. Install it with:

    rustup toolchain install ${TOOLCHAIN} --profile minimal

cargo-fuzz needs nightly; the rest of this repository stays on the stable pin.
See docs/FUZZING.md.
EOF
    exit 1
fi

echo "=== dhow fuzz ==="
echo "toolchain ${TOOLCHAIN}, sanitizer ${SANITIZER}, ${SECONDS_PER_TARGET}s per target"
echo

echo "seeding corpora from proto/vectors.json"
python3 "$ROOT/scripts/seed_corpus.py"
echo

FAILED=0

for target in "${TARGETS[@]}"; do
    if [ -n "$ONLY" ] && [ "$target" != "$ONLY" ]; then
        continue
    fi

    echo "=== ${target} ==="

    # -max_total_time bounds the run; -print_final_stats reports what it
    # actually did, so a run that found nothing is distinguishable from a run
    # that executed nothing. The two look identical without it, and that is how
    # a fuzz job silently stops fuzzing.
    if cargo "+${TOOLCHAIN}" fuzz run --fuzz-dir "$ROOT/fuzz" -s "$SANITIZER" "$target" -- \
        -max_total_time="$SECONDS_PER_TARGET" \
        -print_final_stats=1 \
        -rss_limit_mb=4096
    then
        echo "  PASS  ${target}"
    else
        echo "  FAIL  ${target}: see $ROOT/fuzz/artifacts/${target}/" >&2
        FAILED=$((FAILED + 1))
    fi
    echo
done

if [ "$FAILED" -gt 0 ]; then
    echo "=== FUZZ FAILED: ${FAILED} target(s) ===" >&2
    echo "Reproduce with:" >&2
    echo "  cargo +${TOOLCHAIN} fuzz run --fuzz-dir $ROOT/fuzz <target> <artifact>" >&2
    exit 1
fi

echo "=== FUZZ PASSED ==="
