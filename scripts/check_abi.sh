#!/usr/bin/env bash
#
# check_abi.sh - ABI drift gate.
#
# Three views of the C ABI must agree:
#
#   1. The Rust source: functions marked #[unsafe(no_mangle)] extern "C".
#   2. The committed header: core/include/dhow.h.
#   3. The Go bindings: declarations in cli/internal/ffi.
#
# Any of the three drifting from the others is a build failure. A header that
# is stale relative to the source is the common case and the most dangerous:
# Go compiles against the header, so a stale one means Go calls a signature
# that no longer exists.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HEADER="$ROOT/core/include/dhow.h"
FFI_SRC="$ROOT/core/dhow-ffi/src"
GO_FFI="$ROOT/cli/internal/ffi"

FAIL=0

fail() {
    echo "  DRIFT: $*" >&2
    FAIL=1
}

# --- 1. Header is present ---

if [ ! -f "$HEADER" ]; then
    echo "core/include/dhow.h is missing. Run scripts/gen_header.sh." >&2
    exit 1
fi

# --- 2. Header matches the source ---
#
# Regenerate into a temporary file and diff. This catches a header that was not
# regenerated after the Rust surface changed.

if command -v cbindgen >/dev/null 2>&1; then
    TMP="$(mktemp -t dhow-abi-XXXXXX.h)"
    trap 'rm -f "$TMP"' EXIT

    cbindgen --config "$ROOT/core/dhow-ffi/cbindgen.toml" \
             --crate dhow-ffi \
             --output "$TMP" \
             "$ROOT/core/dhow-ffi" >/dev/null 2>&1

    if ! diff -q "$HEADER" "$TMP" >/dev/null 2>&1; then
        fail "core/include/dhow.h is stale; run scripts/gen_header.sh"
        diff -u "$HEADER" "$TMP" | head -40 >&2 || true
    fi
else
    echo "  cbindgen not installed; skipping header regeneration check" >&2
fi

# --- 3. Every exported Rust symbol appears in the header ---

RUST_SYMBOLS="$(grep -rho 'pub \(unsafe \)\?extern "C" fn [a-z_0-9]*' "$FFI_SRC" \
    | sed 's/.*fn //' | sort -u)"

if [ -z "$RUST_SYMBOLS" ]; then
    echo "No exported symbols found in $FFI_SRC; the gate would pass vacuously." >&2
    exit 1
fi

for sym in $RUST_SYMBOLS; do
    if ! grep -q "\b$sym\b" "$HEADER"; then
        fail "$sym is exported from Rust but absent from dhow.h"
    fi
done

# --- 4. Every symbol the Go bindings call exists in Rust ---

if [ -d "$GO_FFI" ]; then
    GO_SYMBOLS="$(grep -rho 'C\.dhow_[a-z_0-9]*' "$GO_FFI" 2>/dev/null \
        | sed 's/^C\.//' | sort -u || true)"

    for sym in $GO_SYMBOLS; do
        if ! echo "$RUST_SYMBOLS" | grep -q "^$sym$"; then
            fail "$sym is called from Go but not exported by Rust"
        fi
    done
else
    echo "  cli/internal/ffi not present yet; skipping Go binding check" >&2
fi

# --- Summary ---

if [ "$FAIL" -ne 0 ]; then
    echo "ABI DRIFT DETECTED" >&2
    exit 1
fi

echo "ABI consistent across Rust, header, and Go"
