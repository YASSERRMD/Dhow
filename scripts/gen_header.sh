#!/usr/bin/env bash
#
# gen_header.sh - regenerate the C header from the dhow-ffi source.
#
# The header is committed so callers can build against it without a Rust
# toolchain. scripts/check_abi.sh fails the build if the two ever disagree.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v cbindgen >/dev/null 2>&1; then
    echo "cbindgen not found. Install it with: cargo install cbindgen" >&2
    exit 1
fi

mkdir -p "$ROOT/core/include"

cbindgen --config "$ROOT/core/dhow-ffi/cbindgen.toml" \
         --crate dhow-ffi \
         --output "$ROOT/core/include/dhow.h" \
         "$ROOT/core/dhow-ffi"

echo "Wrote core/include/dhow.h"
