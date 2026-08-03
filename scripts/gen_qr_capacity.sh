#!/usr/bin/env bash
#
# gen_qr_capacity.sh - regenerate proto/qr-capacity.md.
#
# The table is measured against the QR encoder rather than transcribed from the
# specification, so it cannot disagree with what dhow will actually accept.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cargo run --quiet --release \
    --manifest-path "$ROOT/core/Cargo.toml" \
    -p dhow-codec --example gen_capacity \
    > "$ROOT/proto/qr-capacity.md"

echo "Wrote proto/qr-capacity.md"
