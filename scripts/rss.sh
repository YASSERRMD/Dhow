#!/usr/bin/env bash
#
# rss.sh - measure peak resident memory for a send and a receive.
#
# Usage:
#   scripts/rss.sh [dataset MiB] [send ratio] [recv ratio]
#
# Defaults to 16 MiB, 12x for send and 8x for recv. Exits non-zero if either
# half exceeds its budget.
#
# The two have separate budgets because they are separate paths with genuinely
# different numbers - send measures around 10.3x and recv around 6.4x - and a
# single loose budget covering both would let the cheaper one regress by ninety
# percent before anything failed.
#
# # Why the budget is a ratio and not a number of bytes
#
# The phase pack asks for "a peak-RSS budget for a 1 GiB transfer". A single
# absolute number for one dataset size is the wrong shape for this: it is
# expensive to check (a 1 GiB run takes minutes and several gigabytes of disk),
# it tells you nothing about a 10 GiB transfer, and a regression that doubles
# memory use at every size still passes it if the number was set loosely.
#
# What the *design* fixes is not a number of bytes, it is how many copies of the
# dataset are resident at once. That is a ratio, it is the same at every size
# above the fixed overhead, and it is what a change either preserves or breaks.
# So the budget is a ratio, measured at a size cheap enough to check on every
# run, and the 1 GiB figure is derived from it and recorded in
# docs/BENCHMARKS.md rather than measured on every commit.
#
# The tradeoff is stated because it is a deviation: this does not run a 1 GiB
# transfer, and a defect that only appears above some threshold would not be
# caught here. scripts/rss.sh 1024 runs the real thing when someone has the
# minutes and the disk.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIZE_MIB="${1:-16}"
SEND_BUDGET="${2:-12}"
RECV_BUDGET="${3:-8}"

WORK="$(mktemp -d -t dhow-rss-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

DHOW="$WORK/dhow"

fail() { echo "  FAIL  $*" >&2; exit 1; }

# peak_rss_bytes runs a command and prints its peak resident size in bytes.
#
# BSD time reports bytes and GNU time reports kilobytes, and getting that wrong
# by a factor of 1024 would make the budget either meaningless or unmeetable.
# The unit is decided by which one is present rather than by parsing a number
# and guessing.
peak_rss_bytes() {
    local out="$WORK/time.txt"
    case "$(uname -s)" in
        Darwin)
            /usr/bin/time -l "$@" 2>"$out" >/dev/null
            awk '/maximum resident set size/ { print $1 }' "$out"
            ;;
        *)
            # GNU time's %M is in kilobytes.
            /usr/bin/time -f '%M' "$@" 2>"$out" >/dev/null
            awk 'END { print $1 * 1024 }' "$out"
            ;;
    esac
}

human() {
    awk -v b="$1" 'BEGIN { printf "%.1f MiB", b / 1048576 }'
}

echo "=== dhow peak RSS ==="
echo "dataset ${SIZE_MIB} MiB, budget ${SEND_BUDGET}x send / ${RECV_BUDGET}x recv"
echo

cargo build --release --quiet --manifest-path "$ROOT/core/Cargo.toml" -p dhow-ffi
(cd "$ROOT" && go build -o "$DHOW" ./cli/cmd/dhow)

"$DHOW" keygen -out "$WORK/operator.key" >/dev/null
"$DHOW" keygen -kind identity -out "$WORK/sender.key" >/dev/null

# One file rather than many. The question is how many copies of the payload are
# resident, and splitting it across files would only add archive overhead to the
# same measurement.
mkdir -p "$WORK/data"
DATASET_BYTES=$((SIZE_MIB * 1024 * 1024))
dd if=/dev/urandom of="$WORK/data/blob.bin" bs=1048576 count="$SIZE_MIB" status=none

echo "measuring send..."
SEND_RSS=$(peak_rss_bytes "$DHOW" send -key "$WORK/operator.key" \
    -identity "$WORK/sender.key" -in "$WORK/data" -out "$WORK/frames" \
    -symbol-size 1320 -blocks 8 -overhead 10 -quiet)

FRAME_COUNT=$(find "$WORK/frames" -name 'frame-*.bin' | wc -l | tr -d ' ')
[ "$FRAME_COUNT" -gt 0 ] || fail "send produced no frames"

echo "measuring recv..."
RECV_RSS=$(peak_rss_bytes "$DHOW" recv -key "$WORK/operator.key" \
    -signer "$WORK/sender.pub" -in "$WORK/frames" -out "$WORK/received" -quiet)

diff -r "$WORK/data" "$WORK/received" >/dev/null \
    || fail "the measured transfer did not round trip"

SEND_RATIO=$(awk -v r="$SEND_RSS" -v d="$DATASET_BYTES" 'BEGIN { printf "%.2f", r / d }')
RECV_RATIO=$(awk -v r="$RECV_RSS" -v d="$DATASET_BYTES" 'BEGIN { printf "%.2f", r / d }')

echo
printf '  dataset   %s\n' "$(human "$DATASET_BYTES")"
printf '  frames    %s\n' "$FRAME_COUNT"
printf '  send RSS  %s (%sx dataset)\n' "$(human "$SEND_RSS")" "$SEND_RATIO"
printf '  recv RSS  %s (%sx dataset)\n' "$(human "$RECV_RSS")" "$RECV_RATIO"
echo

OVER=0
if awk -v r="$SEND_RATIO" -v m="$SEND_BUDGET" 'BEGIN { exit !(r > m) }'; then
    echo "  FAIL  send used ${SEND_RATIO}x the dataset, above the ${SEND_BUDGET}x budget" >&2
    OVER=1
fi
if awk -v r="$RECV_RATIO" -v m="$RECV_BUDGET" 'BEGIN { exit !(r > m) }'; then
    echo "  FAIL  recv used ${RECV_RATIO}x the dataset, above the ${RECV_BUDGET}x budget" >&2
    OVER=1
fi

if [ "$OVER" -ne 0 ]; then
    echo >&2
    echo "See docs/BENCHMARKS.md for what the budget is and why it is a ratio." >&2
    exit 1
fi

echo "=== RSS WITHIN BUDGET ==="
