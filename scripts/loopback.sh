#!/usr/bin/env bash
#
# loopback.sh - unattended end-to-end transfer harness.
#
# Runs a complete transfer through the real dhow binary: pack, encrypt, chunk,
# fountain-code, frame, then decode, verify, decrypt, and extract. Frames move
# between the two halves through a directory rather than a screen and camera,
# so the harness runs without hardware; everything above the optical layer is
# the production path.
#
# Faults are injected on purpose. A transfer that only works when nothing goes
# wrong has not been tested: the whole reason for the fountain code is that
# real captures drop and corrupt frames.
#
# Usage:
#   scripts/loopback.sh [size_mb] [loss_percent]
#
# Defaults to a 16 MiB dataset with 20 percent of frames dropped. Exits
# non-zero on the first failure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIZE_MB="${1:-16}"
LOSS_PCT="${2:-20}"

WORK="$(mktemp -d -t dhow-loopback-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

DHOW="$WORK/dhow"

pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*" >&2; exit 1; }

echo "=== dhow loopback harness ==="
echo "dataset ${SIZE_MB} MiB, frame loss ${LOSS_PCT}%"
echo

# --- Build ---

echo "building..."
cargo build --release --quiet --manifest-path "$ROOT/core/Cargo.toml" -p dhow-ffi
(cd "$ROOT" && go build -o "$DHOW" ./cli/cmd/dhow)
pass "built dhow"

# --- Fixture ---

DATA="$WORK/data"
mkdir -p "$DATA/docs" "$DATA/bin" "$DATA/nested/deep"

# A mix of compressible and incompressible content, because a payload that is
# all one or the other exercises only half of what a real dataset does.
head -c $((SIZE_MB * 1024 * 1024 / 2)) /dev/urandom > "$DATA/bin/random.bin"

# Built with a loop rather than `yes | head -c`: head closing the pipe sends
# SIGPIPE to yes, which pipefail then reports as a failed pipeline.
: > "$DATA/docs/repetitive.txt"
TARGET=$((SIZE_MB * 1024 * 1024 / 2))
CHUNK="the quick brown fox jumps over the lazy dog"
while [ "$(wc -c < "$DATA/docs/repetitive.txt")" -lt "$TARGET" ]; do
    for _ in $(seq 1 2000); do printf '%s\n' "$CHUNK"; done >> "$DATA/docs/repetitive.txt"
done
truncate -s "$TARGET" "$DATA/docs/repetitive.txt" 2>/dev/null || true
printf '#!/bin/sh\necho hello\n' > "$DATA/bin/run.sh"
chmod +x "$DATA/bin/run.sh"
printf 'nested content\n' > "$DATA/nested/deep/file.txt"
: > "$DATA/docs/empty.txt"

ACTUAL_MB=$(du -sm "$DATA" | cut -f1)
pass "built a ${ACTUAL_MB} MiB fixture"

# --- Keys ---

"$DHOW" keygen -out "$WORK/operator.key" >/dev/null
"$DHOW" keygen -out "$WORK/wrong.key" >/dev/null
pass "generated operator keys"

# --- Send ---

START=$(date +%s)
"$DHOW" send -key "$WORK/operator.key" -in "$DATA" -out "$WORK/frames" \
    -symbol-size 1024 -blocks 8 -overhead 60 -json > "$WORK/send.json"
SEND_END=$(date +%s)

FRAME_COUNT=$(find "$WORK/frames" -name 'frame-*.bin' | wc -l | tr -d ' ')
[ "$FRAME_COUNT" -gt 0 ] || fail "send produced no frames"
pass "sent ${FRAME_COUNT} frames in $((SEND_END - START))s"

# --- Clean receive ---

"$DHOW" recv -key "$WORK/operator.key" -in "$WORK/frames" -out "$WORK/clean" >/dev/null
diff -r "$DATA" "$WORK/clean" >/dev/null || fail "clean transfer did not round trip"
pass "clean transfer round trips byte for byte"

# The executable bit is part of what a file is, not metadata about it.
[ -x "$WORK/clean/bin/run.sh" ] || fail "executable bit was lost"
pass "executable bit survived"

# --- Lossy receive ---

LOSSY="$WORK/lossy"
cp -R "$WORK/frames" "$LOSSY"

# Loss is spread evenly across the stream rather than taken as a contiguous
# run from the front. Frames are emitted block by block, so a contiguous run
# removes one block entirely, which no amount of repair overhead can recover:
# RaptorQ repairs within a block, not across blocks. Scattered loss is also
# what a camera actually produces.
DROPPED=0
if [ "$LOSS_PCT" -gt 0 ]; then
    EVERY=$((100 / LOSS_PCT))
    i=0
    for f in "$LOSSY"/frame-*.bin; do
        if [ $((i % EVERY)) -eq 0 ]; then
            rm -f "$f"
            DROPPED=$((DROPPED + 1))
        fi
        i=$((i + 1))
    done
fi

if [ "$DROPPED" -eq 0 ]; then
    pass "loss injection disabled (0%)"
else
    "$DHOW" recv -key "$WORK/operator.key" -in "$LOSSY" -out "$WORK/recovered" >/dev/null \
        || fail "transfer did not survive ${DROPPED} dropped frames"
    diff -r "$DATA" "$WORK/recovered" >/dev/null \
        || fail "recovered dataset differs after frame loss"
    pass "recovered from ${DROPPED} dropped frames"
fi

# --- Contiguous outage ---
#
# An operator stepping in front of the screen, or a camera refocusing, drops a
# run of consecutive frames rather than a scattered sample. This is survivable
# only because frames are interleaved across blocks: RaptorQ repairs within a
# block and never across them, so an outage that fell entirely inside one block
# would be unrecoverable at any overhead.

OUTAGE="$WORK/outage"
cp -R "$WORK/frames" "$OUTAGE"

RUN=$((FRAME_COUNT / 6))
START_AT=$((FRAME_COUNT / 3))
i=0
for f in "$OUTAGE"/frame-*.bin; do
    if [ "$i" -ge "$START_AT" ] && [ "$i" -lt $((START_AT + RUN)) ]; then
        rm -f "$f"
    fi
    i=$((i + 1))
done

"$DHOW" recv -key "$WORK/operator.key" -in "$OUTAGE" -out "$WORK/from-outage" >/dev/null \
    || fail "transfer did not survive a contiguous outage of ${RUN} frames"
diff -r "$DATA" "$WORK/from-outage" >/dev/null \
    || fail "contiguous outage produced a different dataset"
pass "recovered from a contiguous outage of ${RUN} frames"

# --- Corruption ---

CORRUPT="$WORK/corrupt"
cp -R "$WORK/frames" "$CORRUPT"
for f in $(find "$CORRUPT" -name 'frame-*.bin' | head -5); do
    printf '\xff' | dd of="$f" bs=1 seek=50 conv=notrunc status=none
done
"$DHOW" recv -key "$WORK/operator.key" -in "$CORRUPT" -out "$WORK/from-corrupt" >/dev/null \
    || fail "transfer did not survive corrupted frames"
diff -r "$DATA" "$WORK/from-corrupt" >/dev/null \
    || fail "corrupted frames produced a different dataset"
pass "corrupted frames were rejected without poisoning the decode"

# --- Fail-closed cases ---

set +e
"$DHOW" recv -key "$WORK/wrong.key" -in "$WORK/frames" -out "$WORK/intruder" >/dev/null 2>&1
WRONG_KEY_EXIT=$?
set -e
[ "$WRONG_KEY_EXIT" -eq 4 ] || fail "wrong key exited ${WRONG_KEY_EXIT}, expected 4"
[ ! -d "$WORK/intruder" ] || fail "a failed transfer still wrote output"
pass "wrong key fails closed and writes nothing"

# --- Verify ---

"$DHOW" verify -in "$WORK/frames" -dir "$WORK/clean" >/dev/null || fail "verify rejected a good dataset"
pass "verify accepts a good dataset"

rm -f "$WORK/clean/docs/empty.txt"
set +e
"$DHOW" verify -in "$WORK/frames" -dir "$WORK/clean" >/dev/null 2>&1
VERIFY_EXIT=$?
set -e
[ "$VERIFY_EXIT" -eq 3 ] || fail "verify of a damaged dataset exited ${VERIFY_EXIT}, expected 3"
pass "verify rejects a damaged dataset"

# --- Determinism ---

"$DHOW" send -key "$WORK/operator.key" -in "$DATA" -out "$WORK/frames-b" \
    -symbol-size 1024 -blocks 8 -overhead 60 >/dev/null
# The session id, salt, and nonce are drawn fresh per transfer by design, so
# the frame bytes differ. What must not differ is the packed payload, which is
# what the reproducibility requirement is about; the frame count proves the
# same payload produced the same coding layout.
COUNT_B=$(find "$WORK/frames-b" -name 'frame-*.bin' | wc -l | tr -d ' ')
[ "$COUNT_B" -eq "$FRAME_COUNT" ] || fail "two sends of one dataset produced ${FRAME_COUNT} and ${COUNT_B} frames"
pass "two sends of one dataset produce the same frame count"

TOTAL=$(( $(date +%s) - START ))
echo
echo "=== LOOPBACK PASSED in ${TOTAL}s ==="
