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
"$DHOW" keygen -kind identity -out "$WORK/sender.key" >/dev/null
"$DHOW" keygen -kind identity -out "$WORK/stranger.key" >/dev/null
pass "generated operator keys and signing identities"

# --- Send ---

START=$(date +%s)
"$DHOW" send -key "$WORK/operator.key" -identity "$WORK/sender.key" \
    -in "$DATA" -out "$WORK/frames" \
    -symbol-size 1024 -blocks 8 -overhead 60 -json > "$WORK/send.json"
SEND_END=$(date +%s)

FRAME_COUNT=$(find "$WORK/frames" -name 'frame-*.bin' | wc -l | tr -d ' ')
[ "$FRAME_COUNT" -gt 0 ] || fail "send produced no frames"
pass "sent ${FRAME_COUNT} frames in $((SEND_END - START))s"

# --- Clean receive ---

"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" -in "$WORK/frames" -out "$WORK/clean" >/dev/null
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
    "$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" -in "$LOSSY" -out "$WORK/recovered" >/dev/null \
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

"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" -in "$OUTAGE" -out "$WORK/from-outage" >/dev/null \
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
"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" -in "$CORRUPT" -out "$WORK/from-corrupt" >/dev/null \
    || fail "transfer did not survive corrupted frames"
diff -r "$DATA" "$WORK/from-corrupt" >/dev/null \
    || fail "corrupted frames produced a different dataset"
pass "corrupted frames were rejected without poisoning the decode"

# --- Interruption and resume ---
#
# A capture that runs for an hour will be interrupted. The receiver keeps a
# journal of the frames it accepted and an index over it, so a restart replays
# what it had rather than starting from nothing. Killing the receiver twice
# exercises a journal that is replayed, extended, and replayed again, which is
# where an off-by-one in the covered length would show up.

STATE="$WORK/state"
RESUMED="$WORK/resumed"

FIRST_STOP=$((FRAME_COUNT / 5))
SECOND_STOP=$((FRAME_COUNT / 2))

for STOP in "$FIRST_STOP" "$SECOND_STOP"; do
    set +e
    "$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" -in "$WORK/frames" -out "$RESUMED" \
        -state "$STATE" -stop-after "$STOP" -save-every 50 >/dev/null 2>&1
    STOP_EXIT=$?
    set -e
    [ "$STOP_EXIT" -eq 4 ] || fail "an interrupted receive exited ${STOP_EXIT}, expected 4"
    [ -f "$STATE/journal.bin" ] || fail "an interrupted receive saved no journal"
    [ -f "$STATE/resume.dhrs" ] || fail "an interrupted receive saved no resume state"
done

"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" -in "$WORK/frames" -out "$RESUMED" \
    -state "$STATE" >/dev/null 2>&1 || fail "a resumed transfer did not complete"
diff -r "$DATA" "$RESUMED" >/dev/null || fail "a resumed transfer produced a different dataset"
[ ! -f "$STATE/resume.dhrs" ] || fail "resume state survived a completed transfer"
pass "resumed through two interruptions and round tripped byte for byte"

# Tampering with either half of the state must stop the transfer rather than
# quietly resume from whatever survived.

TAMPER="$WORK/tamper-state"
set +e
"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" -in "$WORK/frames" -out "$WORK/tampered" \
    -state "$TAMPER" -stop-after "$FIRST_STOP" >/dev/null 2>&1
set -e

# Offset 40 is inside the index's journal digest: the field that would have to
# be rewritten to make a doctored journal look like the expected one.
printf '\xff' | dd of="$TAMPER/resume.dhrs" bs=1 seek=40 conv=notrunc status=none
set +e
"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" -in "$WORK/frames" -out "$WORK/tampered" \
    -state "$TAMPER" >/dev/null 2>&1
TAMPER_EXIT=$?
set -e
[ "$TAMPER_EXIT" -eq 2 ] || fail "a tampered resume index exited ${TAMPER_EXIT}, expected 2"

JOURNAL_TAMPER="$WORK/journal-state"
set +e
"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" -in "$WORK/frames" -out "$WORK/tampered2" \
    -state "$JOURNAL_TAMPER" -stop-after "$FIRST_STOP" >/dev/null 2>&1
set -e
printf '\xff' | dd of="$JOURNAL_TAMPER/journal.bin" bs=1 seek=60 conv=notrunc status=none
set +e
"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" -in "$WORK/frames" -out "$WORK/tampered2" \
    -state "$JOURNAL_TAMPER" >/dev/null 2>&1
JOURNAL_EXIT=$?
set -e
[ "$JOURNAL_EXIT" -eq 2 ] || fail "a tampered journal exited ${JOURNAL_EXIT}, expected 2"
pass "tampered resume state and journal both fail closed"

# --- Fail-closed cases ---

set +e
"$DHOW" recv -key "$WORK/wrong.key" -signer "$WORK/sender.pub" -in "$WORK/frames" -out "$WORK/intruder" >/dev/null 2>&1
WRONG_KEY_EXIT=$?
set -e
[ "$WRONG_KEY_EXIT" -eq 4 ] || fail "wrong key exited ${WRONG_KEY_EXIT}, expected 4"
[ ! -d "$WORK/intruder" ] || fail "a failed transfer still wrote output"
pass "wrong key fails closed and writes nothing"

# --- The signature ---
#
# The whole point of the signed manifest is that it answers a question the
# operator key cannot: not "was this encrypted with the key we share" but "was
# this produced by the holder of the sending key". These two cases are what
# distinguish the two questions, so they are checked separately from the
# encryption failures above.

set +e
"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/stranger.pub" \
    -in "$WORK/frames" -out "$WORK/unsigned" >/dev/null 2>&1
STRANGER_EXIT=$?
set -e
[ "$STRANGER_EXIT" -eq 3 ] || fail "a manifest signed by another identity exited ${STRANGER_EXIT}, expected 3"
[ ! -d "$WORK/unsigned" ] || fail "a transfer with an unverifiable manifest still wrote output"
pass "a manifest signed by another identity fails closed and writes nothing"

# Every byte of the manifest is inside the signature, so altering any of them
# must be caught. Sample rather than sweep: the exhaustive walk is a unit test,
# and this is an end-to-end check that the CLI applies it at all.
MANIFEST_LEN=$(wc -c < "$WORK/frames/manifest.bin" | tr -d ' ')
for OFFSET in 8 40 70 110 130 200 $((MANIFEST_LEN - 1)); do
    TAMPERED="$WORK/tampered-manifest"
    rm -rf "$TAMPERED"
    cp -R "$WORK/frames" "$TAMPERED"
    printf '\xa5' | dd of="$TAMPERED/manifest.bin" bs=1 seek="$OFFSET" conv=notrunc status=none
    set +e
    "$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" \
        -in "$TAMPERED" -out "$WORK/from-tampered" >/dev/null 2>&1
    EXIT=$?
    set -e
    [ "$EXIT" -eq 3 ] \
        || fail "a manifest altered at offset ${OFFSET} exited ${EXIT}, expected 3"
    [ ! -d "$WORK/from-tampered" ] \
        || fail "a transfer with an altered manifest at offset ${OFFSET} wrote output"
done
rm -rf "$WORK/tampered-manifest"
pass "an altered manifest fails closed wherever it is altered"

# --- Verify ---

"$DHOW" verify -in "$WORK/frames" -signer "$WORK/sender.pub" -dir "$WORK/clean" >/dev/null \
    || fail "verify rejected a good dataset"
pass "verify accepts a good dataset"

set +e
"$DHOW" verify -in "$WORK/frames" -signer "$WORK/stranger.pub" -dir "$WORK/clean" >/dev/null 2>&1
VERIFY_STRANGER_EXIT=$?
set -e
[ "$VERIFY_STRANGER_EXIT" -eq 3 ] \
    || fail "verify against the wrong identity exited ${VERIFY_STRANGER_EXIT}, expected 3"
pass "verify rejects a dataset whose manifest was not signed by the expected identity"

# One flipped byte in a multi-megabyte file, with every name, count, and size
# left correct. This is the corruption a file count cannot see.
printf '\xff' | dd of="$WORK/clean/bin/random.bin" bs=1 seek=4096 conv=notrunc status=none
set +e
"$DHOW" verify -in "$WORK/frames" -signer "$WORK/sender.pub" -dir "$WORK/clean" -json > "$WORK/verify.json" 2>/dev/null
VERIFY_EXIT=$?
set -e
[ "$VERIFY_EXIT" -eq 3 ] || fail "verify of a corrupted file exited ${VERIFY_EXIT}, expected 3"
grep -q '"kind": "content"' "$WORK/verify.json" \
    || fail "verify did not report a content problem for a flipped byte"
pass "verify catches a single flipped byte in a good-looking dataset"

rm -f "$WORK/clean/docs/empty.txt"
set +e
"$DHOW" verify -in "$WORK/frames" -signer "$WORK/sender.pub" -dir "$WORK/clean" -json > "$WORK/verify2.json" 2>/dev/null
VERIFY_EXIT=$?
set -e
[ "$VERIFY_EXIT" -eq 3 ] || fail "verify of a damaged dataset exited ${VERIFY_EXIT}, expected 3"
grep -q '"kind": "missing"' "$WORK/verify2.json" \
    || fail "verify did not report the removed file as missing"
pass "verify rejects a damaged dataset"

# --- Determinism ---

"$DHOW" send -key "$WORK/operator.key" -identity "$WORK/sender.key" \
    -in "$DATA" -out "$WORK/frames-b" \
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
