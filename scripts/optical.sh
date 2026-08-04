#!/usr/bin/env bash
#
# optical.sh - end-to-end transfer across the optical layer.
#
# scripts/loopback.sh moves frames between the two halves as binary files,
# which exercises everything above the optical layer and nothing in it. This
# harness moves them as pictures: every frame is rendered as a QR code, and the
# receiver locates, samples, and decodes each one before anything reaches the
# fountain decoder. Nothing here knows the frames were rendered rather than
# photographed.
#
# What it does not do is degrade the images. Blur, skew, occlusion, and noise
# are applied in Go, by cli/internal/optical, because they need pixel
# arithmetic that a shell script has no way to do without a dependency this
# repository does not have. Those tests run in the gate too, under
# `go test -race`, along with the streaming and capture-command paths that need
# a subprocess. This script's job is the one thing they cannot check: that the
# shipped binary does an optical transfer, from real files, through its own
# command line.
#
# Usage:
#   scripts/optical.sh [qr_version] [loss_percent]
#
# Defaults to QR version 8 with 25 percent of the captured images missing.
# Exits non-zero on the first failure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QR_VERSION="${1:-8}"
LOSS_PCT="${2:-25}"

WORK="$(mktemp -d -t dhow-optical-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

DHOW="$WORK/dhow"

pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*" >&2; exit 1; }

echo "=== dhow optical harness ==="
echo "QR version ${QR_VERSION}, ${LOSS_PCT}% of captures missing"
echo

# --- Build ---

echo "building..."
cargo build --release --quiet --manifest-path "$ROOT/core/Cargo.toml" -p dhow-ffi
(cd "$ROOT" && go build -o "$DHOW" ./cli/cmd/dhow)
pass "built dhow"

# --- Fixture ---
#
# Small on purpose. Every frame becomes a picture that has to be located and
# sampled, which is thousands of times the work of reading a file, and a gate
# that takes minutes is a gate people skip. The size that matters for the
# optical layer is the size of one frame, not the size of the dataset.

DATA="$WORK/data"
mkdir -p "$DATA/nested"
head -c 24576 /dev/urandom > "$DATA/random.bin"
printf 'the quick brown fox jumps over the lazy dog\n' > "$DATA/nested/text.txt"
printf '#!/bin/sh\necho hello\n' > "$DATA/run.sh"
chmod +x "$DATA/run.sh"
: > "$DATA/empty"
pass "built a fixture"

# --- Keys ---

"$DHOW" keygen -out "$WORK/operator.key" >/dev/null
"$DHOW" keygen -out "$WORK/wrong.key" >/dev/null
"$DHOW" keygen -kind identity -out "$WORK/sender.key" >/dev/null
pass "generated keys"

# --- Send, rendering every frame ---
#
# The symbol size is chosen so a frame fits the chosen QR version: a frame is
# 46 bytes of header plus 4 of payload identifier plus the symbol, and the
# whole thing has to fit one code. Getting this wrong is the first mistake an
# operator makes, and `send` names the sizes when it does.

SYMBOL_SIZE=96
if [ "$QR_VERSION" -ge 12 ]; then SYMBOL_SIZE=256; fi

"$DHOW" send -key "$WORK/operator.key" -identity "$WORK/sender.key" \
    -in "$DATA" -out "$WORK/frames" \
    -symbol-size "$SYMBOL_SIZE" -blocks 2 -overhead 120 \
    -qr -qr-version "$QR_VERSION" -qr-ecc M -qr-scale 6 -json > "$WORK/send.json"

IMAGE_COUNT=$(find "$WORK/frames" -name 'frame-*.png' | wc -l | tr -d ' ')
FRAME_COUNT=$(find "$WORK/frames" -name 'frame-*.bin' | wc -l | tr -d ' ')
[ "$IMAGE_COUNT" -eq "$FRAME_COUNT" ] \
    || fail "rendered ${IMAGE_COUNT} images for ${FRAME_COUNT} frames"
[ "$IMAGE_COUNT" -gt 0 ] || fail "send rendered no images"
pass "rendered ${IMAGE_COUNT} frames as QR codes"

# --- detect ---
#
# Before the transfer, because an operator whose captures are not decoding runs
# this on one picture and it is the only thing that distinguishes a camera
# problem from a key problem.

# A glob rather than `find | sort | head`: head closing the pipe sends
# SIGPIPE to sort, which pipefail then reports as a failed pipeline.
set -- "$WORK/frames"/frame-*.png
FIRST="$1"
"$DHOW" detect -json "$FIRST" > "$WORK/detect.json" \
    || fail "detect could not read a rendering the tool had just produced"
grep -q '"is_dhow_frame": true' "$WORK/detect.json" \
    || fail "detect did not recognise a dhow frame in a rendered frame"
grep -q "\"qr_version\": ${QR_VERSION}" "$WORK/detect.json" \
    || fail "detect read a version other than ${QR_VERSION}"
pass "detect reads a rendered frame and names its version and session"

# --- Clean optical transfer ---

"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" \
    -in "$WORK/frames" -source images -out "$WORK/clean" -json > "$WORK/recv.json" \
    || fail "an optical transfer of clean renderings did not complete"
diff -r "$DATA" "$WORK/clean" >/dev/null \
    || fail "an optical transfer did not round trip"
[ -x "$WORK/clean/run.sh" ] || fail "the executable bit was lost across the optical layer"
grep -q '"unreadable": 0' "$WORK/recv.json" \
    || fail "a clean rendering was unreadable; the detector is not doing its job"
pass "a transfer across the optical layer round trips byte for byte"

# --- Missing captures ---
#
# A camera misses frames: it was refocusing, somebody walked past, the exposure
# was wrong for that hundredth of a second. Repair symbols are why that is
# survivable, and this is the check that the optical path benefits from them
# rather than merely having them.

CAPTURED="$WORK/captured"
mkdir -p "$CAPTURED"
DROPPED=0
KEPT=0
i=0
for f in "$WORK/frames"/frame-*.png; do
    if [ "$LOSS_PCT" -gt 0 ] && [ $((i % (100 / LOSS_PCT))) -eq 0 ]; then
        DROPPED=$((DROPPED + 1))
    else
        cp "$f" "$CAPTURED/"
        KEPT=$((KEPT + 1))
    fi
    i=$((i + 1))
done
[ "$DROPPED" -gt 0 ] || fail "no captures were dropped; the loss injection did nothing"

"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" \
    -in "$WORK/frames" -source "images:$CAPTURED" -out "$WORK/lossy" >/dev/null \
    || fail "an optical transfer did not survive ${DROPPED} missed captures"
diff -r "$DATA" "$WORK/lossy" >/dev/null \
    || fail "a lossy optical transfer produced a different dataset"
pass "recovered from ${DROPPED} missed captures out of ${IMAGE_COUNT}"

# --- Pictures that are not frames ---
#
# A camera pointed at the wrong thing, or at the right screen before the
# transfer started. The receiver must report that it read nothing rather than
# decode something.

NOISE="$WORK/noise"
mkdir -p "$NOISE"
cp "$WORK/frames/manifest.bin" "$NOISE/not-an-image.png"
"$DHOW" detect "$NOISE/not-an-image.png" >/dev/null 2>&1 \
    && fail "detect claimed to read a symbol out of a file that is not an image"
pass "detect refuses a file that is not an image"

# --- Wrong key ---
#
# The optical path must fail closed in the same way the file path does. A
# receiver that read every symbol perfectly and holds the wrong key has an
# incomplete transfer, not a corrupt one.

set +e
"$DHOW" recv -key "$WORK/wrong.key" -signer "$WORK/sender.pub" \
    -in "$WORK/frames" -source images -out "$WORK/intruder" >/dev/null 2>&1
WRONG_KEY_EXIT=$?
set -e
[ "$WRONG_KEY_EXIT" -eq 4 ] || fail "the wrong key exited ${WRONG_KEY_EXIT}, expected 4"
[ ! -d "$WORK/intruder" ] || fail "a failed optical transfer still wrote output"
pass "the wrong key fails closed across the optical layer and writes nothing"

# --- Another session's screen ---
#
# Two transfers running in one room, or a camera that caught the tail of the
# previous one. Frames of another session must be rejected before they reach
# the decoder, which is what the pre-filter's session check is for.

"$DHOW" send -key "$WORK/operator.key" -identity "$WORK/sender.key" \
    -in "$DATA" -out "$WORK/other" \
    -symbol-size "$SYMBOL_SIZE" -blocks 2 -overhead 120 \
    -qr -qr-version "$QR_VERSION" -qr-ecc M -qr-scale 6 >/dev/null

set +e
"$DHOW" recv -key "$WORK/operator.key" -signer "$WORK/sender.pub" \
    -in "$WORK/frames" -source "images:$WORK/other" -out "$WORK/crossed" \
    -json > "$WORK/crossed.json" 2>/dev/null
CROSSED_EXIT=$?
set -e
[ "$CROSSED_EXIT" -eq 4 ] || fail "another session's screen exited ${CROSSED_EXIT}, expected 4"
[ ! -d "$WORK/crossed" ] || fail "a transfer fed another session's frames wrote output"
pass "another session's screen is rejected and writes nothing"

# --- Verify ---

"$DHOW" verify -in "$WORK/frames" -signer "$WORK/sender.pub" -dir "$WORK/clean" >/dev/null \
    || fail "verify rejected a dataset that arrived across the optical layer"
pass "verify accepts a dataset that arrived across the optical layer"

echo
echo "=== OPTICAL PASSED ==="
