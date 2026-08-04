#!/usr/bin/env bash
#
# quickstart.sh - run the README's quickstart, exactly as written.
#
# A quickstart that does not work is worse than no quickstart: it is the first
# thing a reader tries and the first impression the project makes. This runs the
# commands from README.md in a scratch directory and fails the build if any of
# them stops working.
#
# It is the same idea as scripts/drill.sh, which does this for
# docs/OPERATIONS.md. Both exist because documentation drifts from code silently
# and there is no way to notice except by executing it.
#
# The commands below are copied from the "Quickstart" section. If that section
# is edited, these have to be edited with it, and the check below is what makes
# that impossible to forget.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
README="$ROOT/README.md"

WORK="$(mktemp -d -t dhow-quickstart-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*" >&2; exit 1; }

echo "=== dhow quickstart ==="
echo "running README.md as written"
echo

# --- The commands in the README must be the commands run here ---

for snippet in \
    "cargo build --release -p dhow-ffi" \
    "go build -o dhow ./cli/cmd/dhow" \
    "./dhow keygen -out operator.key" \
    "./dhow keygen -kind identity -out sender.key" \
    "./dhow send -key operator.key -identity sender.key -in ./mydata -out ./frames" \
    "./dhow recv -key operator.key -signer sender.pub -in ./frames -out ./received" \
    "./dhow verify -in ./frames -signer sender.pub -dir ./received" \
    "./dhow display -in ./frames -signer sender.pub -fps 8" \
    "./dhow detect -binarized ./seen ./capture.png"
do
    grep -qF -- "$snippet" "$README" \
        || fail "the README no longer contains '$snippet'; this script is out of date"
done
pass "the script matches the README's quickstart"

# --- Build, exactly as the README says ---

(cd "$ROOT/core" && cargo build --release --quiet -p dhow-ffi)
(cd "$ROOT" && go build -o "$WORK/dhow" ./cli/cmd/dhow)
pass "built dhow"

cd "$WORK"

# A dataset for it to move. The README assumes the reader has one; the shapes
# that matter are a nested directory and an executable, because those are what
# the archive format and the inventory have to carry.
mkdir -p mydata/nested
head -c 20000 /dev/urandom > mydata/blob.bin
printf 'hello\n' > mydata/nested/note.txt
printf '#!/bin/sh\nexit 0\n' > mydata/run.sh
chmod +x mydata/run.sh

# --- keygen ---

./dhow keygen -out operator.key > keygen.log
grep -q "mode 0600" keygen.log \
    || fail "the operator keygen no longer reports the mode the README implies"

./dhow keygen -kind identity -out sender.key > identity.log
[ -f sender.pub ] \
    || fail "keygen -kind identity did not write sender.pub, which the README's recv line uses"
grep -qE 'fingerprint ([0-9a-f]{2}:){7}[0-9a-f]{2}' identity.log \
    || fail "keygen no longer prints the fingerprint the README tells operators to compare"
pass "both keys generated, and the identity printed a fingerprint"

# --- send ---

./dhow send -key operator.key -identity sender.key -in ./mydata -out ./frames > send.log
FRAMES=$(find ./frames -name 'frame-*.bin' | wc -l | tr -d ' ')
[ "$FRAMES" -gt 0 ] || fail "send produced no frames"
[ -f ./frames/manifest.bin ] || fail "send produced no signed manifest"
pass "sent ${FRAMES} frames and a signed manifest"

# --- recv ---

./dhow recv -key operator.key -signer sender.pub -in ./frames -out ./received > recv.log
diff -r ./mydata ./received >/dev/null \
    || fail "the received dataset differs from the one that was sent"
[ -x ./received/run.sh ] || fail "the executable bit did not survive"
pass "received and round tripped byte for byte"

# --- verify ---

./dhow verify -in ./frames -signer sender.pub -dir ./received > verify.log
grep -q "result    OK" verify.log || fail "verify did not report OK on a good dataset"
grep -qE '^signer    ([0-9a-f]{2}:){7}[0-9a-f]{2}$' verify.log \
    || fail "verify no longer names the signer, which is what the README claims it proves"
pass "verify accepted the dataset and named the signer"

# --- The README's claims about the keys ---
#
# It says the identity is what answers "which one", and that recv reads nothing
# before the signature checks. Both are checkable rather than decorative.

./dhow keygen -kind identity -out stranger.key >/dev/null
set +e
./dhow recv -key operator.key -signer stranger.pub -in ./frames -out ./intruder >/dev/null 2>&1
WRONG_SIGNER=$?
set -e
[ "$WRONG_SIGNER" -eq 3 ] \
    || fail "a transfer signed by another identity exited ${WRONG_SIGNER}, expected 3"
[ ! -d ./intruder ] \
    || fail "a transfer with an unverifiable signature still wrote output"
pass "a transfer signed by another identity is refused, and writes nothing"

# --- The README's "Across a screen" section ---
#
# The camera command in it cannot run here, but everything on either side of it
# can: rendering the frames, reading one back with detect, and receiving from
# images. The one part that needs hardware is the capture program, and the
# receiver treats it as a source of images like any other.

./dhow send -key operator.key -identity sender.key -in ./mydata -out ./optical \
    -symbol-size 96 -qr -qr-version 8 -qr-ecc M >/dev/null
RENDERED=$(find ./optical -name 'frame-*.png' | wc -l | tr -d ' ')
[ "$RENDERED" -gt 0 ] || fail "the README's -qr flags rendered no images"
pass "rendered ${RENDERED} frames as QR codes"

# A glob rather than `find | sort | head`: head closing the pipe sends
# SIGPIPE to sort, which pipefail then reports as a failed pipeline.
set -- ./optical/frame-*.png
FIRST="$1"
./dhow detect -binarized ./seen "$FIRST" > detect.log
grep -q "dhow frame" detect.log \
    || fail "detect did not recognise a frame the tool had just rendered"
[ -n "$(find ./seen -name '*.binarized.png')" ] \
    || fail "detect -binarized wrote nothing, which the README says it does"
pass "detect read a rendered frame and wrote what the binarizer saw"

./dhow recv -key operator.key -signer sender.pub -in ./optical -source images \
    -out ./from-screen >/dev/null
diff -r ./mydata ./from-screen >/dev/null \
    || fail "a transfer read back from images differs from the one that was sent"
pass "a transfer across the optical layer round trips byte for byte"

echo
echo "=== QUICKSTART PASSED ==="
