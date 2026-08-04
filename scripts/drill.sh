#!/usr/bin/env bash
#
# drill.sh - cold-start operator drill.
#
# Runs exactly the commands docs/OPERATIONS.md tells an operator to run, in the
# order it tells them to, using the parameters from its worked example. Nothing
# here consults the source: if the guide is wrong, this fails.
#
# That is the point. A guide is only as good as the last time someone followed
# it, and nobody follows a guide they wrote. This does, on every gate run.
#
# It cannot exercise the camera, which does not exist yet; frames move through
# a directory as they do everywhere else in this repository. Everything else -
# the key ceremony, the parameter choices, the resume flag, the verification
# step, and the exit codes the guide promises - is the guide's own text.
#
# Usage:
#   scripts/drill.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUIDE="$ROOT/docs/OPERATIONS.md"

WORK="$(mktemp -d -t dhow-drill-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

DHOW="$WORK/dhow"

pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*" >&2; exit 1; }

echo "=== dhow cold-start drill ==="
echo "following docs/OPERATIONS.md"
echo

cargo build --release --quiet --manifest-path "$ROOT/core/Cargo.toml" -p dhow-ffi
(cd "$ROOT" && go build -o "$DHOW" ./cli/cmd/dhow)

# --- The guide's worked example must still be the guide's worked example ---
#
# The commands below are copied from the "Running a transfer" section. If that
# section is edited, these have to be edited with it, and this check is what
# makes that impossible to forget.

for snippet in \
    "dhow keygen -out operator.key" \
    "dhow keygen -kind identity -out sender.key" \
    "dhow send -key operator.key -identity ./sender.key" \
    "dhow recv -key operator.key -signer ./sender.pub" \
    "dhow verify -in ./frames -signer ./sender.pub -dir ./received" \
    "-symbol-size 1320 -blocks 11 -overhead 60" \
    "-state ./.dhow-state"
do
    grep -qF -- "$snippet" "$GUIDE" \
        || fail "the guide no longer contains '$snippet'; this drill is out of date"
done
pass "the drill matches the guide's worked example"

cd "$WORK"

# --- A dataset to move ---

mkdir -p dataset/docs dataset/bin
head -c 400000 /dev/urandom > dataset/bin/payload.bin
printf 'notes for the other side\n' > dataset/docs/notes.txt
printf '#!/bin/sh\necho hello\n' > dataset/bin/run.sh
chmod +x dataset/bin/run.sh

# --- Key ceremony, per the guide ---

"$DHOW" keygen -out operator.key >/dev/null
"$DHOW" keygen -kind identity -out sender.key >/dev/null

# The guide says the file is mode 0600 and that dhow refuses one readable by
# anyone else. Both claims are checked rather than believed.
MODE=$(stat -f '%Lp' operator.key 2>/dev/null || stat -c '%a' operator.key)
[ "$MODE" = "600" ] || fail "the guide claims mode 0600, got ${MODE}"

chmod 644 operator.key
set +e
"$DHOW" recv -key operator.key -signer ./sender.pub -in ./frames -out ./x >/dev/null 2>&1
PERM_EXIT=$?
set -e
[ "$PERM_EXIT" -ne 0 ] || fail "the guide claims a permissive key is refused, but it was accepted"
chmod 600 operator.key

# The guide says keygen refuses to overwrite without -force.
set +e
"$DHOW" keygen -out operator.key >/dev/null 2>&1
CLOBBER_EXIT=$?
set -e
[ "$CLOBBER_EXIT" -eq 2 ] || fail "the guide claims an existing key is not overwritten; exit was ${CLOBBER_EXIT}"

# The guide's key-ceremony table claims the identity writes two files, that the
# secret half is 0600, and that keygen prints a fingerprint the two operators
# compare. All three are what an operator is told to rely on.
[ -f sender.key ] || fail "the guide says keygen -kind identity writes sender.key"
[ -f sender.pub ] || fail "the guide says keygen -kind identity writes sender.pub"
ID_MODE=$(stat -f '%Lp' sender.key 2>/dev/null || stat -c '%a' sender.key)
[ "$ID_MODE" = "600" ] || fail "the guide claims the identity is mode 0600, got ${ID_MODE}"

"$DHOW" keygen -kind identity -out ceremony.key > ceremony.log 2>&1
grep -qE 'fingerprint ([0-9a-f]{2}:){7}[0-9a-f]{2}' ceremony.log \
    || fail "the guide tells operators to compare a fingerprint keygen no longer prints"

# The guide says the two kinds are recorded in the file and not interchangeable.
set +e
"$DHOW" send -key operator.key -identity ./operator.key -in ./dataset -out ./nope >/dev/null 2>&1
WRONG_KIND=$?
set -e
[ "$WRONG_KIND" -ne 0 ] \
    || fail "the guide says an operator key cannot be used as an identity, but send accepted one"
pass "key ceremony behaves as the guide describes"

# --- Send, with the guide's parameters ---

"$DHOW" send -key operator.key -identity ./sender.key -in ./dataset -out ./frames \
    -symbol-size 1320 -blocks 11 -overhead 60 >/dev/null

FRAMES=$(find ./frames -name 'frame-*.bin' | wc -l | tr -d ' ')
[ "$FRAMES" -gt 0 ] || fail "send produced no frames"

# The guide pairs symbol size 1320 with QR version 30 at ECC M. If that pairing
# is wrong, every frame fails to render and the operator discovers it after
# setting up a camera.
"$DHOW" display -in ./frames -qr-version 30 -qr-ecc M -loops 1 -fps 120 \
    -calibration 0 -no-clear >/dev/null 2>&1 \
    || fail "the guide's symbol size does not fit the QR version it pairs with"
pass "sent ${FRAMES} frames and they fit the guide's QR version"

# --- Receive, with the state directory the guide insists on ---

"$DHOW" recv -key operator.key -signer ./sender.pub -in ./frames -out ./received \
    -state ./.dhow-state -verbose 2> recv.log >/dev/null

# The guide tells an operator to watch per-block progress under -verbose, and
# tells them to read "N of M blocks decoded". If that line is not there, the
# troubleshooting section is unusable.
grep -q "blocks decoded" recv.log \
    || fail "the guide promises per-block progress under -verbose; none appeared"
pass "receive reported the progress the guide tells operators to watch"

# --- Verify, per the guide ---

"$DHOW" verify -in ./frames -signer ./sender.pub -dir ./received >/dev/null \
    || fail "verify rejected a dataset that transferred cleanly"
diff -r ./dataset ./received >/dev/null || fail "the dataset did not round trip"
[ -x ./received/bin/run.sh ] || fail "the executable bit was lost"
pass "dataset round tripped and verified"

# --- The exit codes the guide's table promises ---

set +e
"$DHOW" recv -key operator.key -signer ./sender.pub -in ./frames -out ./partial \
    -state ./.partial-state -stop-after 5 >/dev/null 2>&1
INCOMPLETE=$?
"$DHOW" verify -in ./frames -signer ./sender.pub -dir ./nonexistent >/dev/null 2>&1
VERIFY_FAIL=$?
"$DHOW" recv -key operator.key -signer ./sender.pub -in ./nonexistent -out ./y >/dev/null 2>&1
BAD_INPUT=$?
"$DHOW" send -nonsense >/dev/null 2>&1
BAD_USAGE=$?
# The guide's table promises exit 3, before a frame is read, when the manifest
# was not signed by the identity in -signer.
"$DHOW" keygen -kind identity -out stranger.key >/dev/null 2>&1
"$DHOW" recv -key operator.key -signer ./stranger.pub -in ./frames -out ./z >/dev/null 2>&1
WRONG_SIGNER=$?
set -e

[ "$INCOMPLETE" -eq 4 ] || fail "the guide promises 4 for incomplete, got ${INCOMPLETE}"
[ "$VERIFY_FAIL" -eq 3 ] || fail "the guide promises 3 for verification failure, got ${VERIFY_FAIL}"
[ "$BAD_INPUT" -eq 2 ] || fail "the guide promises 2 for bad input, got ${BAD_INPUT}"
[ "$BAD_USAGE" -eq 1 ] || fail "the guide promises 1 for usage errors, got ${BAD_USAGE}"
[ "$WRONG_SIGNER" -eq 3 ] || fail "the guide promises 3 for a wrong signer, got ${WRONG_SIGNER}"
[ ! -d ./z ] || fail "a receive with an unverifiable manifest wrote output"
pass "every exit code in the guide's table is the code produced"

# --- The block-count advice, demonstrated ---
#
# The guide's central warning is that loss on a period equal to the block count
# concentrates on one block and is unrecoverable, while the same loss rate
# against a coprime block count is absorbed. An operator is being asked to
# choose a prime on that basis, so the claim is demonstrated rather than
# asserted.

"$DHOW" send -key operator.key -identity ./sender.key -in ./dataset -out ./f8 \
    -symbol-size 1320 -blocks 8 -overhead 60 >/dev/null
cp -R ./f8 ./f8-lossy
i=0
for f in ./f8-lossy/frame-*.bin; do
    [ $((i % 8)) -eq 0 ] && rm -f "$f"
    i=$((i + 1))
done

set +e
"$DHOW" recv -key operator.key -signer ./sender.pub -in ./f8-lossy -out ./r8 >/dev/null 2>&1
PERIODIC_EXIT=$?
set -e
[ "$PERIODIC_EXIT" -eq 4 ] \
    || fail "loss on the block period was expected to defeat the transfer; exit was ${PERIODIC_EXIT}"

# The same loss rate, against a prime block count the period does not divide.
"$DHOW" send -key operator.key -identity ./sender.key -in ./dataset -out ./f11 \
    -symbol-size 1320 -blocks 11 -overhead 60 >/dev/null
cp -R ./f11 ./f11-lossy
i=0
for f in ./f11-lossy/frame-*.bin; do
    [ $((i % 8)) -eq 0 ] && rm -f "$f"
    i=$((i + 1))
done

"$DHOW" recv -key operator.key -signer ./sender.pub -in ./f11-lossy -out ./r11 >/dev/null 2>&1 \
    || fail "the guide's recommended prime block count did not survive the same loss"
diff -r ./dataset ./r11 >/dev/null || fail "the recovered dataset differs"
pass "the guide's block-count advice holds: 8 blocks fails where 11 survives"

# --- The camera section ---
#
# The guide names four sources and a set of counts an operator is told to read.
# The camera itself cannot be run here, but the source it names is the same
# object as a directory of images, and the counts are printed by the same code
# whichever source produced them.

"$DHOW" send -key operator.key -identity ./sender.key -in ./dataset -out ./optical \
    -symbol-size 96 -blocks 2 -overhead 100 \
    -qr -qr-version 8 -qr-ecc M -qr-scale 6 >/dev/null

"$DHOW" recv -key operator.key -signer ./sender.pub -in ./optical -source images \
    -out ./from-camera > optical.log
diff -r ./dataset ./from-camera >/dev/null \
    || fail "a transfer read back through the optical layer differs from the one sent"

# Every bucket the guide's table names has to appear, or an operator following
# it is reading for something the tool does not print.
for bucket in dropped unreadable foreign damaged repeats; do
    grep -q "$bucket" optical.log \
        || fail "recv does not report '${bucket}', which the guide's count table names"
done
pass "an optical transfer round trips and reports every count the guide names"

# The guide tells an operator to run detect on one saved capture, and says
# -binarized writes what the binarizer saw.
# A glob rather than `find | sort | head`: head closing the pipe sends
# SIGPIPE to sort, which pipefail then reports as a failed pipeline.
set -- ./optical/frame-*.png
FIRST="$1"
"$DHOW" detect -binarized ./seen "$FIRST" > detect.log
grep -q "dhow frame" detect.log \
    || fail "detect did not name a dhow frame, which the guide says it does"
[ -n "$(find ./seen -name '*.binarized.png')" ] \
    || fail "detect -binarized wrote nothing, which the guide says it does"
pass "detect names the frame and writes what the binarizer saw"

# The guide says an unknown source is a usage error rather than a receiver that
# quietly reads nothing.
set +e
"$DHOW" recv -key operator.key -signer ./sender.pub -in ./optical -source webcam \
    -out ./nowhere >/dev/null 2>&1
BAD_SOURCE=$?
set -e
[ "$BAD_SOURCE" -eq 1 ] || fail "an unknown -source exited ${BAD_SOURCE}, expected 1"
pass "an unknown -source is a usage error"

echo
echo "=== DRILL PASSED ==="
