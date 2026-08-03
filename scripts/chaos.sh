#!/usr/bin/env bash
#
# chaos.sh - randomised fault-injection soak.
#
# Every other test in this repository picks the fault it injects, which means
# it tests the failures somebody already thought of. This one picks them at
# random: coding parameters, dataset shape, loss rate, loss pattern, corruption
# count, and whether the receiver is killed partway through.
#
# Each round has exactly two acceptable outcomes:
#
#   COMPLETE  the transfer finished and the dataset verifies byte for byte
#   CLOSED    the transfer failed, and nothing wrong was written
#
# A third outcome - a transfer that reports success and produces a dataset that
# differs from the input - is silent corruption, and it is the failure this
# harness exists to catch. It is never acceptable, at any loss rate, under any
# fault.
#
# Everything random comes from one seed, which is printed. A failing round is
# reproduced by re-running with that seed.
#
# Usage:
#   scripts/chaos.sh [rounds] [seed]
#
# Defaults to 25 rounds with a seed drawn from the clock. The gate runs a small
# number; a soak run is `scripts/chaos.sh 500`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROUNDS="${1:-25}"
SEED="${2:-$(date +%s)}"

WORK="$(mktemp -d -t dhow-chaos-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

DHOW="$WORK/dhow"

COMPLETED=0
CLOSED=0

fail() { echo "  FAIL  $*" >&2; echo; echo "reproduce with: scripts/chaos.sh $ROUNDS $SEED" >&2; exit 1; }

# rand sets RAND_VALUE to a deterministic pseudo-random number in [0, $1).
#
# Bash has $RANDOM but seeding it portably and reproducibly across shells is
# unreliable, so the sequence is generated here: a 32-bit linear congruential
# generator with the constants from Numerical Recipes. It does not need to be
# a good generator. It needs to be the same generator tomorrow.
#
# It sets a variable rather than echoing, because `x=$(rand 10)` runs the
# function in a subshell and the advanced state dies with it. The first
# version of this harness did exactly that and produced the same "random"
# round every time, which is a fault-injection harness that injects one fault.
RAND_STATE="$SEED"
RAND_VALUE=0
rand() {
    RAND_STATE=$(( (1664525 * RAND_STATE + 1013904223) % 4294967296 ))
    RAND_VALUE=$(( RAND_STATE % $1 ))
}

# bytes writes $1 deterministic pseudo-random bytes derived from the label $2.
#
# Not /dev/urandom. The seed has to reproduce the *whole* round, dataset bytes
# included, or a failure that depends on the data cannot be replayed - which is
# not hypothetical: the first long soak of this harness found a real failure
# that a re-run on the same seed did not reproduce, because the data was drawn
# from /dev/urandom and only the parameters came from the seed.
#
# An AES-CTR keystream over zeroes is deterministic given the passphrase, and
# openssl is present wherever this runs.
bytes() {
    local count="$1" label="$2"
    if [ "$count" -eq 0 ]; then
        return 0
    fi
    # pipefail is disabled inside the subshell on purpose: head closes the
    # pipe, openssl takes SIGPIPE, and pipefail would report that as a failed
    # pipeline. It is the expected way for an endless stream to end.
    (
        set +o pipefail
        openssl enc -aes-256-ctr -pass "pass:${label}" -nosalt -in /dev/zero 2>/dev/null \
            | head -c "$count"
    )
}

# pick sets PICK_VALUE to one of its arguments, for the same reason.
PICK_VALUE=""
pick() {
    rand $#
    eval "PICK_VALUE=\${$((RAND_VALUE + 1))}"
}

# --- Self-check: the seed must reproduce ---
#
# The harness's central promise is that a failing round can be replayed from
# the printed seed. If the generator drifts, the seed is decoration and every
# failure it ever reports is unreproducible. Two short sequences from the same
# seed are compared before any transfer runs.
selftest() {
    local saved=$RAND_STATE
    local a="" b="" i
    RAND_STATE="$SEED"
    for i in $(seq 1 20); do rand 1000; a="$a $RAND_VALUE"; done
    RAND_STATE="$SEED"
    for i in $(seq 1 20); do rand 1000; b="$b $RAND_VALUE"; done
    RAND_STATE=$saved
    [ "$a" = "$b" ] || fail "the generator is not reproducible from its seed"
    # A stuck generator would also compare equal to itself, so check it moves.
    [ "$(echo "$a" | tr ' ' '\n' | sort -u | wc -l)" -gt 5 ] \
        || fail "the generator produced almost the same value 20 times"
}
selftest

echo "=== dhow chaos soak ==="
echo "rounds ${ROUNDS}, seed ${SEED}"
echo

cargo build --release --quiet --manifest-path "$ROOT/core/Cargo.toml" -p dhow-ffi
(cd "$ROOT" && go build -o "$DHOW" ./cli/cmd/dhow)

"$DHOW" keygen -out "$WORK/operator.key" >/dev/null

for round in $(seq 1 "$ROUNDS"); do
    R="$WORK/round-$round"
    mkdir -p "$R/data/nested"

    # --- A dataset of random shape ---
    #
    # Sizes straddle the boundaries that matter: smaller than one symbol, an
    # exact multiple, and larger than one block.
    rand 200000; SIZE=$RAND_VALUE
    bytes "$SIZE" "${SEED}-${round}-blob" > "$R/data/blob.bin"
    printf 'round %s\n' "$round" > "$R/data/nested/note.txt"
    : > "$R/data/empty.txt"
    rand 2
    if [ "$RAND_VALUE" -eq 0 ]; then
        printf '#!/bin/sh\nexit 0\n' > "$R/data/run.sh"
        chmod +x "$R/data/run.sh"
    fi

    # --- Random coding parameters ---

    pick 64 128 256 512 1024 1320; SYMBOL=$PICK_VALUE
    pick 1 2 3 5 7 8 11 16; BLOCKS=$PICK_VALUE
    pick 0 10 30 50 80 150; OVERHEAD=$PICK_VALUE

    if ! "$DHOW" send -key "$WORK/operator.key" -in "$R/data" -out "$R/frames" \
        -symbol-size "$SYMBOL" -blocks "$BLOCKS" -overhead "$OVERHEAD" \
        >/dev/null 2>"$R/send.err"
    then
        fail "round ${round}: send failed with symbol=${SYMBOL} blocks=${BLOCKS} overhead=${OVERHEAD}: $(cat "$R/send.err")"
    fi

    TOTAL=$(find "$R/frames" -name 'frame-*.bin' | wc -l | tr -d ' ')
    [ "$TOTAL" -gt 0 ] || fail "round ${round}: send produced no frames"

    # --- Random damage to the captured stream ---

    cp -R "$R/frames" "$R/captured"

    # Loss is drawn relative to the repair overhead rather than independently.
    # Drawn independently, most rounds pair heavy loss with no overhead, every
    # one of them fails closed, and the soak stops exercising the path where a
    # transfer actually succeeds. The range still reaches past what the
    # overhead can absorb, so both outcomes stay common.
    rand $(( OVERHEAD / 2 + 20 )); LOSS=$RAND_VALUE
    pick scattered contiguous periodic; PATTERN=$PICK_VALUE
    rand 6; CORRUPT=$RAND_VALUE              # frames whose bytes are mangled

    DROPPED=0
    if [ "$LOSS" -gt 0 ]; then
        case "$PATTERN" in
            scattered)
                EVERY=$((100 / LOSS))
                [ "$EVERY" -lt 2 ] && EVERY=2
                i=0
                for f in "$R/captured"/frame-*.bin; do
                    if [ $((i % EVERY)) -eq 0 ]; then rm -f "$f"; DROPPED=$((DROPPED + 1)); fi
                    i=$((i + 1))
                done
                ;;
            contiguous)
                RUN=$((TOTAL * LOSS / 100))
                rand $((TOTAL - RUN + 1)); START=$RAND_VALUE
                i=0
                for f in "$R/captured"/frame-*.bin; do
                    if [ "$i" -ge "$START" ] && [ "$i" -lt $((START + RUN)) ]; then
                        rm -f "$f"; DROPPED=$((DROPPED + 1))
                    fi
                    i=$((i + 1))
                done
                ;;
            periodic)
                # Deliberately including periods that divide the block count.
                # This is the pattern the operations guide warns about, and the
                # harness must not pretend it does not happen.
                pick 2 3 4 5 7 8 11 16; PERIOD=$PICK_VALUE
                i=0
                for f in "$R/captured"/frame-*.bin; do
                    if [ $((i % PERIOD)) -eq 0 ]; then rm -f "$f"; DROPPED=$((DROPPED + 1)); fi
                    i=$((i + 1))
                done
                ;;
        esac
    fi

    # Collected into an array rather than piped through head: `find | head -n N`
    # makes head close the pipe, find takes SIGPIPE, and pipefail turns that
    # into a failed pipeline that set -e exits on. It only bites when find is
    # still producing when head stops, so it passes on small rounds and kills
    # large ones, which is the worst way for a harness to be wrong.
    SURVIVORS=("$R/captured"/frame-*.bin)
    for _ in $(seq 1 "$CORRUPT"); do
        [ "${#SURVIVORS[@]}" -gt 0 ] || break
        rand "${#SURVIVORS[@]}"
        VICTIM="${SURVIVORS[$RAND_VALUE]}"
        [ -f "$VICTIM" ] || continue
        rand 40; OFFSET=$RAND_VALUE
        printf '\xa5' | dd of="$VICTIM" bs=1 seek="$OFFSET" conv=notrunc status=none
    done

    # --- Receive, sometimes killed partway ---

    rand 3; KILL=$RAND_VALUE   # one round in three is interrupted and resumed
    STATE_DIR="$R/state"
    EXIT_CODE=0

    RESUMED=no
    if [ "$KILL" -eq 0 ]; then
        rand 80; STOP=$((RAND_VALUE + 1))
        set +e
        "$DHOW" recv -key "$WORK/operator.key" -in "$R/captured" -out "$R/received" \
            -state "$STATE_DIR" -stop-after "$STOP" >/dev/null 2>"$R/first.err"
        FIRST_EXIT=$?
        set -e

        case "$FIRST_EXIT" in
            0)
                # A small dataset can finish inside the frame budget. That is a
                # completed transfer, not an interrupted one, and asserting it
                # wrote nothing would be asserting something untrue.
                KILL=1
                ;;
            4)
                # Interrupted. Nothing may have been written yet.
                [ ! -d "$R/received" ] \
                    || fail "round ${round}: an interrupted receive wrote a dataset"
                RESUMED=yes
                ;;
            *)
                fail "round ${round}: an interrupted receive exited ${FIRST_EXIT}: $(cat "$R/first.err")"
                ;;
        esac
    fi

    set +e
    if [ "$RESUMED" = yes ]; then
        "$DHOW" recv -key "$WORK/operator.key" -in "$R/captured" -out "$R/received" \
            -state "$STATE_DIR" >/dev/null 2>"$R/recv.err"
        EXIT_CODE=$?
    elif [ "$KILL" -eq 0 ]; then
        "$DHOW" recv -key "$WORK/operator.key" -in "$R/captured" -out "$R/received" \
            >/dev/null 2>"$R/recv.err"
        EXIT_CODE=$?
    else
        # Either an ordinary round, or one whose "interruption" turned out to
        # complete the transfer. Reuse the result rather than receiving twice.
        if [ -d "$R/received" ]; then
            EXIT_CODE=0
        else
            "$DHOW" recv -key "$WORK/operator.key" -in "$R/captured" -out "$R/received" \
                >/dev/null 2>"$R/recv.err"
            EXIT_CODE=$?
        fi
    fi
    set -e

    DESC="symbol=${SYMBOL} blocks=${BLOCKS} overhead=${OVERHEAD} loss=${LOSS}%/${PATTERN} dropped=${DROPPED}/${TOTAL} corrupt=${CORRUPT} resumed=${RESUMED}"

    [ -n "${CHAOS_VERBOSE:-}" ] && echo "  round ${round}: exit ${EXIT_CODE} ${DESC}"

    case "$EXIT_CODE" in
        0)
            # Completed. The dataset must be identical and must verify. A
            # transfer that says it succeeded and did not is the failure this
            # whole harness exists to find.
            diff -r "$R/data" "$R/received" >/dev/null \
                || fail "round ${round}: SILENT CORRUPTION - recv succeeded but the dataset differs (${DESC})"
            # The verify output is captured, not discarded. A harness that
            # reports "verify rejected the dataset" without saying which file
            # and why has found a defect and thrown away the evidence.
            if ! "$DHOW" verify -in "$R/frames" -dir "$R/received" -json > "$R/verify.json" 2>&1; then
                fail "round ${round}: recv succeeded but verify rejected the dataset (${DESC})
$(cat "$R/verify.json")"
            fi
            if [ -f "$R/data/run.sh" ] && [ ! -x "$R/received/run.sh" ]; then
                fail "round ${round}: the executable bit was lost (${DESC})"
            fi
            COMPLETED=$((COMPLETED + 1))
            ;;
        4)
            # Failed closed. Nothing may have been written.
            [ ! -d "$R/received" ] \
                || fail "round ${round}: an incomplete transfer wrote a dataset (${DESC})"
            CLOSED=$((CLOSED + 1))
            ;;
        *)
            fail "round ${round}: recv exited ${EXIT_CODE}, which is neither success nor incomplete (${DESC}): $(cat "$R/recv.err")"
            ;;
    esac

    # Keep the working set bounded so a long soak does not fill the disk.
    rm -rf "$R"
done

# A soak in which nothing ever completes is not testing the success path, and a
# soak in which nothing ever fails is not testing the failure path. Either way
# it would keep passing while covering half of what it claims. This is the
# check that noticed the first version of this harness injecting one fault
# repeatedly, and it stays.
if [ "$ROUNDS" -ge 10 ]; then
    [ "$COMPLETED" -gt 0 ] \
        || fail "no round completed in ${ROUNDS}; the soak is not exercising a successful transfer"
    [ "$CLOSED" -gt 0 ] \
        || fail "no round failed closed in ${ROUNDS}; the soak is not exercising the failure path"
fi

echo "  rounds     ${ROUNDS}"
echo "  completed  ${COMPLETED}"
echo "  closed     ${CLOSED}"
echo "  corrupted  0"
echo
echo "=== CHAOS PASSED (seed ${SEED}) ==="
