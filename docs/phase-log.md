# Phase Log

## Phase 28 - Wire the signed manifest through the CLI

**Objective:** `dhow-crypt` has implemented manifest signing, verification,
`Policy`, and `VerifiedManifest` since Phase 15, and none of it has ever been
reachable from the command line. `send` writes an unsigned `transfer.json`
beside the frames and `verify` checks against that, so `dhow verify` answers
"does this dataset still match the record?" and not "was this produced by
someone holding the operator's signing key?" - anyone who can edit the dataset
can edit the record sitting next to it. This phase closes that gap: an FFI
surface for identity handles and for manifest build and verify, a manifest wire
format that carries everything the JSON record carried, and `keygen`, `send`,
`recv`, and `verify` wired through it. The unsigned record is deleted, not
deprecated.

**Gates:** the manifest round-trips through the ABI with its inventory intact;
a manifest signed by the wrong identity, or altered in any byte, is rejected by
both `recv` and `verify`; `transfer.json` no longer exists anywhere in the
tree; `scripts/gate.sh` stays green.

## Phase 27 - Chaos and soak

**Objective:** Every test so far picks the fault it injects. A harness that
picks them at random, from a seed it prints, runs many transfers unattended
with randomised coding parameters, loss rates, corruption, and mid-transfer
kills, and asserts the only two acceptable outcomes: the transfer completes
and the dataset verifies byte for byte, or it fails closed and writes nothing
wrong. Silent corruption is the one result that is never acceptable.

**Gates:** a soak of many consecutive randomised rounds with zero silent
corruption; the seed reproduces a failing round exactly; the harness runs
bounded in the gate and unbounded on demand.

### The harness found three defects, two of them its own

Writing a fault-injection harness that is itself wrong is the obvious failure
mode, and it happened three times before the harness was worth anything.

**The generator never advanced.** `x=$(rand 10)` runs the function in a
subshell, so the mutated state died with it and every round drew the same
numbers. Twelve rounds of "randomised" testing were twelve copies of one
round. `rand` now sets a variable instead of echoing, and a self-check
compares two sequences from one seed *and* checks the sequence moves, because
a stuck generator compares equal to itself.

**`find | head -n N` was a coin flip.** head closes the pipe, find takes
SIGPIPE, and `pipefail` reports that as a failed pipeline that `set -e` exits
on. It only fires when find is still producing when head stops, so it passed
on small rounds and killed large ones - the worst way for a harness to be
wrong, because it looks like flakiness. Replaced with an array.

**An "interrupted" receive sometimes finished.** `-stop-after N` with a small
dataset completes the transfer, and the harness then asserted that an
interrupted receive had written nothing, which was untrue. It now branches on
what the first receive actually did.

The third defect was real and in the product. See below.

### Loss is drawn relative to the overhead, on purpose

The first working version drew loss independently of repair overhead. Most
rounds paired heavy loss with no overhead, every one failed closed, and the
soak silently stopped exercising a successful transfer at all - it was
measuring one half of the invariant and reporting a pass.

Loss is now drawn from a range that scales with the overhead, and a soak of
ten rounds or more asserts that *both* outcomes occurred. A harness that
degenerates into testing one path keeps passing, which is the failure mode
that matters most in a test you are not watching.

The periodic loss pattern deliberately includes periods that divide the block
count - the case `docs/OPERATIONS.md` warns operators about. A harness that
avoided it would be testing a friendlier world than the one operators work in.

### Defect found: a failed extraction left a partial dataset

The harness asserts that a round which fails closed has written nothing. That
invariant, written down, exposed that extraction wrote directly into the
output directory. A failure partway through - a name the archive should not
have contained, a disk filling, a permission the destination does not grant -
left whatever had been written so far.

The transfer reported failure either way, but an operator rerunning a script
and finding a populated directory has been handed something that looks like
output and is not.

Extraction now stages into a sibling directory and renames, so the output
either holds the whole dataset or does not exist. A sibling rather than the
system temporary directory, because a rename across filesystems is a copy and
the point is that the last step is atomic. An output directory that already
exists is refused rather than merged into: blending two datasets would leave
every file that happened to match still verifying, which is the most
misleading result available.

### One failure got away, and it is in the backlog

The first 120-round soak reported:

```
FAIL  round 120: recv succeeded but verify rejected the dataset
      (symbol=1320 blocks=7 overhead=50 loss=5%/contiguous dropped=8/161
       corrupt=0 resumed=no)
```

The harness runs `diff -r` before `verify` and the diff passed, so the dataset
was byte-for-byte correct and `verify` rejected it anyway. That points at the
transfer record's inventory rather than at the transfer.

**It has not been reproduced.** Re-running the same seed passed, because the
harness was drawing dataset bytes from `/dev/urandom` and only the *parameters*
from the seed - so the seed reproduced the shape of the round and not its data.
That was a real gap in the harness's central promise, and it is fixed: content
now comes from an AES-CTR keystream keyed by the seed and the round. The fix
cannot recover the bytes that triggered the original failure.

Four further soaks of sixty rounds each, on seeds 7919, 15838, 23757, and
31676, have not reproduced it. That is 240 rounds with the seeded-data
harness, none of which failed and none of which reported corruption. Absence
over 240 rounds is weak evidence about a failure seen once in 120; it is not
grounds for closing the item.

It is recorded as `B-1` in `docs/BACKLOG.md` with what is known: `diff` does
not compare permissions, so a lost executable bit produces exactly this
signature, and so does a wrong recorded digest - which would be far more
serious, because it would make `verify` unreliable in both directions. The
failure message now carries `verify`'s JSON, which names the file and the
problem kind and distinguishes the two on the next occurrence.

Reporting this as a clean phase would have been easy and wrong.

### Deviation

Thirteen atomic commits, below the twenty-commit floor. The phase is one
harness, one defect it found, and the documentation of both; splitting the
harness into a dozen commits would have been padding rather than
decomposition. Recording the shortfall as the git procedure requires.

The pack's Phase 38 gate calls for 100 consecutive transfers with randomised
faults. The soak for this phase was 120 rounds plus four runs of sixty, 360 in
total, all of which passed with zero silent corruption. The gate itself runs
twelve on a fixed seed, because a gate's job is to confirm the harness still
works, not to search; CI runs forty on a seed that varies by run number.
Searching in earnest is `scripts/chaos.sh 500` on a fresh seed, and
`CONTRIBUTING.md` says when to do it.

### Soak output

```
$ scripts/chaos.sh 120 20260803
  rounds     120
  completed  71
  closed     49
  corrupted  0

$ scripts/chaos.sh 60 7919      # and 15838, 23757, 31676
  rounds     60
  completed  33
  closed     27
  corrupted  0
```

### Gate output

```
$ ./scripts/gate.sh
  Passed: 15
  Failed: 0
ALL GATES PASSED
```

The gate grows to fifteen checks with the chaos soak.


## Phase 26 - Operator UX and the operations guide

**Objective:** Make the tool usable by someone who did not build it. A
coherent `-quiet` and `-verbose` across every command, live progress while a
receive runs, error messages that name a next step rather than only a cause,
an exit-code contract that is tested rather than merely documented, and
`docs/OPERATIONS.md` covering physical setup, throughput, troubleshooting, and
the key ceremony.

The operations guide must cover how block count interacts with the loss
pattern a physical setup produces. Phase 23 found that interleaving moves the
pathological case rather than removing it, and that is an operator-facing
consequence, not an implementation detail.

**Gates:** every documented exit code is produced by a test that provokes it;
`-quiet` and `-verbose` change what is printed without changing exit codes or
JSON; a cold-start drill following only the guide completes a transfer.

### The guide is a gate, not a document

`scripts/drill.sh` runs the commands `docs/OPERATIONS.md` tells an operator to
run, with the parameters from its own worked example, and checks the claims it
makes rather than the code's behaviour: mode 0600, a permissive key refused, an
existing key not overwritten, symbol size 1320 fitting QR version 30 at ECC M,
the per-block progress line the troubleshooting section tells operators to
read, and every exit code in its table. It also greps the guide for the
commands it copied, so editing the worked example without updating the drill
fails rather than leaving the drill silently testing something the guide no
longer says.

A guide is only as good as the last time someone followed it, and nobody
follows a guide they wrote. This does, on every gate run and on every pull
request.

Writing it found one real error in the guide immediately: the display example
used a frame rate above the 120 fps the command accepts. An operator would
have hit that after setting up a camera.

### The block-count advice is demonstrated, not asserted

The guide's longest section asks an operator to choose a prime block count on
the strength of a claim about periodic loss. Phase 23 established that
interleaving fixed contiguous outage but moved the pathological case to loss
on a period *equal to* the block count, which now concentrates on one block.

The drill demonstrates it. The same dataset is sent at 8 blocks and at 11, and
every 8th frame is dropped from both:

```
  PASS  the guide's block-count advice holds: 8 blocks fails where 11 survives
```

The 8-block transfer exits 4 and the 11-block transfer round trips byte for
byte, under identical loss. An operator is being asked to change a parameter
on the basis of that claim, so the claim carries its own evidence.

### Verbosity: three decisions worth recording

`-quiet` and `-verbose` are registered by every command through one helper, so
they mean the same thing everywhere. Three choices:

- **`-quiet` never suppresses a failure.** It drops the end-of-command summary
  a person reads. A `verify` that failed still reports its problems, because a
  display preference that hides a correctness result is a hazard, not a
  preference.
- **`-quiet` never suppresses `-json`.** A caller asking for machine output and
  silence together wants the JSON; dropping it would be data loss dressed up as
  quiet.
- **Both together is exit 1, not a precedence rule.** Guessing which was meant
  would make the tool unpredictable in exactly the situation where the operator
  is already unsure what it is doing.

Progress is reported by block rather than by frame. Frames arrive in their
thousands and almost none of them change anything an operator can act on; a
block completing is the unit of real progress and is what tells them whether
moving the camera is helping.

### The wrong key now says so

A wrong key is indistinguishable from a bad camera angle until the stream
ends, which on a real capture is hours: frames arrive, none authenticate, and
the block count sits at zero. Fifty frames read with none accepted is not
ambiguous, so `-verbose` says it outright. The threshold is high enough not to
fire on the ordinary run of unreadable frames at the start of a capture,
because a warning that cries wolf on healthy runs gets ignored on the run
where it matters. A test asserts both halves of that.

### Exit code 5 is deliberately unprovoked

Five of the six documented codes have a test that produces them. `5` means an
internal bug. Provoking it would mean building a fault-injection path into the
shipped binary to prove a code that says "this should never happen", which
would be a worse trade than the coverage is worth. `docs/UX-REVIEW.md` records
that as a known gap rather than leaving the row looking complete.

### Deviation

The pack's Phase 32 gate calls for "a cold-start operator following only the
doc". The drill is a scripted simulation of that, not a person, and it cannot
exercise the camera, which does not exist. The guide states that limitation in
its first paragraph so a reader does not follow it expecting hardware to work.

The throughput table is arithmetic over the measured QR capacity table rather
than measurements of a real camera, and says so in the text. An operator plans
a seven-hour capture around those numbers; presenting derived figures as
observed ones would be worse than presenting no figures at all.

### Drill output

```
$ scripts/drill.sh
  PASS  the drill matches the guide's worked example
  PASS  key ceremony behaves as the guide describes
  PASS  sent 528 frames and they fit the guide's QR version
  PASS  receive reported the progress the guide tells operators to watch
  PASS  dataset round tripped and verified
  PASS  every exit code in the guide's table is the code produced
  PASS  the guide's block-count advice holds: 8 blocks fails where 11 survives
=== DRILL PASSED ===
```

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===        PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===               PASS
=== GATE: cargo audit ===              PASS
=== GATE: cargo deny ===               PASS
=== GATE: ABI drift ===                PASS
=== GATE: build rust core for cgo ===  PASS
=== GATE: go vet ===                   PASS
=== GATE: go test -race ===            PASS
=== GATE: go build ===                 PASS
=== GATE: golangci-lint ===            PASS
=== GATE: govulncheck ===              PASS
=== GATE: loopback end-to-end ===      PASS
=== GATE: operations guide drill ===   PASS

=== GATE SUMMARY ===
  Passed: 14
  Failed: 0
ALL GATES PASSED
```

The gate grows to fourteen checks. 21 atomic commits.

## Phase 25 - Verification that checks contents

**Objective:** `dhow verify` currently counts files. A dataset with the right
number of files, every one of them corrupted, passes. This phase gives the
command something to check against: the transfer record gains a per-file
inventory - name, size, executable bit, and content digest - and verify walks
the extracted dataset and compares every one of them, reporting each
discrepancy precisely rather than as a single failure.

**Gates:** verify passes on a good dataset and fails with a distinct, accurate
diagnosis for each corruption class: a missing file, an extra file, a
truncated file, a single flipped byte, and a lost executable bit.

### What the command was, and why it was not verification

`verify` counted the regular files under a directory and compared the number
with the count in the transfer record. A dataset with the right number of
files and every one of them corrupted passed. It could not distinguish a
transfer from a directory of the same shape filled with zeroes.

`recv` was never the problem: it checks the payload digest and the AEAD tag
before it extracts a byte, so a dataset that exists on disk was correct when
written. The question `verify` exists to answer is a different one - is it
still correct *now*, months later, after a disk, a backup, and a sync tool
have all had a turn. Answering it needs something to compare against, and the
record carried nothing but a count.

The record now carries an inventory: name, size, executable bit, and BLAKE3
content digest per file, taken from the same read that fed the archive. verify
walks the dataset and checks all four, plus files present that were never
sent.

Three decisions worth recording. Size is checked before contents, so a
truncated file is reported as truncated rather than as a digest mismatch,
which says only that *something* is wrong. A wrong executable bit does not
suppress the content check, or the more serious of two problems would be
hidden by the lesser. And every discrepancy is reported in one run: an
operator staring at a dataset that came back wrong needs the whole picture,
not the alphabetically first part of it.

Problems carry a stable `kind` beside the prose, so a script branches on
`content` rather than on a sentence that may be reworded.

### Avoided: a memory regression, and a second BLAKE3

Two things went differently than the obvious implementation.

Go has no BLAKE3. Adding one would mean the digest that decides whether a
dataset verified had two implementations - the transfer's and verify's - which
would disagree silently rather than loudly. The core exposes its own instead,
so there is one.

The first version of the packing change hashed each file by buffering it and
digesting the buffer. That turns a working set bounded by the payload into one
that also grows with the largest single file, which is a real regression on
exactly the datasets this tool exists for. Replaced with a streaming hasher
across the FFI: `pack` hashes through an `io.MultiWriter` on the stream that
already feeds the archive, so no part of a file is held on the digest's
account, and `verify` streams each file rather than reading it whole.

The streamed and one-shot digests are asserted equal at eight different write
sizes, on and off BLAKE3's 1024-byte chunk boundary, because a hasher that
mishandles a partial chunk agrees with the one-shot only when the splits
happen to align.

### Defect found: an ABI-version test pinned to a literal

`test_abi_version_is_two` asserted the literal `2`, and failed the moment the
version moved to 3. A test whose only failure mode is being out of date gets
updated reflexively rather than read, so it now checks that the exported
function agrees with the constant. The Go bindings still assert the number
itself, which is where a disagreement between the two sides actually matters.

`ineffassign` also caught a variable assigned and immediately replaced in a
new test - a finding that only surfaces because Phase 24 made the linter
config apply.

### Deviation

The pack's Phase 30 calls for verification "against its manifest". The signed
Ed25519 manifest exists in `dhow-crypt` but is not yet wired to the CLI, so
verify checks against the transfer record, which is the documented stand-in
until the manifest travels in the frame stream.

The difference is stated plainly in `docs/VERIFY.md` rather than glossed: the
record is unsigned and sits beside the dataset, so verify answers "does this
dataset still match the record?" and not "was this produced by someone holding
the operator key?". Wiring the signed manifest through send, recv, and verify
is its own phase.

### Verified by hand

```
$ dhow verify -in frames -dir got
session   5a4f2099a4bb8fc90a88ee09c48ad4b3
files     3
bytes     5024
result    OK

$ dhow verify -in frames -dir got     # one byte flipped, one file removed,
session   5a4f2099a4bb8fc90a88ee09c48ad4b3   # one planted, one chmod -x
files     2 checked of 3
result    FAILED
  - a.txt: missing from the dataset
  - run.sh: is not executable but was sent executable
  - sub/blob.bin: contents differ: digest ac633003, expected e1ddb64b
  - extra.txt: is not part of the transfer
                                                                     exit 3
```

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===        PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===               PASS
=== GATE: cargo audit ===              PASS
=== GATE: cargo deny ===               PASS
=== GATE: ABI drift ===                PASS
=== GATE: build rust core for cgo ===  PASS
=== GATE: go vet ===                   PASS
=== GATE: go test -race ===            PASS
=== GATE: go build ===                 PASS
=== GATE: golangci-lint ===            PASS
=== GATE: govulncheck ===              PASS
=== GATE: loopback end-to-end ===      PASS

=== GATE SUMMARY ===
  Passed: 13
  Failed: 0
ALL GATES PASSED
```

```
$ scripts/loopback.sh 2 20
  PASS  verify accepts a good dataset
  PASS  verify catches a single flipped byte in a good-looking dataset
  PASS  verify rejects a damaged dataset
=== LOOPBACK PASSED in 6s ===
```

430 Rust tests and every Go package pass. The ABI moves to version 3 for the
one-shot digest and the streaming hasher.

## Phase 24 - Interruption and resume, full stack

**Objective:** A receiver that survives being killed. Progress is persisted to
disk as it is earned, a restart picks the transfer up where it stopped rather
than from zero, and a resume state that has been tampered with or that belongs
to another session is rejected rather than trusted. The persistence path runs
the whole stack: the codec records which symbols each block holds, the resume
wire format carries that record with its own integrity protection, the FFI
exposes save and verify, and the CLI drives both.

**Gates:** a receiver killed partway through a transfer restarts and completes;
every tampering class against the resume state is rejected with a distinct
error; the Rust CI gates actually execute for the first time.

### The design problem: RaptorQ state cannot be serialized

The obvious implementation of resume - save the decoder, load it back - is not
available. A RaptorQ decoder holds partially-solved linear systems, not a set
of symbols, and the crate exposes no way to serialize one. So progress is kept
the only way it can be: the receiver journals the frames it accepted and
replays them into a fresh decoder on restart.

That turns the problem into a different one. A journal is a file an operator
can edit, so the replay needs something to check itself against, and the
existing resume format could not provide it. Version 1 recorded which symbols
each block held - which says what the replay should produce, not what the
journal on disk is. Two journals with the same symbols in a different order
produce identical bitmaps and different decoder states.

Version 2 adds the binding. The decoder keeps a rolling BLAKE3 over the bytes
of every accepted frame in acceptance order; the resume file carries it. Any
reordering, insertion, truncation, or substitution moves it. There is a test
that asserts the bitmaps are identical before showing that the digest still
catches a swap of two frames, because that is the case the bitmap alone
cannot see.

The second field is `journal_bytes`. The journal is appended on every accepted
frame while the index is rewritten every 200, so a crash routinely leaves a
journal longer than its index. Without a recorded length that ordinary residue
would fail the digest and cost the operator the whole capture. With it, the
tail is discarded as progress that was never durably recorded. The opposite
case - an index covering more journal than exists - is refused, because the
journal is fsynced before the index that describes it, so it cannot happen by
accident.

The header grew from 96 to 128 bytes to hold both. `proto/migration.md`
records that there is no conversion from v1: the digest a v1 file would need
was never computed. The cost is one discarded state directory, and nothing
that crossed the optical channel is affected.

### What actually defends the resume path

The threat model's entry for tampered resume files credited the integrity
digest with stopping tampering. It does not. A resume file is local state with
no key in it, so anyone who can rewrite the file can recompute both its CRC
and its digest.

What stops a doctored journal is that every replayed frame goes through
`Decoder.Accept` exactly as it did on first capture: MAC against the session
key, CRC, session binding, symbol bounds. The state directory holds no key
material. The digests buy something real but smaller - a half-written index is
never believed, and an index cannot be paired with a journal it does not
describe - and the entry now says so, along with the residual risk that
someone with write access can still delete the directory and cost a recapture.

### Defect found: the golden vectors were BLAKE2b, not BLAKE3

Adding the first Rust test that parses the committed resume vectors made them
fail their own integrity check. `scripts/gen_vectors.py` had a function named
`blake3` whose body was `hashlib.blake2b`. Every integrity digest in
`proto/vectors.json` was a BLAKE2b digest published as BLAKE3, and had been
since Phase 3.

Nothing caught it because nothing had ever parsed those vectors. The chunker
vectors are the only ones with a Rust golden test and they carry no digests;
`check_spec.py` and `conformance_test.py` checked structure, sizes, magic, and
reserved fields, never a digest value.

This mattered beyond the repository. The vectors are the conformance suite a
third-party implementation is meant to build against, so anyone following them
would have shipped a receiver that rejects every real Dhow transfer.

Fixed with a pure-Python reference BLAKE3 in `scripts/blake3_ref.py`, kept
deliberately as a second implementation - calling into the Rust core would
make the vectors agree with the code by construction and stop being evidence
of anything. It self-tests against the published BLAKE3 vectors at eleven
input lengths, including the multi-chunk tree cases that a naive
implementation gets wrong. The Rust side now parses the resume vectors and
re-serializes them byte for byte, so the loop is closed in both directions.

The conformance suite's version check was also hardcoded to `0x01` for every
format, which would have let any format be bumped without the suite noticing.
It now takes the expected version per vector.

### Defect found: the CI Rust gates had never run

Every one of them, since Phase 2:

- `rustfmt`, `clippy`, `rust-test`, and `cargo-deny` ran `cargo` from the
  repository root. The workspace is in `core/`, so each died with "could not
  find Cargo.toml" before doing any work.
- `cargo-audit` referenced `rustsec/audit-ci-action`, which does not exist.
  The job failed at action resolution, before any advisory database was
  consulted.
- No Go job built the Rust staticlib the cgo package links against, so
  `go vet`, `go build`, `govulncheck`, and `golangci-lint` all died at the
  linker on `-ldhow_ffi`.
- CI ran no Go tests at all, only vet and build. The race detector is the
  reason to run them in CI.

All fixed, plus a `go-test` job that runs `go test -race` to match
`scripts/gate.sh`.

### Defect found: the golangci-lint config had never applied

`.golangci.yml` used the v1 top-level `linters-settings` and
`issues.exclude-rules` keys. golangci-lint v2 rejects both:

```
$ golangci-lint config verify        # before
jsonschema: "issues" does not validate with "/properties/issues/additionalProperties": additional properties 'exclude-rules' not allowed
jsonschema: "" does not validate with "/additionalProperties": additional properties 'linters-settings' not allowed
The command is terminated due to an error: the configuration contains invalid elements
```

`golangci-lint run` did not fail on this - it discarded the unknown keys and
linted with defaults. So the gate ran green for twenty-two phases while none
of the configured strictness was in effect.

With the keys parsed, nineteen findings surfaced. Fifteen were `check-blank`
flagging the codebase's deliberate, commented `_ = f.Close()`, which is the
explicit form errcheck exists to encourage; `check-blank` leaves no way to
express "considered and discarded", so it is turned off with the reason
recorded in the config rather than dropped quietly. Two unchecked type
assertions in tests and two gocritic style findings were real and are fixed.
gocritic's `dupImport` reads cgo's `C` and `unsafe` as one import twice and
cannot be satisfied in source, so it is excluded for that one file.

### Deviation

The gate for this phase, as written in the pack, called for killing the
receiver at 40 percent in loopback. The harness does that with `-stop-after`
rather than a signal: the directory transport processes six thousand frames in
about a second, so timing a `kill` against it is a race that would make the
harness flaky rather than strict. `SIGINT` and `SIGTERM` are implemented and
save before exiting - that is what an operator's Ctrl-C does - but the
unattended harness drives the deterministic path. Two interruptions are used
rather than one, so a journal that is replayed, extended, and replayed again
is covered.

### Harness output

```
$ scripts/loopback.sh 4 20
  PASS  sent 6592 frames in 1s
  PASS  clean transfer round trips byte for byte
  PASS  executable bit survived
  PASS  recovered from 1319 dropped frames
  PASS  recovered from a contiguous outage of 1098 frames
  PASS  corrupted frames were rejected without poisoning the decode
  PASS  resumed through two interruptions and round tripped byte for byte
  PASS  tampered resume state and journal both fail closed
  PASS  wrong key fails closed and writes nothing
  PASS  verify accepts a good dataset
  PASS  verify rejects a damaged dataset
  PASS  two sends of one dataset produce the same frame count
=== LOOPBACK PASSED in 13s ===
```

### Verified by hand

```
$ dhow recv -key op.key -in frames -out received -state state -stop-after 60
dhow: transfer incomplete: 60 frames accepted, 0 rejected; stopped before the
end of the stream; progress saved in state, rerun with -state state to continue

$ dhow recv -key op.key -in frames -out received -state state
resumed 60 frames from state
session   b023b5ee4a9dbff4d5ca703459dbdb8d
resumed   60 frames
accepted  256 frames
rejected  0 frames
files     2
written   received
```

Each tampering class, through the shipped binary:

```
$ dhow recv ... -state state          # one byte flipped in the index
dhow: saved state in state is unusable (dhow: resume state rejected: resume
file integrity check failed (possible tampering)); delete it to start this
transfer over                                                        exit 2

$ dhow recv ... -state state          # one byte flipped in a journaled frame
dhow: replaying saved progress from state: replaying journal record at 0:
dhow: frame rejected: frame error: CRC32C mismatch                   exit 2

$ dhow recv ... -state state          # state from a different transfer
dhow: saved state in state belongs to session b023b5ee..., not eb96facf...;
point -state at the right directory                                  exit 2
```

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===       PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===              PASS
=== GATE: cargo audit ===             PASS
=== GATE: cargo deny ===              PASS
=== GATE: ABI drift ===               PASS
=== GATE: build rust core for cgo === PASS
=== GATE: go vet ===                  PASS
=== GATE: go test -race ===           PASS
=== GATE: go build ===                PASS
=== GATE: golangci-lint ===           PASS
=== GATE: govulncheck ===             PASS
=== GATE: loopback end-to-end ===     PASS

=== GATE SUMMARY ===
  Passed: 13
  Failed: 0
ALL GATES PASSED
```

427 Rust tests and every Go package pass; the ABI moves to version 2 for the
three new entry points and the new status code.

## Phase 23 - Loopback integration

**Objective:** An unattended end-to-end harness that runs a real transfer
through the shipped binary with faults injected, wired into the gate.

**Gates:** loopback transfer completes unattended; scattered loss, contiguous
outage, corruption, wrong key, and a damaged dataset all handled as intended.

### Defect found: contiguous loss was unrecoverable

The harness earned its place immediately. Its first version dropped a
contiguous run of frames and the transfer failed. That looked like a harness
bug and was really the codec reporting a genuine weakness.

Frames were emitted block by block, so every frame of block 0 came first. A
contiguous outage - an operator stepping in front of the screen, a camera
refocusing, a light flickering - falls entirely inside one block. RaptorQ
repairs *within* a block and never across blocks, so a block whose whole run
was missed is unrecoverable at any repair overhead.

Fixed by interleaving frames round-robin across blocks, which spreads any
contiguous run of loss evenly over every block. A test drops a fifth of the
stream as one unbroken run and still completes; the harness drops a sixth.

### Consequence worth knowing

Interleaving moves the pathological case rather than removing it. Loss on a
period *equal to the block count* now lands on the same block every time and
concentrates there, which is the one pattern interleaving cannot help. A real
camera does not drop on such a period, but a test can, and one in the
end-to-end suite did: it dropped every fourth frame against four blocks and
began failing the moment interleaving landed. Its stride is now coprime with
the block count, with the reason recorded at the call site.

This belongs in the operations guide when Phase 32 writes it: block count
interacts with the loss pattern the physical setup produces.

### Harness output

```
$ scripts/loopback.sh 4 20
  PASS  sent 6592 frames in 0s
  PASS  clean transfer round trips byte for byte
  PASS  executable bit survived
  PASS  recovered from 1319 dropped frames
  PASS  recovered from a contiguous outage of 1098 frames
  PASS  corrupted frames were rejected without poisoning the decode
  PASS  wrong key fails closed and writes nothing
  PASS  verify accepts a good dataset
  PASS  verify rejects a damaged dataset
=== LOOPBACK PASSED in 11s ===
```

### Gate output

```
$ ./scripts/gate.sh
  Passed: 13
  Failed: 0
ALL GATES PASSED
```


## Phase 22 - Screen renderer

**Objective:** A display loop that shows a frame stream at a configurable
rate, opens with a calibration pattern and an on-screen session fingerprint,
and ends cleanly when the operator stops it.

**Gates:** renders on a headless surface; frame pacing measured within
tolerance; calibration output deterministic for a session and distinct between
sessions.

### Design notes

The sender has no back channel. It cannot know which frames the camera caught,
so it loops the whole stream until stopped, and every pass is identical, which
is what lets the receiver treat any capture of a frame as interchangeable.

Pacing uses a ticker rather than sleeping the frame interval after each draw.
Sleeping would let render time accumulate: a draw costing 5ms would make every
subsequent frame 5ms late, and the drift would compound across a long stream.

The calibration pattern is a QR code holding a fixed public string rather than
an arbitrary image, so the operator can confirm with any phone scanner that the
screen, distance, and lighting can read a code of this size before committing
to a transfer. The fingerprint lets both operators establish by eye that they
are on the same session, which no protocol can do for them across an air gap.

The command writes its summary to stderr so stdout carries only what a camera
should see.

### Verified by hand

```
$ dhow display -in frames -fps 40 -loops 1 -calibration 1 -no-clear -qr-version 20
CALIBRATION  session AFA2-6DA9-574B-B483
session AFA2-6DA9-574B-B483   frame 1/29   pass 1
shown       29 frames over 1 passes in 1s
```

### Gate output

```
$ ./scripts/gate.sh
  Passed: 12
  Failed: 0
ALL GATES PASSED
```


## Phase 21 - QR frame encoding

**Objective:** Pack wire frames into QR codes with configurable version and
error-correction level, derive the capacity table by measurement rather than
guesswork, and render frames to a terminal and to PNG. Frame-to-QR is 1:1 and
deterministic.

**Gates:** encode/decode identity through the module grid; capacity table
committed with its generation script; rendering deterministic; every capacity
boundary exact in both directions.

### Design notes

Capacity is measured by binary searching the real encoder rather than derived
from the specification's codeword arithmetic. A hand-transcribed table that is
optimistic by one byte fails only for frames that fill a version exactly, which
is the worst kind of intermittent bug. A test asserts that at every sampled
version and level, exactly `capacity` bytes encode and `capacity + 1` does not.

Pinning the QR version is not merely a preference. A stream whose frames
changed size mid-transfer would force the receiver to re-acquire focus and
framing on every change, so `encode_at` fixes the version and also disables
qrcodegen's automatic error-correction boost, which would otherwise move a
frame away from the level the operator chose.

Rendering takes a scale in pixels per module rather than a target image size,
because the operator's real constraint is how large a module appears on screen,
which is what decides whether a capture works at a given distance. PNG output
is a two-entry paletted image so no anti-aliasing or colour management step can
soften a module edge.

QR encoding stays in Rust and crosses the ABI as a module grid. Reusing the
audited `qrcodegen` avoids adding a second QR implementation to the dependency
tree, and passing one byte per module in a single buffer costs one allocation
per frame instead of tens of thousands of boundary crossings.

### Verified by hand

```
$ dhow send -key operator.key -in data -out qrframes -qr -qr-version 20 -qr-scale 6
frames    35
$ file qrframes/frame-000000.png
PNG image data, 630 x 630, 1-bit colormap, non-interlaced
$ dhow recv -key operator.key -in qrframes -out r2 && diff -r data r2
# identical
```

630 = (97 modules + 8 quiet-zone modules) x 6 pixels, as intended.

### Not covered

The rendered PNGs are not yet decoded back through a QR *reader*; that is
Phase 25 (QR detection and extraction), which needs a decoder the project does
not have yet. What is proved here is that the module grid round-trips and that
the rendering is faithful to it, not that a camera can read the result.

### Gate output

```
$ ./scripts/gate.sh
  Passed: 12
  Failed: 0
ALL GATES PASSED
```

```
$ cargo test -p dhow-codec --lib qr     25 passed
$ go test ./cli/internal/render/        ok
```


## Phase 20 - CLI surface and dataset packaging

**Objective:** Make `dhow` a runnable binary. Implement `keygen`, `send`,
`recv`, `verify`, and `version` with documented exit codes and `--json` output,
plus deterministic dataset packing and traversal-safe extraction.

**Gates:** exit-code contract tests; byte-identical archive across two runs;
traversal and bomb fixtures rejected; a full send and receive round trip
recovers the dataset byte for byte.

### Starting point

`cli/cmd/dhow/main.go` was `func main() {}`. There was no command surface and
no way to run a transfer.

### Design notes

Packing records no timestamp, uid, gid, or inode, and sorts entries by name, so
the same tree produces identical bytes on every run and machine. The only mode
bit kept is the executable bit, which changes what a file *is* rather than
describing when it was touched. Symlinks are skipped: following one could pull
in a file from outside the tree, and recording one would let a receiver be
talked into creating a link pointing anywhere.

Extraction treats the archive as hostile even after the signature, because a
signed archive may still have been built by a mistaken sender. Names are
re-validated per component, the declared entry count is bounded before it sizes
an allocation, a declared file size is checked against the remaining buffer
before it is used to slice, and files are created with `O_EXCL` so anything
already at the target cannot be followed or clobbered.

Subcommands use the standard library `flag` package rather than adding cobra.
The UX is equivalent and the dependency is not worth adding to a project whose
supply chain is audited on every build.

`send` writes frames to a directory and `recv` reads them back. The optical
layer is a later phase; this transport keeps the whole codec and crypto path
exercisable without hardware. The transfer record beside the frames carries
what a receiver needs and no secret; in the finished product it becomes the
signed manifest inside the frame stream.

### Verified by hand

```
$ dhow keygen -out operator.key
$ dhow send -key operator.key -in data -out frames
session   afa26da9574bb483c967336bc411071f
files     3
payload   5118 bytes
frames    35
$ dhow recv -key operator.key -in frames -out received
accepted  35 frames    rejected  0 frames    files 3
$ diff -r data received      # identical, executable bit preserved

$ rm frames/frame-00000[0-5].bin   # drop 6 frames
$ dhow recv ...                    # still identical
$ dhow recv -key wrong.key ...     # exit 4, 29 frames rejected, nothing written
$ dhow send -in /nonexistent       # exit 2
```

### Gate findings

`govulncheck` failed on GO-2026-4602, a `FileInfo` escape from a `Root` in
`os`. The finding is real rather than inherited: the new packing code reaches
it through `filepath.WalkDir`, and the gate started failing the moment that
code landed. Fixed by pinning the toolchain to go1.25.8.

`errcheck` flagged a deferred, discarded `Close` on the extraction write path.
That one mattered: on some filesystems a write error surfaces only at `Close`,
and reporting a file as extracted when its bytes never landed is exactly the
silent corruption this project exists to rule out. It is now checked and
propagated.

### Deviation

The test files were committed alongside their implementation rather than as
separate `test(cli)` commits, because the staging pattern used swept them in.
The tests are present and covered by the gate; only the commit decomposition
is coarser than intended.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===         PASS
=== GATE: cargo clippy -D warnings ===  PASS
=== GATE: cargo test ===                PASS
=== GATE: cargo audit ===               PASS
=== GATE: cargo deny ===                PASS
=== GATE: ABI drift ===                 PASS
=== GATE: build rust core for cgo ===   PASS
=== GATE: go vet ===                    PASS
=== GATE: go test -race ===             PASS
=== GATE: go build ===                  PASS
=== GATE: golangci-lint ===             PASS
=== GATE: govulncheck ===               PASS

=== GATE SUMMARY ===
  Passed: 12
  Failed: 0
ALL GATES PASSED
```


## Phase 19 - Go bindings

**Objective:** Wrap the C ABI in a Go-idiomatic package so the CLI has
something to call, with memory ownership rules documented and enforced, and
wire the Go half of the ABI drift gate now that bindings exist.

**Gates:** Go round trip equals the Rust round trip on shared inputs;
`go test -race` clean; no double free or use-after-free; the drift gate detects
a Go call to a symbol Rust does not export.

### Design notes

Go never sees a secret key. Operator keys stay opaque handles and the derived
session key never leaves Rust. This is deliberate rather than incidental: Go's
collector may copy a value while moving it, so a secret held in a Go slice
could persist in memory after the slice was overwritten.

Calls that can fail run with the OS thread locked. The last-error channel is
thread-local in Rust, so without the lock a goroutine could be rescheduled
between the failing call and the read and pick up another thread's message. A
concurrency test with eight simultaneous transfers covers this.

`Close` returns nothing rather than an `error`. Freeing a handle cannot fail;
an error return would imply a failure mode that does not exist and would force
every deferred call to discard a value. `errcheck` flagging the original
signature is what surfaced this.

`ErrIncomplete` and `ErrFrameRejected` are matchable with `errors.Is`, because
both are conditions a receiver acts on rather than aborts for.

### Drift gate, Go half

Verified it bites by pointing a binding at a symbol Rust does not export:

```
  DRIFT: dhow_abi_versionx is called from Go but not exported by Rust
ABI DRIFT DETECTED
```

### Gate additions

`gate.sh` now builds the Rust core before the Go gates, since the Go package
links the staticlib and a clean clone otherwise fails at the linker with an
error that says nothing about the cause. It also runs `go test -race`, which
the gate did not run at all: the Go side had no test execution in it despite
the engineering standard requiring the race detector on in all test runs.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===         PASS
=== GATE: cargo clippy -D warnings ===  PASS
=== GATE: cargo test ===                PASS
=== GATE: cargo audit ===               PASS
=== GATE: cargo deny ===                PASS
=== GATE: ABI drift ===                 PASS
=== GATE: build rust core for cgo ===   PASS
=== GATE: go vet ===                    PASS
=== GATE: go test -race ===             PASS
=== GATE: go build ===                  PASS
=== GATE: golangci-lint ===             PASS
=== GATE: govulncheck ===               PASS

=== GATE SUMMARY ===
  Passed: 12
  Failed: 0
ALL GATES PASSED
```

```
$ go test -race ./cli/internal/ffi/
ok  	dhow/cli/internal/ffi	2.789s   (18 tests)
```


## Phase 18 - C ABI and cbindgen

**Objective:** Give `dhow-ffi` the C surface the architecture depends on:
a handle-based encoder, decoder, and key API; a status-code and last-error
channel; `catch_unwind` at every entry point; a cbindgen-generated header; and
an ABI drift gate wired into `gate.sh`.

**Gates:** header generates deterministically; every function documented in the
header; no raw key bytes in any signature; a forced null or malformed input
surfaces as a status code rather than a crash; the drift gate fails on a
deliberate mismatch.

### Starting point

`dhow-ffi` was six lines: a doc comment and `#![allow(unsafe_code)]`. It had no
exported symbols, no header, and nothing for Go to call.

### Design notes

No function accepts or returns raw secret key material. Operator keys live
behind opaque handles, and the derived session key never leaves Rust:
`dhow_encoder_new` takes a key handle and a salt and derives internally.

Buffers are always caller-allocated, so this library never returns a pointer
the caller must free and no two allocators can disagree about a block.
Variable-length output uses one convention throughout: pass a null buffer to
learn the required size, then call again.

`dhow_encoder_params` reports the parameters the encoder actually used. The
caller describes the plaintext, but framing operates on ciphertext, which is
longer by the AEAD tag. Exposing the resolved values keeps the caller from
having to reimplement the length and digest rules to fill in the manifest.
This was added after the tests needed a fragile helper to recompute the digest,
which was a signal that the ABI was missing something a real sender needs.

The panic guard is a backstop, not a strategy. The core is written to be
panic-free on arbitrary input; a caught panic is a bug here. The panic payload
is not forwarded to the caller, because it can interpolate arbitrary values
including data-path bytes, and the error channel's contents must stay safe to
log.

### Drift gate

`scripts/check_abi.sh` regenerates the header into a temporary file and diffs
it against the committed one, then cross-checks symbol presence in both
directions between Rust and Go.

Verified it bites: renaming `dhow_encoder_frame_count` in the committed header
produced

```
  DRIFT: core/include/dhow.h is stale; run scripts/gen_header.sh
  DRIFT: dhow_encoder_frame_count is exported from Rust but absent from dhow.h
ABI DRIFT DETECTED
```

and the gate passed again once restored. The Go binding check reports that it
is skipped while `cli/internal/ffi` does not exist, rather than passing
silently.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===        PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===               PASS
=== GATE: cargo audit ===              PASS
=== GATE: cargo deny ===               PASS
=== GATE: ABI drift ===                PASS
=== GATE: go vet ===                   PASS
=== GATE: go build ===                 PASS
=== GATE: golangci-lint ===            PASS
=== GATE: govulncheck ===              PASS

=== GATE SUMMARY ===
  Passed: 10
  Failed: 0
ALL GATES PASSED
```

```
$ cargo test -p dhow-ffi
test result: ok. 20 passed; 0 failed; 0 ignored
```


## Phase 17 - Manifest signing and verification

**Objective:** Sign the manifest with Ed25519 and give the receiver a
verification pipeline: structure, signature, then policy. Until this phase the
manifest was transmitted unsigned, so the threat model's central claim - that a
receiver rejects a transfer whose manifest signature fails - had nothing
enforcing it.

**Gates:** signature verifies; any single-byte mutation of a signed manifest
fails; adversarial matrix (oversize claims, traversal names, wrong key,
downgraded version, replayed session) rejected with distinct errors.

### Defects fixed from earlier phases

Three defects in the Phase 10 manifest wire format, each fixed here:

1. **Signature scope.** The format signed bytes 0..100 only, leaving every file
   name, size, and digest unauthenticated. An attacker could rewrite an entry
   to a traversal path and the signature would still verify. The signature now
   covers the whole manifest with the signature field zeroed. Three tests
   rewrite a name, a size, and a digest in a signed manifest; all three would
   have passed under the old scope.
2. **Path traversal.** The check tested only whether a name *started* with
   `..`, so `a/../../etc/passwd` was accepted. Every component is now
   inspected. Backslash is rejected unconditionally, since the sender cannot
   know whether the receiver treats it as a separator.
3. **Unbounded allocation.** `Manifest::from_bytes` passed the declared `u32`
   file count straight to `Vec::with_capacity`, so a manifest claiming
   `u32::MAX` entries could exhaust memory before a single entry was read. The
   count is bounded and capacity is reserved against what the buffer could
   actually hold.

Defects 2 and 3 landed in the same commit as the traversal fix rather than
separately, because they touch adjacent code in one module.

### Design notes

The expected signer is supplied by the caller, never read from the manifest: a
key carried inside the structure it signs authenticates nothing.

Verification runs structure, then signature, then policy. Policy limits
describe what a legitimate sender may claim, so applying them to
unauthenticated bytes would report attacker-controlled values as meaningful.

`VerifiedManifest` is a distinct type, so extraction code cannot be handed
unauthenticated metadata by mistake.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===        PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===               PASS
=== GATE: cargo audit ===              PASS
=== GATE: cargo deny ===               PASS
=== GATE: go vet ===                   PASS
=== GATE: go build ===                 PASS
=== GATE: golangci-lint ===            PASS
=== GATE: govulncheck ===              PASS

=== GATE SUMMARY ===
  Passed: 9
  Failed: 0
ALL GATES PASSED
```

```
$ cargo test --all
test result: ok. 239 passed; 0 failed   (dhow-codec)
test result: ok. 103 passed; 0 failed   (dhow-crypt)
test result: ok.  11 passed; 0 failed   (end_to_end)
test result: ok.  12 passed; 0 failed   (doc-tests)
```


## Phase 16 - Payload AEAD

**Objective:** Encrypt the payload with XChaCha20-Poly1305 before chunking,
derive the payload key and the frame session key from the operator key with
HKDF-BLAKE3 under a per-transfer salt, and prove the crypt and codec layers
compose into a working transfer.

**Gates:** decrypt of tampered ciphertext fails; nonce and salt uniqueness
across transfers; end-to-end transfer round trips through dropped, reordered,
duplicated, and corrupted frames; replayed and foreign-key transfers fail
closed.

### Design notes

The operator key is never used to encrypt anything. Each transfer draws a
random 32-byte salt and derives two independent keys from it under separate
HKDF `info` strings, so disclosing the frame MAC key does not disclose the key
protecting the payload, and two transfers between the same operators share no
key material.

XChaCha20's 192-bit nonce is wide enough to draw at random per transfer, which
suits a courier whose two halves never communicate and so cannot agree a
counter. The session ID is authenticated as associated data, so a recording of
one session fails to decrypt if replayed into another.

Decryption failures are reported identically whether the key, nonce, session,
or ciphertext was wrong. Distinguishing them would tell an attacker probing
with modified captures which part to change next.

### Defect found by the new tests

The HKDF expand loop incremented its `u8` block counter after emitting the
final block, which overflowed on a full-length derivation. Caught by the
output-length limit test and fixed in this phase.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===      PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===             PASS
=== GATE: cargo audit ===            PASS
=== GATE: cargo deny ===             PASS
=== GATE: go vet ===                 PASS
=== GATE: go build ===               PASS
=== GATE: golangci-lint ===          PASS
=== GATE: govulncheck ===            PASS

=== GATE SUMMARY ===
  Passed: 9
  Failed: 0
ALL GATES PASSED
```

```
$ cargo test -p dhow-crypt
test result: ok. 79 passed; 0 failed   (unit)
test result: ok. 11 passed; 0 failed   (tests/end_to_end.rs)
```

## Phase 15 - Key generation and storage

**Objective:** Give `dhow-crypt` the key handling it had only declared errors
for: Ed25519 identity keypairs for manifest signing, a symmetric operator key
that per-transfer keys derive from, a versioned and checksummed key file
format, owner-only permission enforcement, and zeroization on drop.

**Gates:** key file round trips; permission test; every single-byte mutation of
a key file is rejected; secrets do not appear in `Debug` output.

### Notes

`VerifyingKey::from_bytes` does not reject every arbitrary 32-byte string. An
all-ones encoding decompresses to a valid curve point, so the negative test
uses encodings whose implied x-squared is not a quadratic residue.

Secret key files are created with mode 0600 through `OpenOptions::mode` rather
than chmodded after writing, so they are never briefly readable by other users.
Loading rejects any file carrying group or other permission bits.

### Gate output

```
$ cargo test -p dhow-crypt
running 42 tests
test result: ok. 42 passed; 0 failed; 0 ignored
```

```
$ cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s)
```

## Phase 14 - Session state machine and receive pipeline

**Objective:** Add the session state machine that tracks a transfer through
initialization, active transfer, FEC recovery, pause, completion, and failure;
and complete the frame pipeline with the receive half, so a payload encoded
into frames can be reassembled and verified rather than only produced.

**Gates:** state machine rejects every invalid transition and both terminal
states are absorbing; pipeline round-trips payloads through reordered,
duplicated, and dropped frames; every single-byte mutation of a valid frame is
rejected; reassembled payloads are verified against the session digest.

### Defects fixed from earlier phases

Phase 13 shipped a pipeline that could not be decoded by any receiver. Three
defects were found and fixed here, each as a `fix(codec)` commit:

1. Frame payloads carried `packet.data()`, discarding the 4-byte RaptorQ
   `PayloadId`. Without it a symbol cannot be placed within its block, so
   decoding was impossible. Frames now carry the serialized `EncodingPacket`.
2. `EncoderWrapper::repair_packets` returned source *and* repair symbols
   because `get_encoded_packets` includes the source prefix. The pipeline
   combined it with `source_packets`, emitting every source symbol twice under
   wrong symbol indices.
3. `FecParams::with_mtu` asserts on a symbol size below 64, and `symbol_size`
   was truncated from `u32` to `u16` at the call site, so some session
   parameters panicked on the data path. Symbol size is now range-checked into
   a typed error.

A fourth defect was found in the new receive path before it shipped:
`EncodingPacket::deserialize` indexes its first four bytes unchecked, so a
frame carrying a shorter payload would panic. The decoder rejects such frames
with a typed error, and a test covers payload lengths 0 through 4.

Phase 13's pipeline tests asserted only that `encode` returned `Ok` and a
non-empty vector, which is why the defects above survived the phase. They are
replaced with round-trip and adversarial tests.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===      PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===             PASS
=== GATE: cargo audit ===            PASS
=== GATE: cargo deny ===             PASS
=== GATE: go vet ===                 PASS
=== GATE: go build ===               PASS
=== GATE: golangci-lint ===          PASS
=== GATE: govulncheck ===            PASS

=== GATE SUMMARY ===
  Passed: 9
  Failed: 0
ALL GATES PASSED
```

```
$ cargo test --all
test result: ok. 236 passed; 0 failed (dhow-codec)
test result: ok. 8 passed; 0 failed (dhow-crypt)
test result: ok. 0 passed; 0 failed (dhow-ffi)
test result: ok. 12 passed; 0 failed (doc-tests)
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
7
```

This phase is below the 20-commit floor in section 5.2. Honest decomposition of
a state machine plus one pipeline module did not yield twenty self-contained
changes, and section 8 forbids padding to reach the floor. Recorded as a
deviation rather than met with filler commits.

### Known gaps entering Phase 15

An audit of the tree against the phase pack found that the following are
declared but not implemented, and are not covered by any phase log entry:

- `dhow-crypt` contains only error enums. No key generation, no AEAD, no
  signing, no manifest verification.
- `dhow-ffi` is an empty crate with no `extern "C"` surface and no header.
- `cli/cmd/dhow/main.go` is `func main() {}`. There is no command surface,
  no QR rendering, no camera capture.
- `manifest.rs` lives in `dhow-codec` and is unsigned; the signed manifest the
  threat model depends on does not exist yet.

## Phase 13 - Frame pipeline

**Objective:** Assemble frame pipeline that combines chunking, FEC encoding,
and frame header construction into a single pipeline.

**Gates:** encode produces frames with correct structure; multiple blocks work;
wrong payload size rejected; proptest on small data.

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib pipeline_test
running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
4
```

## Phase 12 - QR encode/decode

**Objective:** QR code encoding and terminal rendering. Encode frame bytes as QR
codes, render to terminal for inspection, support medium error correction.

**Gates:** QR encodes arbitrary binary data; terminal rendering produces
correct dimensions; proptest on small data ranges.

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib qr_test
running 12 tests
test result: ok. 12 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
21
```

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib session_test
running 13 tests
test result: ok. 13 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
14
```

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib manifest_test
running 18 tests
test result: ok. 18 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
16
```

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib manifest_test
running 20 tests
test result: ok. 20 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
16
```

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib resume_test
running 23 tests
test result: ok. 23 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
16
```

## Phase 8 - Frame wire format

**Objective:** Binary frame header and payload wire format per `proto/frame.md`.
Serialize/deserialize frame headers; compute truncated HMAC-BLAKE3 MAC and
CRC32C checksum; validate magic, version, and integrity.

**Gates:** round-trip identity (serialize -> deserialize recovers original);
MAC verification with correct and wrong key; CRC32C mismatch detection;
invalid magic and version rejection; proptest on arbitrary payloads.

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib frame_test
running 16 tests
test result: ok. 16 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
14
```

## Phase 7 - FEC (RaptorQ)

**Objective:** RaptorQ (RFC 6330) encoding and decoding wrappers for
fault-tolerant payload transmission. Generate source and repair symbols;
decode from any sufficient subset.

**Gates:** round-trip identity (encode -> decode recovers original);
decode from source packets only; decode from repair packets only;
known-answer test against RFC 6330 vectors.

### Planned atomic commits

1. `docs: add phase-log.md with Phase 7 objective`
2. `chore: add raptorq dependency`
3. `feat(codec): add raptorq module skeleton`
4. `feat(codec): add FecParams struct`
5. `feat(codec): add encode function`
6. `feat(codec): add repair packet generation`
7. `feat(codec): add decode function`
8. `feat(codec): add FecError error variant`
9. `test(codec): add encode-decode round-trip test`
10. `test(codec): add source-only decode test`
11. `test(codec): add repair-only decode test`
12. `test(codec): add known-answer test against RFC 6330`
13. `test(codec): add proptest for round-trip property`
14. `docs(codec): document raptorq module`
15. `chore: verify FEC gates pass`

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib fec_test
running 12 tests
test result: ok. 12 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

#### Round-trip property tests (proptest)

- `prop_fec_round_trip`: round-trip identity on arbitrary payloads (1 to 10,000 bytes)

#### Edge case tests

- Empty payloads (skip - raptorq panics on 0-length)
- Single byte payload
- 100K byte payload
- 30% simulated packet loss recovery
- Custom MTU (512)
- MTU below minimum (64) panics as expected

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
21
```

## Phase 6 - Integrity primitives

**Objective:** CRC32C and BLAKE3 wrappers with streaming interfaces; per-block
and whole-payload digests per spec.

**Gates:** known-answer tests against published vectors; streaming equals one-shot
on random inputs.

### Gate output

#### Rust tests

```
$ cargo test --all-targets
running 55 tests (dhow-codec)
test result: ok. 55 passed; 0 failed; 0 ignored

running 8 tests (dhow-crypt)
test result: ok. 8 passed; 0 failed; 0 ignored

running 0 tests (dhow-ffi)
test result: ok. 0 passed; 0 failed; 0 ignored
```

#### Clippy
```
$ cargo clippy -D warnings
    Finished `dev` profile [unoptimized + debuginfo]
```

#### Security audit
```
$ cargo audit
error: 0 vulnerabilities found
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
21
```

## Phase 5 - Chunker

**Objective:** Deterministic payload chunking into source blocks and symbols per
`proto/block.md`; property tests (arbitrary sizes 0 bytes to 4 GiB simulated,
boundary sizes, off-by-one edges); golden vectors generated by script.

**Gates:** round-trip identity on property tests; golden vectors match.

### Planned atomic commits

1. `docs: add phase-log.md with Phase 5 objective`
2. `feat(codec): add chunker module skeleton with constants`
3. `feat(codec): add SymbolIndexOutOfRange and Truncated error variants`
4. `feat(codec): add ChunkParams struct with validation`
5. `feat(codec): add BlockInfo and SymbolInfo structs`
6. `feat(codec): add ChunkMap struct`
7. `feat(codec): implement block boundaries computation`
8. `feat(codec): implement symbol boundaries computation`
9. `feat(codec): implement chunker constructor`
10. `feat(codec): implement block extraction`
11. `feat(codec): implement symbol extraction with padding`
12. `feat(codec): implement reassembly from blocks`
13. `test(codec): add chunker unit tests`
14. `test(codec): add boundary size tests`
15. `test(codec): add off-by-one tests`
16. `test(codec): add property tests with proptest`
17. `test(codec): add golden vector tests`
18. `docs(codec): document chunker module`
19. `chore: add proptest dev-dependency`
20. `chore: add chunker golden vectors to gen_vectors.py`
21. `chore: verify chunker gates pass`

### Gate output

#### Rust tests

```
$ cargo test --all-targets
running 34 tests (dhow-codec)
test result: ok. 34 passed; 0 failed; 0 ignored

running 8 tests (dhow-crypt)
test result: ok. 8 passed; 0 failed; 0 ignored
```

#### Property tests (proptest)

- `test_round_trip_identity`: round-trip identity on arbitrary payloads (0 to 100,000 bytes)
- `test_block_sizes_sum_to_payload`: block sizes always sum to payload size
- `test_block_offsets_continuous`: block offsets are continuous (no gaps)
- `test_symbol_count_correct`: symbol count matches ceil(block_size / symbol_size)
- `test_symbol_extraction_padded`: last symbol padding is correct

#### Golden vectors

- 7 chunker golden vectors generated by `scripts/gen_vectors.py`
- All vectors match the Rust implementation
- Vectors cover: simple, remainder, padding, exact multiple, single byte, empty, symbol size 1

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
22
```

## Phase 4 - Error taxonomy and logging spine

**Objective:** `dhow-codec` and `dhow-crypt` error enums; Go error wrapping
conventions; structured logger with data-path silence enforced by a test that
fails if payload bytes appear in log output.

**Gates:** log-silence test passes; error types documented.

### Planned atomic commits

1. `chore: add thiserror dependency to codec and crypt crates`
2. `feat(codec): add error enum with thiserror`
3. `feat(codec): add error context and display impls`
4. `test(codec): add error enum unit tests`
5. `docs(codec): document error types`
6. `feat(crypt): add error enum with thiserror`
7. `feat(crypt): add error context and display impls`
8. `docs(crypt): document error types`
9. `feat(cli): add structured logger with levels`
10. `feat(cli): add log configuration`
11. `feat(cli): add data-path silence enforcement`
12. `test(cli): add log silence test`
13. `feat(cli): add error wrapping conventions`
14. `docs(cli): document error wrapping conventions`
15. `test(cli): add error wrapping tests`
16. `docs: add phase-log.md with Phase 4 objective`
17. `chore: verify log silence test passes`
18. `chore: verify error types are documented`
19. `docs: record gate output in phase-log.md`
20. `chore: final cleanup`

### Gate output

#### Rust tests

```
$ cargo test --all-targets
running 8 tests (dhow-codec)
test result: ok. 8 passed; 0 failed; 0 ignored

running 8 tests (dhow-crypt)
test result: ok. 8 passed; 0 failed; 0 ignored
```

#### Go tests

```
$ go test ./internal/log/ ./internal/errors/ -v
--- PASS: TestLogSilenceOnDataPath
--- PASS: TestLogSilentMode
--- PASS: TestLogLevelFiltering
--- PASS: TestLogStructuredFields
--- PASS: TestLogNoPayloadBytes
--- PASS: TestUserError
--- PASS: TestUserErrorWithInner
--- PASS: TestUserErrorUnwrap
--- PASS: TestInternalError
--- PASS: TestInternalErrorWithInner
--- PASS: TestInternalErrorUnwrap
--- PASS: TestWrap
--- PASS: TestWrapNil
--- PASS: TestWrapUser
--- PASS: TestWrapInternal
--- PASS: TestErrorChain
--- PASS: TestNoPayloadInError
PASS
```

#### Log silence test

The log silence test (`TestLogSilenceOnDataPath`) verifies that:
- The logger never outputs payload bytes.
- The logger never outputs key material.
- The logger never outputs the word "payload" or "key" (except in session context).
- A silent logger produces no output.

#### Error type documentation

- `core/dhow-codec/ERRORS.md` documents all 4 error enums (CodecError, ChunkError, FrameError, SessionError, ResumeError).
- `core/dhow-crypt/ERRORS.md` documents all 5 error enums (CryptError, KeyError, AeadError, SigningError, ManifestError).
- `cli/internal/errors/CONVENTIONS.md` documents Go error wrapping conventions.

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
20
```
