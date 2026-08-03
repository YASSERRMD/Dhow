# Backlog

Known issues and deferred work, each with enough detail to act on without the
conversation that produced it. An item is removed when it is fixed, not when it
stops being convenient.

## Open

### B-1: one unreproduced chaos failure (Phase 27)

**Severity: unknown, treat as high until reproduced.**

The first 120-round soak of `scripts/chaos.sh` reported:

```
FAIL  round 120: recv succeeded but verify rejected the dataset
      (symbol=1320 blocks=7 overhead=50 loss=5%/contiguous dropped=8/161
       corrupt=0 resumed=no)
```

The harness runs `diff -r` before `verify`, and the `diff` passed. So the
extracted dataset was byte-for-byte identical to the input, and `dhow verify`
rejected it anyway. That points at the transfer record's inventory rather than
at the transfer: either a recorded digest, size, or executable bit did not
describe the file that was packed.

**It has not been reproduced.** Re-running the same seed passed, because at
that point the harness drew dataset bytes from `/dev/urandom` and only the
round *parameters* from the seed. That gap is fixed — content is now derived
from the seed — but the fix cannot recover the data that triggered the
original failure.

**Soak evidence so far, all with the seeded-data harness:**

| Run | Rounds | Completed | Closed | Corrupted | Reproduced B-1 |
|-----|-------:|----------:|-------:|----------:|----------------|
| seeds 7919, 15838, 23757, 31676 | 4 x 60 | 132 | 108 | 0 | no |
| seeds 101, 202, 303, 404 | 4 x 150 | 381 | 219 | 0 | no |
| seeds 1000003, 2718281, 31415926, 57721566 (Phase 28) | 4 x 500 | 1321 | 679 | 0 | no |

**2,960 rounds**, none of which failed and none of which reported corruption.

That is still not grounds for closing this. The original failure was seen once
in 120 rounds with data the harness could not replay, so the population being
sampled now is not provably the same one. Absence here bounds how common it is,
not whether it exists.

What is known:

- `diff -r` does not compare permissions, so a lost executable bit would show
  exactly this signature. `verify` checks the bit; `diff` does not.
- A wrong recorded digest would also show it, and would be more serious: it
  would mean `pack.Create` sometimes records a digest that does not describe
  the bytes it packed, which would make `verify` unreliable in both directions.
- No round has ever reported silent corruption, so whatever this is, it did not
  produce a wrong dataset.

**Ruled out in Phase 28: umask.** `pack.writeFile` passes the mode to
`os.OpenFile`, where the process umask applies, so a umask containing `0100`
would strip the executable bit and produce the observed signature. A transfer
of an executable file was run under umasks 0022, 0002, 0077, and 0027, and the
bit survived every one; 0111 and 0177 could not be tested because they stop the
harness creating its own fixture, and no shell runs with them. The harness runs
under 0022. This does not rule out a `mode` cause, only this mechanism for one.

Next steps for whoever picks this up:

1. Keep soaking with fresh seeds: `scripts/chaos.sh 500`. The failure message
   includes `verify`'s JSON, which names the file and the problem kind, and
   that alone distinguishes the two hypotheses above.
2. If it is `mode`, look at extraction permissions in `cli/internal/pack`
   beyond umask - the `O_EXCL` open, and `os.MkdirAll`'s directory modes.
3. If it is `content`, treat it as a correctness bug in the streaming digest
   path (`dhow_hasher_*` and `pack.writeEntry`) and stop shipping until it is
   understood.

Note that Phase 28 moved the inventory into the signed manifest. That changes
nothing about this defect: the digests are still produced by `pack.writeEntry`
from the same stream, and the executable bit still comes from the same
`d.Info()` call. If the cause is in either, it survived the change.

## Deferred

### B-3: camera capture and QR detection do not exist

Frames move between the two halves through a directory. Everything above the
optical layer is exercised end to end without hardware, but the tool cannot yet
run across a real air gap. `README.md` and `docs/OPERATIONS.md` both say so.

### B-7: no fuzz target reaches `dhow-ffi` (Phase 29)

Phase 29 built five targets, all of which exercise `dhow-codec` and
`dhow-crypt`. Both carry `#![forbid(unsafe_code)]`, so the memory errors a
sanitizer exists to catch cannot be written in them.

`dhow-ffi` is the one crate where `unsafe` is permitted, it is where every
caller pointer is dereferenced and every caller buffer is written, and nothing
fuzzes it. Its unit tests cover null handles, out-of-range indices, and the
two-call size convention, which is the set somebody thought of.

What this needs is a target that drives the handle lifecycle with a fuzzer
choosing the sequence — create, feed, poll, finish, free, in arbitrary order,
with buffers deliberately one byte short — rather than one that feeds bytes to
a parser. That is closer to Phase 34's structured decoder fuzzing than to
Phase 29's parser targets, which is why it was not folded into this phase.

Note that AddressSanitizer is disabled on macOS (`docs/FUZZING.md` explains
why), so an FFI target written today would run without a sanitizer on a
developer machine and with one in CI. That asymmetry matters more for `dhow-ffi`
than for anything fuzzed so far.

### B-5: operator UX gaps

Recorded in `docs/UX-REVIEW.md`: no ETA or progress bar, `send` is silent while
packing a large dataset, no `--dry-run`, and no config file or environment
overrides.

### B-6: `send` holds the whole payload in memory (Phase 28, measured Phase 31)

`runSend` packs the dataset into a `strings.Builder` and hands the result to
the encoder as one `[]byte`, so peak memory is at least the size of the
archive. `pack.Create` streams and the CLI immediately un-streams it.

**Measured in Phase 31: `dhow send` peaks at 10.4x the dataset size** (16 MiB
dataset, 166.9 MiB resident; 9.1x at 64 MiB as the fixed overhead amortises).
For a 1 GiB dataset that is roughly **9 GiB resident**. The components are
listed in `docs/BENCHMARKS.md`: the archive, the copy out of the builder, the
ciphertext, and every frame held at once.

`scripts/rss.sh` enforces a 12x budget in the gate, which is a regression check
and not an endorsement of the number.

Fixing it means an encoder that takes a reader rather than a slice. That is an
FFI change - a new streaming handle with feed and poll, replacing the
`payload`/`payload_len` pair in `dhow_encoder_new` - and a phase of its own.

### B-8: `recv` holds the whole payload in memory (Phase 31)

The same shape as B-6, one copy shallower. The decoder holds the symbols,
reassembles the ciphertext, decrypts to a plaintext, and `dhow_decoder_finish`
copies that into a Go buffer that `pack.Extract` then slices.

**Measured: `dhow recv` peaks at 6.4x the dataset size** (16 MiB dataset, 102.2
MiB resident; 5.9x at 64 MiB). For a 1 GiB dataset that is roughly **6 GiB
resident**, on the machine least likely to have it - the receiver is
deliberately off every network and is rarely the newest one in the building.

Fixing it needs both a streaming `finish` across the ABI and a `pack.Extract`
that reads from a reader rather than a slice. The second is the easier half and
does not need an ABI change.

`scripts/rss.sh` enforces an 8x budget.

## Closed

### B-4: no fuzzing targets (Phase 2, closed Phase 29)

`cargo-fuzz` targets were specified in Phase 2 and not built, blocked on a
toolchain question with three plausible answers and no recorded decision.

Closed by Phase 29: the decision is a second nightly pinned to a date and
scoped to `fuzz/` alone, recorded in `docs/FUZZING.md` along with what was
rejected and why. Five targets - `frame_decode`, `session_header`,
`manifest_entry`, `manifest_verify`, `resume_load` - each asserting the
invariants its parser promises rather than only that it did not crash. Corpora
are derived from `proto/vectors.json` by `scripts/seed_corpus.py`, so a
wire-format change regenerates them, and the minimized corpus is committed under
`fuzz/seeds/` and replayed on stable by `dhow-codec`'s `replay_test`. A bounded pass runs in the gate and in CI.

The targets were shown to bite: `validate_name` was removed from
`FileEntry::from_bytes` on a scratch working tree, and `manifest_entry` found a
name containing a backslash and failed within thirty seconds.

See B-7 for what the targets still do not reach.

### B-2: the signed manifest is not wired to the CLI (Phase 25, closed Phase 28)

`dhow-crypt` implemented manifest signing and verification, `Policy`, and
`VerifiedManifest`, and none of it was reachable from the command line. `send`
wrote an unsigned `transfer.json` beside the frames and `verify` checked
against that, so anyone who could edit the dataset could edit the record beside
it.

Closed by Phase 28: an FFI surface for identity handles and for manifest build
and verify, manifest wire format v2 carrying the salt, nonce, coding
parameters, and per-file executable bits, and `keygen -kind identity`, `send
-identity`, and `recv`/`verify`/`display -signer`. `transfer.json` is deleted,
not deprecated.
