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

960 rounds, none of which failed and none of which reported corruption.

That is not grounds for closing this. The original failure was seen once in
120 rounds with data the harness could not replay, so the population being
sampled now is not provably the same one. Absence here bounds how common it
is, not whether it exists.

What is known:

- `diff -r` does not compare permissions, so a lost executable bit would show
  exactly this signature. `verify` checks the bit; `diff` does not.
- A wrong recorded digest would also show it, and would be more serious: it
  would mean `pack.Create` sometimes records a digest that does not describe
  the bytes it packed, which would make `verify` unreliable in both directions.
- No round has ever reported silent corruption, so whatever this is, it did not
  produce a wrong dataset.

Next steps for whoever picks this up:

1. Soak hard with the seeded-data harness: `scripts/chaos.sh 2000`. The failure
   message now includes `verify`'s JSON, which names the file and the problem
   kind, and that alone distinguishes the two hypotheses above.
2. If it is `mode`, look at extraction permissions and umask handling in
   `cli/internal/pack`.
3. If it is `content`, treat it as a correctness bug in the streaming digest
   path (`dhow_hasher_*` and `pack.writeEntry`) and stop shipping until it is
   understood.

## Deferred

### B-2: the signed manifest is not wired to the CLI (Phase 25)

`dhow-crypt` implements manifest signing and verification, `Policy`, and
`VerifiedManifest`, and none of it is reachable from the command line. `send`
writes an unsigned `transfer.json` beside the frames, and `verify` checks
against that.

The consequence is stated in `docs/VERIFY.md`: verify answers "does this
dataset still match the record?" and not "was this produced by someone holding
the operator key?" Anyone who can edit the dataset can usually edit the record
beside it.

Closing this needs an FFI surface for identity handles and for manifest build
and verify, then replacing the transfer record with the signed manifest
carried in the frame stream.

### B-3: camera capture and QR detection do not exist

Frames move between the two halves through a directory. Everything above the
optical layer is exercised end to end without hardware, but the tool cannot yet
run across a real air gap. `README.md` and `docs/OPERATIONS.md` both say so.

### B-4: no fuzzing targets

`cargo-fuzz` targets for frame decode, manifest verify, and resume load are
specified and not built. Blocked on toolchain: `cargo-fuzz` requires nightly
Rust while `rust-toolchain.toml` pins stable. Resolve that first — either a
second pinned nightly for the fuzz job alone, or a fuzzing approach that runs
on stable.

### B-5: operator UX gaps

Recorded in `docs/UX-REVIEW.md`: no ETA or progress bar, `send` is silent while
packing a large dataset, no `--dry-run`, and no config file or environment
overrides.
