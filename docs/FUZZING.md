# Fuzzing

> Part of the [Contributing guide](../CONTRIBUTING.md).

Every parser in `dhow-codec` handles input an attacker chooses. Frames arrive
off a camera, a manifest arrives beside them, and a resume file is read from
storage the tool does not own. The unit tests cover the malformed inputs
somebody thought of. Fuzzing covers the ones nobody did.

## The toolchain decision

`cargo-fuzz` requires a nightly compiler: it builds targets with `-Z
sanitizer=address` and links `libfuzzer-sys`, and neither is available on
stable. `rust-toolchain.toml` pins stable 1.97.0 for the whole workspace, so
the two cannot both be satisfied by one toolchain file.

**The decision: a second pinned nightly, scoped to the fuzz crate alone.**

`fuzz/rust-toolchain.toml` pins `nightly-2025-12-14`. Nothing else in the
repository sees it: `rustup` resolves the toolchain from the nearest
`rust-toolchain.toml` walking up from the working directory, so `cargo build`
in `core/` still gets stable 1.97.0 and `scripts/gate.sh` is unaffected. The
fuzz crate is also excluded from the `core/` workspace, so a stable `cargo
test --all-targets` never tries to compile a libfuzzer target.

### What was rejected, and why

**A stable-only fuzzer.** `honggfuzz-rs` runs on stable and would have avoided
the second toolchain. It was rejected because it needs the honggfuzz binary
built from C sources at install time, which trades a Rust toolchain pin for a C
build dependency — a worse trade for a project whose entire non-Go surface is
Rust, and one that moves the fragility from a version number to a build that
either works on the machine or does not.

**A hand-rolled corpus replayer on stable.** Deterministic, no extra toolchain,
and not fuzzing: without coverage instrumentation, a mutation harness explores
the input space by luck. It would have satisfied the letter of B-4 and none of
its purpose.

**Floating `nightly` rather than a dated one.** A floating channel means a fuzz
run that passed yesterday can fail to compile today for reasons unrelated to
the code, which is the failure mode that teaches people to ignore a job. The
date is pinned and is bumped deliberately.

### The cost of the decision

The pinned nightly is 1.94.0-nightly, which is *older* than the pinned stable.
That is fine today — the core compiles on both — and it will not stay fine
forever. When the core starts using something the pinned nightly does not have,
the nightly moves forward, and that is a deliberate commit rather than a
surprise. `scripts/fuzz.sh` fails with a message naming the toolchain if it is
not installed, so the failure is a one-line fix rather than a puzzle.

## AddressSanitizer is off on macOS

`cargo-fuzz` enables AddressSanitizer by default. On macOS 26 (Darwin 25) the
ASan runtime shipped with the pinned nightly **hangs before executing a single
input**: it spins at 100% CPU inside `__asan::InitializeShadowMemory`, in
`get_dyld_hdr()`, and never leaves dyld initialisation. A ten-second run did not
terminate after eleven minutes; the process was sampled and the stack confirms
where it is stuck. This is an incompatibility between that sanitizer runtime and
this operating system, not a defect in this code.

`scripts/fuzz.sh` therefore selects `-s none` on Darwin and `-s address`
everywhere else. Override with `DHOW_FUZZ_SANITIZER=address` to try it anyway.

**What that costs, stated plainly.** Every target here exercises `dhow-codec`
and `dhow-crypt`, and both carry `#![forbid(unsafe_code)]`. The memory errors
ASan exists to catch cannot be written in them: an out-of-bounds index is a
panic, and libFuzzer catches a panic. ASan would earn its keep against
`dhow-ffi`, the one crate allowed `unsafe` — and no target here reaches it,
which is a real gap in the *targets*, not one this workaround introduced. It is
recorded in `docs/BACKLOG.md`.

Without the sanitizer the targets run at roughly a million executions per
second per target on this hardware, which is where the coverage comes from.

## Running it

Install the tooling once:

```bash
rustup toolchain install nightly-2025-12-14 --profile minimal
cargo install cargo-fuzz --locked
```

Then, from the repository root:

```bash
scripts/fuzz.sh                 # every target, 60s each
scripts/fuzz.sh 300             # every target, 300s each
scripts/fuzz.sh 300 frame_decode   # one target
```

The script seeds each target's corpus from `proto/vectors.json` before it runs,
so a fresh clone starts from valid structures rather than from noise. A parser
reached only through a correct 46-byte header and a correct CRC is a parser a
fuzzer starting from random bytes will not reach this side of a heat death.

## The targets

| Target | What it parses | Why it is hostile input |
|--------|----------------|-------------------------|
| `frame_decode` | `FrameHeader::from_bytes`, and `Frame::from_bytes` both unaltered and with the MAC and CRC repaired | Every frame comes off a camera pointed at a screen anyone can stand in front of. |
| `session_header` | `SessionHeader::from_bytes` | Unsigned framing that configures the decoder before anything is verified. |
| `manifest_entry` | `FileEntry::from_bytes` | The path-traversal surface, reached with an attacker-chosen length prefix. |
| `manifest_verify` | `Manifest::from_bytes`, then signature verification and policy | The receiver's first sight of a transfer; it decides what is extracted, and now also the salt, nonce, and coding parameters. |
| `resume_load` | `ResumeFile::from_bytes` | Read from local storage, which a compromised receiver controls. |

### Why `frame_decode` repairs the MAC

A fuzzer will not produce eight bytes of keyed MAC by mutation. Left alone,
every input dies at the first check and the code that reads a declared length
and slices a payload out of a buffer is never reached — which is the code worth
fuzzing. The target therefore parses the input twice: once unaltered, which is
the rejection path a real attacker without the key gets, and once with the MAC
and CRC recomputed so the frame authenticates.

Repairing a checksum to get past a gate is standard practice and it is sound
here: the repaired fields are exactly the ones a sender computes, and everything
the fuzzer still controls — the indices, the declared length, the payload, the
version and type bytes — is what a *legitimate but malicious* sender controls.
That is the threat model on this side of the MAC. Adding the repair took the
target from 79 to 95 covered edges.

Each target asserts the invariants the parser promises, not merely that it did
not crash:

- **No panic** on any input. A panic in the core is a bug; a panic across the
  FFI boundary is undefined behaviour and a release blocker.
- **No unbounded allocation.** A declared count or length may never drive an
  allocation before it has been checked against what the buffer could hold.
- **Round-trip fidelity.** Anything that parses successfully must re-serialize
  to the bytes it was parsed from. A parser that accepts input it cannot
  reproduce is one that is discarding something.
- **Verification means verification.** `manifest_verify` asserts that any input
  it accepts really does carry a signature over its own bytes.

## When a target finds something

`cargo-fuzz` writes the input to `fuzz/artifacts/<target>/`. Reproduce it with:

```bash
cargo +nightly-2025-12-14 fuzz run --fuzz-dir fuzz -s none <target> \
    fuzz/artifacts/<target>/<file>
```

`-s none` on macOS, `-s address` elsewhere — the same choice `scripts/fuzz.sh`
makes, and it prints the whole line for you when a target fails.

Then: copy the input to `fuzz/regressions/<target>/`, fix the parser, and commit
both in the same change. A crash found by fuzzing and fixed without a regression
input is a crash that will come back.

`fuzz/regressions/` is committed, unlike `fuzz/corpus/`. It is replayed two
ways:

- `scripts/fuzz.sh` copies it into the corpus before every run, because an input
  that once broke a parser is the most interesting starting point there is.
- `dhow-codec`'s `replay_test` walks it on **stable**, in the default `cargo
  test`, asserting the same invariants the fuzz targets assert.

The second is the one that matters. The fuzz gate skips on a machine without
nightly, and that is right for a search and wrong for a regression: an input
that once crashed a parser must be checked by everyone, on every run, with the
toolchain everyone has. The duplication between `replay_test` and the fuzz
targets is deliberate — the fuzz crate cannot be a dependency of `dhow-codec`,
and a regression check that only runs where the fuzzer runs is a regression
check that was not needed.

`replay_test` fails if a regression directory is empty or missing, rather than
iterating over nothing and reporting success.

## What the gate runs, and what it does not

`scripts/gate.sh` runs a short bounded pass — seconds per target, not minutes —
because a gate that takes an hour is a gate people skip. Its job is to prove
the targets still build and still run, not to search.

Searching is `scripts/fuzz.sh 3600` on a machine with time to spare. The
cumulative hours actually run are recorded in `docs/phase-log.md`, honestly,
including when they fall short of what the phase pack asked for.
