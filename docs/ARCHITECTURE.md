# Architecture

How the pieces fit, and why the seams are where they are.

## The shape of it

```
                          SENDER                                RECEIVER
                          ------                                --------

  directory  ──▶  pack.Create ─────────┐                   ┌──▶ pack.Extract ──▶ directory
                  (Go)                 │                   │    (Go)
                                       ▼                   │
                              ┌─────────────────┐   ┌──────────────┐
                              │ encrypt (AEAD)  │   │ decrypt      │
                              │ dhow-crypt      │   │ dhow-crypt   │
                              └────────┬────────┘   └──────▲───────┘
                                       │                   │
                              ┌────────▼────────┐   ┌──────┴───────┐
                              │ chunk + RaptorQ │   │ RaptorQ      │
                              │ dhow-codec      │   │ dhow-codec   │
                              └────────┬────────┘   └──────▲───────┘
                                       │                   │
                              ┌────────▼────────┐   ┌──────┴───────┐
                              │ frame + MAC+CRC │   │ parse + auth │
                              │ dhow-codec      │   │ dhow-codec   │
                              └────────┬────────┘   └──────▲───────┘
                                       │                   │
                          ═════════════▼═══════════════════╧═════════════
                                    the C ABI (dhow-ffi)
                          ═════════════▼═══════════════════╧═════════════
                                       │                   │
                              ┌────────▼────────┐   ┌──────┴───────┐
                              │ render to QR    │   │ detect QR    │
                              │ Go              │   │ NOT BUILT    │
                              └────────┬────────┘   └──────▲───────┘
                                       │                   │
                                    screen ─ ─ ─ ─ ─ ─ ▶ camera
                                       (the air gap)
```

Everything above the double line is Rust and is where correctness lives.
Everything below is Go and is where the machine's peripherals live. The camera
half of the bottom row does not exist yet; frames move between the two halves
through a directory, which exercises every layer above the optical one without
hardware. See [B-3](BACKLOG.md).

## Why the seam is there

**Rust owns everything whose failure would be silent.** Chunking, fountain
coding, the frame wire format, integrity, AEAD, signing, manifest build and
verify, resume-state serialization. `dhow-codec` and `dhow-crypt` both carry
`#![forbid(unsafe_code)]`, which is a compile error rather than a lint, and
[`cargo geiger` confirms zero unsafe expressions in either](THREAT-MODEL.md#cargo-geiger).

**Go owns everything whose failure is visible immediately.** The CLI, flags,
progress output, terminal rendering, file system walking, and eventually camera
capture. A bug here produces a wrong message or a missing file; a bug above the
line produces a dataset that is quietly not the one that was sent.

**Go never holds key material.** Keys cross the boundary as opaque handles and
the derived session key never leaves Rust at all. That is not fastidiousness:
Go's garbage collector may copy a value while moving it, so a secret in a Go
slice can survive in memory after the slice is overwritten.

## The crates

| Crate | Owns | Unsafe |
|-------|------|--------|
| `dhow-codec` | Chunking, RaptorQ, frame and session and manifest and resume wire formats, CRC32C, BLAKE3, QR encoding | forbidden |
| `dhow-crypt` | XChaCha20-Poly1305, HKDF-BLAKE3, Ed25519, key files, manifest signing and policy | forbidden |
| `dhow-ffi` | The C ABI over both | permitted, at the boundary only |

`dhow-crypt` depends on `dhow-codec` (it signs the codec's manifest type);
nothing depends on `dhow-ffi` except Go.

## The Go packages

| Package | Owns |
|---------|------|
| `internal/cli` | Subcommands, flags, exit codes, the operator-facing text |
| `internal/ffi` | The cgo bindings and the handle types |
| `internal/pack` | Directory to deterministic archive, and traversal-safe extraction |
| `internal/render` | QR modules to a PNG or a terminal |
| `internal/display` | The frame loop, pacing, and the calibration preamble |
| `internal/resume` | The on-disk journal and its index |
| `internal/log` | A structured logger that is silent on the data path |
| `internal/errors` | Error wrapping conventions |

## A transfer, end to end

What `dhow send` does, in order, and where each step lives:

1. **Walk and pack** (`internal/pack`). Sorted entries, no timestamps, no uid or
   gid; the only mode bit kept is the owner execute bit. Each file is hashed by
   the same read that writes it into the archive, so the digest describes the
   bytes that were actually packed.
2. **Derive** (`dhow-crypt`). A payload key and a session key from the operator
   key and a fresh 32-byte salt, by HKDF-BLAKE3 with distinct info strings.
3. **Encrypt** (`dhow-crypt`). XChaCha20-Poly1305 over the whole archive, with
   the session id as associated data, so a ciphertext replayed into another
   session does not decrypt.
4. **Chunk and encode** (`dhow-codec`). The ciphertext is split into blocks and
   each block into symbols; RaptorQ produces source and repair symbols.
5. **Frame** (`dhow-codec`). Each symbol gets a 46-byte header carrying the
   session id, a truncated MAC over the header under the session key, and a
   CRC32C over the payload.
6. **Sign** (`dhow-crypt`). A manifest naming every file with its size, digest,
   and executable bit, plus the salt, nonce, payload digest, and coding
   parameters, signed with the sender's Ed25519 identity.

`dhow recv` runs it backwards, with one difference that matters: **it verifies
the manifest before it reads anything else out of the transfer.** The session id,
salt, nonce, and every coding parameter come from the manifest, so an unverified
one configures the whole decode.

## The three integrity layers, and what each is for

| Layer | Covers | Catches | Cost to forge |
|-------|--------|---------|---------------|
| CRC32C | one frame's payload | corruption | none — recompute it |
| Truncated MAC | one frame's header | frames from another session or key | the operator key |
| BLAKE3 + Ed25519 | the whole payload and inventory | anything else | the sender's identity key |

They are not redundant. The CRC is a fast reject on a channel that is mostly
noise; running the MAC on every captured smudge would waste the receiver's time.
The MAC keeps a foreign session's frames out of this decoder before they reach
RaptorQ. The signature is the only one that answers *who*.

## The two keys

| | `operator.key` | `sender.key` |
|---|---|---|
| Kind | 32-byte symmetric | Ed25519 |
| Held by | **both** operators | the sender only |
| Does | encrypts, authenticates frames | signs the manifest |
| Answers | "was this made by someone in the group" | "which one" |

The operator key cannot answer the second question, because both sides hold it —
either could have produced any transfer made with it. That is the whole reason
the identity exists. See the [key ceremony](OPERATIONS.md#key-ceremony).

## The FFI boundary

Handle-based, C ABI, generated header. Three rules, each with a reason:

1. **Handles are opaque.** The header declares incomplete struct types, so no
   caller can depend on a layout.
2. **Buffers are caller-allocated.** The library never returns a pointer the
   caller must free, which removes the class of bug where two allocators
   disagree. Variable-length output uses one convention throughout: call with a
   null buffer to learn the size, then call again.
3. **No raw key material in any signature.** Keys are handles; the only way to
   get one is to generate it or load a key file.

Every entry point runs inside a panic guard, because unwinding across the ABI is
undefined behaviour. See [FFI.md](FFI.md) to bind it from another language, and
[the drift gate](../scripts/check_abi.sh) for how the three views of the ABI are
kept in step.

## What runs when

| Check | Where | Catches |
|-------|-------|---------|
| Unit and property tests | `cargo test`, `go test` | logic |
| [Fuzzing](FUZZING.md) | `scripts/fuzz.sh`, CI | parser defects nobody thought of |
| [Differential](../cli/internal/ffi/differential_test.go) | `go test` | the ABI boundary |
| [Chaos soak](../scripts/chaos.sh) | gate, CI | silent corruption under random faults |
| [Loopback](../scripts/loopback.sh) | gate, CI | the whole stack, with loss |
| [Drill](../scripts/drill.sh) | gate, CI | the operations guide drifting from the tool |
| [CLI conformance](../scripts/conformance_cli.py) | gate, CI | the implementation drifting from `proto/` |
| [RSS budget](BENCHMARKS.md) | gate | memory regressions |
| [Reproducible build](RELEASE.md) | gate, CI | a release nobody can audit |

## What is not built

- **Camera capture and QR detection.** Everything above the optical layer is
  exercised end to end without hardware, but the tool cannot yet run across a
  real air gap. [B-3](BACKLOG.md).
- **Streaming encode and decode.** Both halves hold the whole payload in memory;
  measured at 10.4x the dataset to send and 6.4x to receive.
  [B-6, B-8](BACKLOG.md), and [the numbers](BENCHMARKS.md).
- **A fuzz target that reaches `dhow-ffi`**, the one crate where `unsafe` lives.
  [B-7](BACKLOG.md).
