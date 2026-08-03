# Migration Notes

> Version 2.0

This document describes how to migrate between versions of the Dhow wire format.

## v1.0 (initial release)

No migration needed. This is the first version of the wire format.

## v1.0 to v1.1 - resume file v2

The resume file gained a binding to the journal it indexes. A v1 resume file
records which symbols a receiver held but nothing about the frames it kept, so
a replay of those frames could not be checked against it.

| | v1 | v2 |
|---|---|---|
| Version byte | 0x01 | 0x02 |
| Fixed header | 96 bytes | 128 bytes |
| Offset 28 | 32 reserved bytes | 8-byte journal length, then 32-byte journal digest |
| Offset 60 | CRC32C | (moved to 92) |
| Offset 64 | Integrity digest | (moved to 96) |
| Offset 68 | - | 24 reserved bytes |

**There is no conversion.** A v1 file cannot be upgraded, because the journal
digest it would need was never computed and cannot be recovered from the
bitmaps. A v2 reader rejects a v1 file with an unsupported-version error.

**Operator impact is none in practice.** Resume state is local, disposable, and
meaningful only while a transfer is in flight. An operator holding a v1 file
deletes the state directory and restarts the receiver, which costs the frames
captured so far and nothing else. Nothing that crossed the optical channel is
affected: the frame, session, and manifest formats are unchanged.

## v1.1 to v2.0 - manifest v2

The manifest gained the session parameters it describes and a flag byte per
file entry.

| | v1 | v2 |
|---|---|---|
| Version byte | 0x01 | 0x02 |
| Fixed header | 168 bytes | 228 bytes |
| Offset 68 | 32 reserved bytes | 32-byte salt |
| Offset 100 | CRC32C | 24-byte nonce |
| Offset 104 | Signature | 8-byte payload size |
| Offset 132 | (file entries) | block count, symbol size, K, total symbols |
| Offset 148 | - | RaptorQ Z, N, PSI, then 2 reserved bytes |
| Offset 160 | - | CRC32C |
| Offset 164 | - | Signature |
| Offset 228 | - | File entries |
| File entry | 42 + name bytes | 43 + name bytes, trailing flag byte |
| Payload digest | digest of the file digests | BLAKE3 of the encrypted payload |

**There is no conversion.** A v1 manifest cannot be upgraded: the salt and
nonce it would need were never inside it, and its payload digest is a different
quantity computed over different bytes. A v2 receiver rejects a v1 manifest
with an unsupported-version error, and the reverse holds.

**Operator impact is real, unlike the v1.1 resume change.** The manifest
crosses the optical channel, so a v1 sender and a v2 receiver do not
interoperate. Both operators upgrade together, and a frame stream captured
before the upgrade cannot be received after it. Re-send the dataset.

**The CLI's `transfer.json` is gone.** It was never a `proto/` format - it was
the unsigned stand-in `send` wrote beside the frames while the manifest was
unreachable from the command line. A frames directory containing
`transfer.json` and no `manifest.bin` was produced by a pre-v2 build; re-run
`dhow send`.

## Future migrations

When the format version is bumped:

1. The sender writes the new version byte.
2. The receiver checks the version byte and rejects unknown versions.
3. Reserved fields allow backward-compatible extensions without a version bump.
4. Breaking changes require a new version and a migration path.

## Reserved field policy

Reserved fields are set to zero by the sender. What the receiver does with a
non-zero one depends on whether the structure is signed.

- **Signed structures** (the manifest): a non-zero reserved field is rejected.
  Ignoring unknown bits inside a signature means a future version's meaning can
  be silently discarded by an old receiver, which is the opposite of what the
  signature is for.
- **Unsigned framing** (frame header, session header, resume file): a non-zero
  reserved field is rejected as malformed, because these parsers treat every
  field as adversarial input and a value they cannot interpret is one they
  cannot act on safely.

In both cases a reserved field may be repurposed in a future version, and doing
so requires a version bump - a receiver that rejects non-zero reserved bytes
cannot be handed new ones under the old version number.
