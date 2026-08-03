# Migration Notes

> Version 1.1

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

## Future migrations

When the format version is bumped:

1. The sender writes the new version byte.
2. The receiver checks the version byte and rejects unknown versions.
3. Reserved fields allow backward-compatible extensions without a version bump.
4. Breaking changes require a new version and a migration path.

## Reserved field policy

Reserved fields are set to zero by the sender and ignored by the receiver.
They may be repurposed in future versions without a version bump, as long as
the total size of the structure remains the same.
