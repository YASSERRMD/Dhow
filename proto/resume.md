# Resume File Format (v2)

> Version 1.1

The resume file lets a receiver save and restore transfer progress. It is
local state, stored on disk, and it is integrity-protected.

## What it is an index over

RaptorQ's decoder state is opaque and cannot be serialized. A receiver
therefore preserves progress by keeping the frames it accepted in a *journal*
and replaying them into a fresh decoder on restart.

The resume file is the index over that journal. It records:

- which session the journal belongs to,
- how many of the journal's bytes are covered,
- the digest the replay must reproduce,
- which symbols each block should end up holding.

A replay that does not reproduce all of this is rejected. The journal itself is
not a trusted store: every frame in it is re-authenticated against the session
key on the way back in, exactly as it was on the way out.

`journal_bytes` exists because the journal is appended to continuously while
the index is rewritten periodically. A crash routinely leaves the journal
longer than the index that describes it. The bytes past `journal_bytes` are
discarded on load; they are progress that was not durably recorded, not
corruption.

## Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Magic (4)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (1)   |                 Reserved (3)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                         Session ID (16)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Block Count (4)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Journal Bytes (8)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      Journal Digest (32)                      +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Reserved (24)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          CRC32C (4)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Integrity Digest (32)                     +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Block Entries (variable)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Field Definitions

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | Magic | bytes | ASCII `DHRS` (0x44485253) |
| 4 | 1 | Version | u8 | Format version, currently 0x02 |
| 5 | 3 | Reserved | bytes | Must be 0x000000 |
| 8 | 16 | Session ID | bytes | 128-bit session identifier |
| 24 | 4 | Block Count | u32 LE | Number of blocks in the transfer |
| 28 | 8 | Journal Bytes | u64 LE | Length of the journal prefix covered |
| 36 | 32 | Journal Digest | bytes | BLAKE3 over the accepted frames, in order |
| 68 | 24 | Reserved | bytes | Must be zero |
| 92 | 4 | CRC32C | u32 LE | CRC32C of bytes 0..92 |
| 96 | 32 | Integrity Digest | bytes | BLAKE3 of bytes 0..96 |
| 128 | variable | Block Entries | bytes | See below |

## Total Fixed Header Size

128 bytes (before block entries).

## Journal Digest

The journal digest is a BLAKE3 hash over the bytes of every frame the decoder
accepted, concatenated in acceptance order. It is not taken over the journal
file, which carries a 4-byte little-endian length before each record; it is
taken over the frame bytes alone.

A receiver appends exactly the frames it accepted, in exactly that order, so
replaying the journal into a fresh decoder recomputes the same value. Any
reordering, insertion, truncation, or substitution changes it.

## Block Entry Format

Each block entry is variable-length:

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | Block Index | u32 LE | Index of the block |
| 4 | 4 | Symbol Count | u32 LE | Total symbols per block in this session |
| 8 | 4 | Symbols Held | u32 LE | Number of distinct symbols held |
| 12 | variable | Symbol Bitmap | bytes | `ceil(symbol_count / 8)` bytes |

The bitmap holds one bit per symbol, least-significant bit of byte 0 being
symbol 0.

Entries appear in block order with no gaps, and the file ends exactly at the
last entry.

## Validation Rules

A reader rejects a resume file when any of the following hold:

| Condition | Error |
|-----------|-------|
| Magic is not `DHRS` | invalid magic |
| Version is not 0x02 | unsupported version |
| Fewer than 128 bytes | truncated |
| Either reserved field is non-zero | reserved not zero |
| CRC32C over 0..92 does not match | integrity check failed |
| BLAKE3 over 0..96 does not match | integrity check failed |
| `symbols_held` exceeds `symbol_count` | invalid symbol count |
| `symbols_held` differs from the bitmap's set-bit count | held count mismatch |
| Bitmap has bits set at or beyond `symbol_count` | invalid symbol count |
| An entry's block index is not its position | block index out of range |
| Bytes remain after the last entry | trailing bytes |

Once loaded, the state is checked against the decoder that replayed the
journal: the session ID, block count, journal digest, and every per-block
bitmap must agree, or the state is rejected as describing a different journal.

## Integrity

- **CRC32C** covers bytes 0..92 and catches accidental corruption cheaply.
- **Integrity Digest** is BLAKE3 over bytes 0..96, which includes the CRC.

Neither is a signature. A resume file is local state, and anyone who can
rewrite it can recompute both. What the digests buy is that a *corrupted* file
is never silently believed. What stops a doctored journal is per-frame
authentication against the session key, which the resume file does not carry.

## Reserved Fields

The 3-byte reserved field at offset 5 and the 24-byte reserved field at offset
68 must be zero. A reader rejects a file that fills them: a writer that does is
either a version this reader cannot understand or is not a Dhow receiver.
