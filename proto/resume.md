# Resume File Format (v1)

> Version 1.0

The resume file allows the receiver to save and restore transfer progress.
It is stored on disk and must be integrity-protected.

## Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                           Magic (4)                           |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (1)   |   Reserved (3)                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                          Session ID (16)                      |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                        Block Count (4)                        |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                         Reserved (32)                         |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                          CRC32C (4)                           |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                       Integrity Digest (32)                   |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                       Block Entries (variable)                |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Field Definitions

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | Magic | bytes | ASCII `DHRS` (0x44485253) |
| 4 | 1 | Version | u8 | Format version, currently 0x01 |
| 5 | 3 | Reserved | bytes | Must be 0x000000 |
| 8 | 16 | Session ID | bytes | 128-bit session identifier |
| 24 | 4 | Block Count | u32 LE | Number of blocks in the transfer |
| 28 | 32 | Reserved | bytes | Must be zero |
| 60 | 4 | CRC32C | u32 LE | CRC32C of bytes 0..60 |
| 64 | 32 | Integrity Digest | bytes | BLAKE3 of bytes 0..64 |
| 96 | variable | Block Entries | bytes | See below |

## Total Fixed Header Size

96 bytes (before block entries).

## Block Entry Format

Each block entry is variable-length:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                         Block Index (4)                       |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                         Symbol Count (4)                      |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                         Symbols Held (4)                      |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                         Symbol Bitmap (variable)              |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Block Entry Fields

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | Block Index | u32 LE | Index of the block |
| 4 | 4 | Symbol Count | u32 LE | Total number of symbols in the block |
| 8 | 4 | Symbols Held | u32 LE | Number of symbols currently held |
| 12 | variable | Symbol Bitmap | bytes | Bitmap of held symbols (1 bit per symbol) |

## Integrity Digest

The integrity digest is the BLAKE3 hash of bytes 0..64 (magic through CRC32C).
This allows the receiver to detect tampering with the resume file.

If the integrity digest does not match, the resume file is rejected with a
typed error.

## Reserved Fields

The 3-byte reserved field at offset 5 and the 32-byte reserved field at offset
28 must be set to zero by the sender and ignored by the receiver.
