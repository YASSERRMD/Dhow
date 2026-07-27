# Session Header Format (v1)

> Version 1.0

The session header is carried in a frame of type 0 (Session). It contains all
parameters needed by the receiver to decode the transfer, including RaptorQ
coding parameters and the payload digest.

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
|                       Payload Size (8)                        |
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
|                        Symbol Size (4)                        |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                   Source Symbols Per Block (4)                |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                    Total Symbols Per Block (4)                |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                          RaptorQ Z (4)                        |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                          RaptorQ N (4)                        |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                        RaptorQ PSI (2)                        |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                       Payload Digest (32)                     |
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
```

## Field Definitions

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | Magic | bytes | ASCII `DSES` (0x44534553) |
| 4 | 1 | Version | u8 | Format version, currently 0x01 |
| 5 | 3 | Reserved | bytes | Must be 0x000000 |
| 8 | 16 | Session ID | bytes | 128-bit random session identifier |
| 24 | 8 | Payload Size | u64 LE | Total size of the encrypted payload in bytes |
| 32 | 4 | Block Count | u32 LE | Number of source blocks |
| 36 | 4 | Symbol Size | u32 LE | Size of each symbol in bytes |
| 40 | 4 | Source Symbols Per Block | u32 LE | Number of source symbols per block (K) |
| 44 | 4 | Total Symbols Per Block | u32 LE | Total symbols per block (K + repair overhead) |
| 48 | 4 | RaptorQ Z | u32 LE | Number of blocks (RFC 6330) |
| 52 | 4 | RaptorQ N | u32 LE | Sub-block count (RFC 6330) |
| 56 | 2 | RaptorQ PSI | u16 LE | Pre-coded symbol count (RFC 6330) |
| 58 | 32 | Payload Digest | bytes | BLAKE3 digest of the encrypted payload |
| 90 | 32 | Reserved | bytes | Must be zero |
| 122 | 4 | CRC32C | u32 LE | CRC32C of bytes 0..122 (excluding this field) |

## Total Session Header Size

Fixed header: 126 bytes.

## RaptorQ Parameters

The RaptorQ parameters (Z, N, PSI, K) follow RFC 6330 semantics. The `raptorq`
crate is used for encoding and decoding; these parameters are passed directly
to it.

- **Z**: Number of source blocks
- **N**: Sub-block count per source block
- **PSI**: Number of pre-coded symbols
- **Source Symbols Per Block (K)**: Number of source symbols in each block

## Payload Digest

The payload digest is the BLAKE3 hash of the entire encrypted payload (before
chunking into symbols). This allows the receiver to verify the complete payload
after reassembly.

## Reserved Fields

The 3-byte reserved field at offset 5 and the 32-byte reserved field at offset
90 must be set to zero by the sender and ignored by the receiver.
