# Frame Header Format (v1)

> Version 1.0

Every QR frame rendered on the screen begins with a frame header, followed by
the frame payload. The header is fixed-size; the payload length is declared in
the header.

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
| Version (1)   |   Frame Type (1)  |       Reserved (2)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                          Session ID (16)                      |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                       Truncated MAC (8)                       |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                         Block Index (4)                       |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                         Symbol Index (4)                      |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                         Payload Length (2)                    |
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
|                        Payload (variable)                     |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Field Definitions

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | Magic | bytes | ASCII `DHOW` (0x44484F57) |
| 4 | 1 | Version | u8 | Format version, currently 0x01 |
| 5 | 1 | Frame Type | u8 | 0=Session, 1=Repair Symbol, 2=Manifest |
| 6 | 2 | Reserved | u16 | Must be 0x0000 |
| 8 | 16 | Session ID | bytes | 128-bit random session identifier |
| 24 | 8 | Truncated MAC | bytes | First 8 bytes of HMAC-BLAKE3(session_key, header_bytes) |
| 32 | 4 | Block Index | u32 LE | Index of the source block this frame belongs to |
| 36 | 4 | Symbol Index | u32 LE | Index of the symbol within the block |
| 40 | 2 | Payload Length | u16 LE | Length of the payload in bytes (max 65535) |
| 42 | 4 | CRC32C | u32 LE | CRC32C of the payload bytes |
| 46 | variable | Payload | bytes | Encoded symbol data |

## Total Header Size

Fixed header: 46 bytes.

## Frame Types

| Value | Name | Description |
|-------|------|-------------|
| 0 | Session | Contains the session header payload |
| 1 | Repair | Contains a repair symbol for RaptorQ decoding |
| 2 | Manifest | Contains the signed manifest payload |

## MAC Computation

The truncated MAC binds the frame to its session. It is computed as:

```
MAC = HMAC-BLAKE3(session_key, magic || version || frame_type || session_id || block_index || symbol_index || payload_length)
```

The first 8 bytes of the 32-byte HMAC output are used. The session key is
derived from the transfer key using HKDF-BLAKE3.

## Reserved Fields

The 2-byte reserved field at offset 6 must be set to 0x0000 by the sender
and ignored by the receiver. This allows future extensions without a version
bump.
