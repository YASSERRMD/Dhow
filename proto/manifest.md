# Manifest Format (v1)

> Version 1.0

The manifest is a signed metadata structure that describes the dataset being
transferred. It is carried in a frame of type 2 (Manifest) and is signed with
Ed25519.

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
|                        File Count (4)                         |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                        Total Size (8)                         |
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
|                                                               |
+                                                               +
|                       Signature (64)                          |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                       File Entries (variable)                 |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Field Definitions

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | Magic | bytes | ASCII `DHMF` (0x44484D46) |
| 4 | 1 | Version | u8 | Format version, currently 0x01 |
| 5 | 3 | Reserved | bytes | Must be 0x000000 |
| 8 | 16 | Session ID | bytes | 128-bit session identifier |
| 24 | 4 | File Count | u32 LE | Number of files in the dataset |
| 28 | 8 | Total Size | u64 LE | Total uncompressed size of all files |
| 36 | 32 | Payload Digest | bytes | BLAKE3 of the encrypted payload |
| 68 | 32 | Reserved | bytes | Must be zero |
| 100 | 4 | CRC32C | u32 LE | CRC32C of bytes 0..100 |
| 104 | 64 | Signature | bytes | Ed25519 signature of bytes 0..100 |
| 168 | variable | File Entries | bytes | See below |

## Total Fixed Header Size

168 bytes (before file entries).

## File Entry Format

Each file entry is variable-length:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                         Name Length (2)                       |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                          Name (variable)                      |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                          File Size (8)                        |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                       File Digest (32)                        |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### File Entry Fields

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 2 | Name Length | u16 LE | Length of the name field in bytes |
| 2 | variable | Name | bytes | UTF-8 file name, sanitized against path traversal |
| 2+Name Length | 8 | File Size | u64 LE | Uncompressed size of the file |
| 10+Name Length | 32 | File Digest | bytes | BLAKE3 of the uncompressed file content |

## Signature

The Ed25519 signature covers bytes 0..100 of the manifest (magic through CRC32C).
The signature is verified using the operator's Ed25519 public key.

## Path Traversal Protection

File names must be sanitized before inclusion in the manifest:

- No leading `/` or `..`
- No null bytes
- No backslash on non-Windows systems
- Maximum name length: 4096 bytes

## Reserved Fields

The 3-byte reserved field at offset 5 and the 32-byte reserved field at offset
68 must be set to zero by the sender and ignored by the receiver.
