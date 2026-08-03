# Manifest Format (v2)

> Version 2.0

The manifest is a signed metadata structure that describes the dataset being
transferred and the session that carries it. It is signed with Ed25519 and is
the only thing in a transfer that binds the dataset to an identity.

## What changed in v2

Version 1 described the dataset and nothing else. Everything a receiver needed
in order to *decode* - the salt, the nonce, and the coding parameters - lived
outside the manifest, so it was unauthenticated. A manifest that authenticates
the file inventory while the parameters that produce those files travel beside
it unsigned protects less than it appears to.

v2 folds those fields into the signed structure and adds a per-entry flag byte
so the inventory carries the executable bit. See `proto/migration.md`.

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
+                        Session ID (16)                        +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       File Count (4)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Total Size (8)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      Payload Digest (32)                      +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                           Salt (32)                           +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                          Nonce (24)                           +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload Size (8)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Block Count (4)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Symbol Size (4)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              Source Symbols Per Block (4)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Total Symbols Per Block (4)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       RaptorQ Z (4)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       RaptorQ N (4)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   RaptorQ PSI (2)             |         Reserved (2)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         CRC32C (4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Signature (64)                          +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  File Entries (variable)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Field Definitions

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | Magic | bytes | ASCII `DHMF` (0x44484D46) |
| 4 | 1 | Version | u8 | Format version, currently 0x02 |
| 5 | 3 | Reserved | bytes | Must be 0x000000 |
| 8 | 16 | Session ID | bytes | 128-bit session identifier |
| 24 | 4 | File Count | u32 LE | Number of files in the dataset |
| 28 | 8 | Total Size | u64 LE | Sum of the entries' file sizes |
| 36 | 32 | Payload Digest | bytes | BLAKE3 of the encrypted payload |
| 68 | 32 | Salt | bytes | Per-transfer HKDF salt |
| 100 | 24 | Nonce | bytes | XChaCha20-Poly1305 nonce |
| 124 | 8 | Payload Size | u64 LE | Length of the encrypted payload |
| 132 | 4 | Block Count | u32 LE | Number of source blocks |
| 136 | 4 | Symbol Size | u32 LE | Bytes per symbol |
| 140 | 4 | Source Symbols Per Block | u32 LE | K |
| 144 | 4 | Total Symbols Per Block | u32 LE | K plus repair overhead |
| 148 | 4 | RaptorQ Z | u32 LE | Source block count |
| 152 | 4 | RaptorQ N | u32 LE | Sub-blocks per source block |
| 156 | 2 | RaptorQ PSI | u16 LE | Pre-coded symbol count |
| 158 | 2 | Reserved | bytes | Must be 0x0000 |
| 160 | 4 | CRC32C | u32 LE | CRC32C of bytes 0..160 |
| 164 | 64 | Signature | bytes | Ed25519 over the whole manifest with this field zeroed |
| 228 | variable | File Entries | bytes | See below |

## Total Fixed Header Size

228 bytes (before file entries).

## Session Fields

The session fields at offsets 68..160 duplicate what the session header
(`proto/session.md`) carries. That is deliberate, and the duplication is
checked rather than assumed: a receiver that holds both must reject the
transfer if they disagree.

The reason both exist is that they answer different questions. The session
header is unsigned framing that lets a decoder start work; the manifest is the
authenticated statement of what the sender intended. A parameter that only ever
appeared in the unsigned copy could be changed by anyone between the two
machines, and the receiver would decode a different transfer than the one that
was signed.

Salt and nonce are public by design - neither reveals anything about the
operator key or the payload - but public is not the same as unauthenticated.
Under v1 a substituted nonce produced a decryption failure, which fails closed
but reports the wrong cause. Under v2 it fails at the signature, where it
belongs.

## File Entry Format

Each file entry is variable-length:

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 2 | Name Length | u16 LE | Length of the name field in bytes |
| 2 | variable | Name | bytes | UTF-8 file name, sanitized against path traversal |
| 2+Name Length | 8 | File Size | u64 LE | Uncompressed size of the file |
| 10+Name Length | 32 | File Digest | bytes | BLAKE3 of the uncompressed file content |
| 42+Name Length | 1 | Flags | u8 | Bit 0: owner execute bit. Bits 1..7 reserved, must be zero |

Total entry size: 43 + Name Length bytes.

### Flags

Bit 0 records whether the file was executable on the sender. It is the only
mode bit carried: every other permission bit varies by machine and by umask and
would break the requirement that the same dataset produces the same manifest.
Whether a file is executable changes what the file *is*, so it travels.

A receiver must reject an entry whose flag byte has any bit above bit 0 set,
rather than masking it off. Ignoring unknown bits in a signed structure means a
future version's semantics can be silently discarded by an old receiver.

## Signature

The Ed25519 signature covers **the entire manifest, file entries included**,
with the 64 bytes of the signature field itself set to zero.

Signer and verifier both construct the signing input the same way: serialize
the complete manifest, then zero bytes 164..228. Zeroing the field rather than
excluding its range keeps the offset of every subsequent byte unchanged, so
neither side has to splice ranges together.

The signature is verified using the sender's Ed25519 public key, which the
receiving operator holds out of band. The key is never read from the manifest:
a key carried inside the structure it signs authenticates nothing.

A signature covering only the fixed header would leave every file name, size,
and digest unauthenticated, allowing an attacker to rewrite an entry to a
path-traversal name without disturbing the signature. Implementations must not
narrow the signing scope.

## Verification Order

A receiver applies the checks in this order, and the order is normative:

1. **Parse.** Magic, version, reserved fields, CRC32C, entry structure, names.
2. **Signature.** Ed25519 over the canonical signing bytes.
3. **Policy.** Bounds on counts and sizes, session binding, consistency between
   the declared total and the summed entries.

Policy limits describe what a *legitimate* sender may claim. Applying them
before the signature verifies would mean reporting attacker-controlled values
as though they meant something.

## Path Traversal Protection

File names are relative paths using `/` as the separator. A name is rejected
when any of the following holds. Every `/`-separated component is inspected;
checking only the start of the string is insufficient, because
`a/../../etc/passwd` opens with a harmless component and still escapes.

- Empty name
- Leading `/` (absolute path)
- A Windows drive prefix, such as `C:` at position 1
- Any component equal to `..`
- Any backslash, at any position
- Any NUL byte
- Length over 4096 bytes

Backslash is rejected unconditionally rather than only on Windows: the sender
cannot know the receiver's platform, and on a Windows receiver a backslash
would split one component into two.

Names such as `..hidden` and `a..b` are legitimate and must be accepted; only
a whole component equal to `..` escapes.

## File Count Bound

The declared file count drives an allocation during parsing and is therefore
bounded before it is trusted. A manifest declaring more than 1,000,000 entries
is rejected, and a parser must not reserve capacity based on the declared count
alone; it reserves against what the received buffer could actually hold.

## Reserved Fields

The 3-byte reserved field at offset 5 and the 2-byte reserved field at offset
158 must be set to zero by the sender and rejected by the receiver if non-zero.
Reserved bits inside a signed structure are rejected rather than ignored, for
the reason given under Flags.
