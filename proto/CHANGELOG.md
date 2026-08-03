# Format Changelog

> Version 1.1

## Transfer record v2 - 2026-08-03

The transfer record is not part of `proto/`: it is a stand-in the CLI writes
alongside the frames until the signed manifest travels in the frame stream. It
is noted here so the two are not confused.

Version 2 adds a per-file inventory - name, size, executable bit, and content
digest - which is what `dhow verify` checks an extracted dataset against. A
version 1 record is rejected: it carries no inventory, so verifying against it
would be the file count the inventory exists to replace.

## v1.1 - 2026-08-03

### Changed

- Resume file format bumped to v2. The 32-byte reserved field at offset 28 is
  replaced by an 8-byte journal length and a 32-byte journal digest, and the
  fixed header grows from 96 to 128 bytes. A v2 reader rejects a v1 file.

### Notes

- Only the resume file changed. Frame, session, and manifest formats are
  untouched, so this is not an over-the-air change: a v1.0 sender and a v1.1
  receiver interoperate. Resume files are local state and never cross the
  optical channel.

## v1.0 - 2026-07-27

### Added

- Frame header format (v1): magic, version, frame type, session ID, truncated MAC,
  block index, symbol index, payload length, CRC32C, payload.
- Session header format (v1): magic, version, session ID, payload size, block count,
  symbol size, RaptorQ parameters, payload digest, reserved, CRC32C.
- Manifest format (v1): magic, version, session ID, file count, total size,
  payload digest, reserved, CRC32C, Ed25519 signature, file entries.
- Resume file format (v1): magic, version, session ID, block count, reserved,
  CRC32C, integrity digest, block entries.
- Block and symbol structure: deterministic chunking, padding rules.
- Endianness and alignment rules: all little-endian, packed.
- Golden test vectors for all formats.
- Spec consistency checker script.

### Breaking changes

None. This is the initial release.

### Notes

- All formats use little-endian byte order.
- All multi-byte fields are packed with no alignment padding.
- CRC32C is used for fast integrity checks.
- BLAKE3 (32-byte) is used for cryptographic integrity.
- Ed25519 (64-byte) is used for manifest signing.
