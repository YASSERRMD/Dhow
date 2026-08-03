# Format Changelog

> Version 2.0

## v2.0 - 2026-08-03

### Changed

- Manifest format bumped to v2. The fixed header grows from 168 to 228 bytes:
  the 32 reserved bytes at offset 68 become the HKDF salt, and 92 new bytes
  carry the nonce, payload size, and the full coding parameter set. The CRC32C
  moves from 100 to 160 and the signature from 104 to 164.
- Manifest file entries grow from 42+name to 43+name bytes, gaining a flag byte
  whose bit 0 is the owner execute bit.
- The manifest's payload digest is now what the spec always said it was: BLAKE3
  of the encrypted payload. v1 shipped a digest of the concatenated per-file
  digests, which is a different value that no receiver could check against
  anything it had.

### Removed

- The CLI's `transfer.json` transfer record. It was a stand-in for the signed
  manifest and was never part of `proto/`; it is deleted rather than versioned,
  because everything it carried is now in the manifest and signed.

### Breaking changes

- A v1 manifest is rejected by a v2 receiver, and a v2 manifest by a v1
  receiver. There is no conversion; see `proto/migration.md`.

### Notes

- This is the first change to a format that crosses the optical channel, so
  unlike the v1.1 resume change it is not local: a v1 sender and a v2 receiver
  do not interoperate. Both operators upgrade together.

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
