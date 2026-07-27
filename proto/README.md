# Dhow Wire-Format Specification

> Version 1.0

This directory is the single source of truth for all Dhow wire formats.

## Formats

| Format | File | Version |
|--------|------|---------|
| Frame header | `frame.md` | v1 |
| Session header | `session.md` | v1 |
| Block & symbol | `block.md` | v1 |
| Manifest | `manifest.md` | v1 |
| Resume file | `resume.md` | v1 |

## Conventions

- **Endianness:** All multi-byte integer fields are little-endian unless noted.
- **Alignment:** No alignment padding; fields are packed.
- **Version bytes:** Every format begins with a 1-byte version field.
- **Reserved fields:** Must be set to zero by the sender; ignored by the receiver.
- **CRC:** CRC32C (Castagnoli) is used for fast integrity checks.
- **Digests:** BLAKE3 (32-byte output) is used for cryptographic integrity.

## Versioning Policy

- A format version bump is required for any change to field widths, ordering, or semantics.
- A v1.x receiver must accept all v1.x formats.
- A v1.x receiver must reject v2+ formats with a clear error.
- Reserved fields allow future extensions without a version bump.
