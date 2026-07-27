# Endianness and Alignment Rules

> Version 1.0

## Endianness

All multi-byte integer fields in all Dhow wire formats are **little-endian**.
This is consistent across all platforms and architectures.

### Rationale

Little-endian is the native byte order on x86 and ARM (the most common
platforms for Dhow). Using a fixed endianness avoids ambiguity and simplifies
cross-platform compatibility.

## Alignment

All fields are **packed** with no alignment padding. Fields are placed
immediately after the previous field, regardless of their natural alignment.

### Rationale

Packed layouts minimize the size of wire-format structures and make the byte
layout deterministic across platforms.

## Integer Types

| Type | Size | Description |
|------|------|-------------|
| u8 | 1 byte | Unsigned 8-bit integer |
| u16 LE | 2 bytes | Unsigned 16-bit little-endian |
| u32 LE | 4 bytes | Unsigned 32-bit little-endian |
| u64 LE | 8 bytes | Unsigned 64-bit little-endian |
| bytes | variable | Raw byte sequence |

## Field Offsets

All field offsets are relative to the start of the structure. The first field
is at offset 0.

## CRC32C

CRC32C (Castagnoli) is computed over the specified bytes and stored as a
4-byte little-endian integer. The CRC does not include itself.

## BLAKE3

BLAKE3 digests are 32 bytes. They are stored as raw bytes (no hex encoding).

## Ed25519

Ed25519 signatures are 64 bytes. They are stored as raw bytes (no hex encoding).
