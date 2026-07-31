# dhow-codec Error Types

This document describes the error types in the `dhow-codec` crate.

## Overview

The `dhow-codec` crate uses a hierarchical error type system. The top-level
`CodecError` enum wraps specific error types for each subsystem.

## Error Types

### `CodecError` (top-level)

| Variant | Wraps | Description |
|---------|-------|-------------|
| `Chunk` | `ChunkError` | Payload chunking errors |
| `Frame` | `FrameError` | Frame encoding/decoding errors |
| `Session` | `SessionError` | Session model errors |
| `Resume` | `ResumeError` | Resume state errors |
| `RaptorQ` | `String` | RaptorQ encoding/decoding errors |
| `Internal` | `String` | Unexpected internal errors |

### `ChunkError`

| Variant | Fields | Description |
|---------|--------|-------------|
| `PayloadTooLarge` | `size`, `max` | Payload exceeds maximum size |
| `InvalidBlockCount` | `count` | Block count is zero or too large |
| `InvalidSymbolSize` | `size` | Symbol size is zero or too large |
| `EmptyPayload` | - | Payload is empty |
| `BlockIndexOutOfRange` | `index`, `count` | Block index exceeds block count |
| `SymbolIndexOutOfRange` | `index`, `count` | Symbol index exceeds symbol count |
| `Truncated` | `expected`, `actual` | Payload is shorter than expected |

### `FrameError`

| Variant | Fields | Description |
|---------|--------|-------------|
| `InvalidMagic` | `got` | Magic bytes don't match "DHOW" |
| `UnsupportedVersion` | `version` | Version byte not supported |
| `CrcMismatch` | `expected`, `actual` | CRC32C check failed |
| `PayloadTooLarge` | `length` | Payload exceeds 65535 bytes |
| `Truncated` | `expected`, `actual` | Frame is shorter than declared |
| `UnknownFrameType` | `frame_type` | Frame type not recognized |
| `SessionMismatch` | `expected`, `actual` | Session ID doesn't match |
| `MacVerificationFailed` | - | Truncated MAC check failed |
| `HeaderTooShort` | `length` | Header is shorter than 46 bytes |

### `SessionError`

| Variant | Fields | Description |
|---------|--------|-------------|
| `NotInitialized` | - | Session not initialized |
| `InvalidSessionId` | - | Session ID is all zeros |
| `InvalidParameters` | `details` | Session parameters invalid |
| `DigestMismatch` | - | Payload digest doesn't match |

### `ResumeError`

| Variant | Fields | Description |
|---------|--------|-------------|
| `InvalidMagic` | `got` | Magic bytes don't match "DHRS" |
| `UnsupportedVersion` | `version` | Version not supported |
| `IntegrityCheckFailed` | - | Integrity digest mismatch (tampering) |
| `Truncated` | `expected`, `actual` | Resume file is truncated |
| `SessionMismatch` | - | Session ID doesn't match |
| `BlockIndexOutOfRange` | `index` | Block index exceeds block count |
| `InvalidSymbolCount` | `count` | Symbol count is invalid |

## Design Principles

1. **No panics.** All errors are returned as `Result<T, CodecError>`.
2. **Typed errors.** Each error variant carries structured data.
3. **Display impls.** All errors implement `Display` with human-readable messages.
4. **No secret material in errors.** Error messages never contain payload bytes
   or key material.
5. **From conversions.** Sub-errors can be converted to `CodecError` via `?`.
