# dhow-crypt Error Types

This document describes the error types in the `dhow-crypt` crate.

## Overview

The `dhow-crypt` crate uses a hierarchical error type system. The top-level
`CryptError` enum wraps specific error types for each subsystem.

## Error Types

### `CryptError` (top-level)

| Variant | Wraps | Description |
|---------|-------|-------------|
| `Key` | `KeyError` | Key generation and handling errors |
| `Aead` | `AeadError` | AEAD encryption/decryption errors |
| `Signing` | `SigningError` | Ed25519 signing/verification errors |
| `Manifest` | `ManifestError` | Manifest build/verify errors |
| `Internal` | `String` | Unexpected internal errors |

### `KeyError`

| Variant | Fields | Description |
|---------|--------|-------------|
| `GenerationFailed` | `details` | Key generation failed |
| `InvalidMagic` | `expected`, `got` | Key file magic bytes don't match |
| `UnsupportedVersion` | `version` | Key file version not supported |
| `Truncated` | `expected`, `actual` | Key file is truncated |
| `InsecurePermissions` | `perms` | Key file permissions too permissive |
| `InvalidKey` | `details` | Key data is invalid |
| `ZeroizationFailed` | - | Key zeroization failed |

### `AeadError`

| Variant | Fields | Description |
|---------|--------|-------------|
| `EncryptionFailed` | `details` | Encryption failed |
| `DecryptionFailed` | `details` | Decryption failed (tampered/wrong key) |
| `InvalidNonce` | `details` | Nonce is invalid |
| `KeyDerivationFailed` | `details` | HKDF key derivation failed |

### `SigningError`

| Variant | Fields | Description |
|---------|--------|-------------|
| `SigningFailed` | `details` | Signing failed |
| `VerificationFailed` | - | Signature verification failed |
| `InvalidPublicKey` | `details` | Public key is invalid |
| `InvalidSignature` | `details` | Signature is invalid |

### `ManifestError`

| Variant | Fields | Description |
|---------|--------|-------------|
| `InvalidMagic` | `got` | Magic bytes don't match "DHMF" |
| `UnsupportedVersion` | `version` | Version not supported |
| `SignatureVerificationFailed` | - | Ed25519 signature verification failed |
| `CrcMismatch` | - | CRC32C check failed |
| `Truncated` | `expected`, `actual` | Manifest is truncated |
| `PathTraversal` | `name` | File name contains path traversal |
| `FileNameTooLong` | `length` | File name exceeds 4096 bytes |
| `FileSizeTooLarge` | `size`, `max` | File size exceeds maximum |
| `InvalidBlockCount` | `count` | Block count in manifest is invalid |
| `SessionMismatch` | - | Session ID doesn't match |

## Design Principles

1. **No panics.** All errors are returned as `Result<T, CryptError>`.
2. **Typed errors.** Each error variant carries structured data.
3. **Display impls.** All errors implement `Display` with human-readable messages.
4. **No secret material in errors.** Error messages never contain payload bytes,
   key material, or ciphertext.
5. **No secret-dependent branching.** Error paths do not branch on secret data.
6. **From conversions.** Sub-errors can be converted to `CryptError` via `?`.
7. **Constant-time where possible.** Cryptographic verification uses constant-time
   comparison primitives.
