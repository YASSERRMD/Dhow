//! dhow-crypt: AEAD, signing, key handling, and manifest for Dhow.
//!
//! This crate owns all cryptographic operations. It is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

pub mod aead;
#[cfg(test)]
mod aead_test;
pub mod kdf;
#[cfg(test)]
mod kdf_test;
pub mod key;
#[cfg(test)]
mod key_test;

use thiserror::Error;

/// Errors that can occur during key generation and handling.
#[derive(Debug, Error)]
pub enum KeyError {
    /// Key generation failed.
    #[error("key generation failed: {details}")]
    GenerationFailed { details: String },

    /// The key file has invalid magic bytes.
    #[error("invalid key file magic: expected {expected:?}, got {got:?}")]
    InvalidMagic { expected: [u8; 4], got: [u8; 4] },

    /// The key file version is not supported.
    #[error("unsupported key file version: {version}")]
    UnsupportedVersion { version: u8 },

    /// The key file is truncated.
    #[error("key file truncated: expected {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// The key file permissions are too permissive.
    #[error("key file permissions too permissive: {perms:#o} (expected 0600)")]
    InsecurePermissions { perms: u32 },

    /// The key data is invalid.
    #[error("invalid key data: {details}")]
    InvalidKey { details: String },

    /// The key could not be zeroized.
    #[error("key zeroization failed")]
    ZeroizationFailed,
}

/// Errors that can occur during AEAD encryption/decryption.
#[derive(Debug, Error)]
pub enum AeadError {
    /// Encryption failed.
    #[error("encryption failed: {details}")]
    EncryptionFailed { details: String },

    /// Decryption failed (ciphertext was tampered or wrong key).
    #[error("decryption failed: {details}")]
    DecryptionFailed { details: String },

    /// The nonce is invalid.
    #[error("invalid nonce: {details}")]
    InvalidNonce { details: String },

    /// The key derivation (HKDF) failed.
    #[error("key derivation failed: {details}")]
    KeyDerivationFailed { details: String },
}

/// Errors that can occur during Ed25519 signing/verification.
#[derive(Debug, Error)]
pub enum SigningError {
    /// Signing failed.
    #[error("signing failed: {details}")]
    SigningFailed { details: String },

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,

    /// The public key is invalid.
    #[error("invalid public key: {details}")]
    InvalidPublicKey { details: String },

    /// The signature is invalid.
    #[error("invalid signature: {details}")]
    InvalidSignature { details: String },
}

/// Errors that can occur during manifest operations.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// The manifest has invalid magic bytes.
    #[error("invalid manifest magic: expected DHMF, got {got:?}")]
    InvalidMagic { got: [u8; 4] },

    /// The manifest version is not supported.
    #[error("unsupported manifest version: {version}")]
    UnsupportedVersion { version: u8 },

    /// The manifest signature verification failed.
    #[error("manifest signature verification failed")]
    SignatureVerificationFailed,

    /// The manifest CRC32C check failed.
    #[error("manifest CRC mismatch")]
    CrcMismatch,

    /// The manifest is truncated.
    #[error("manifest truncated: expected {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// A file name in the manifest contains path traversal.
    #[error("path traversal detected in file name: {name}")]
    PathTraversal { name: String },

    /// A file name in the manifest is too long.
    #[error("file name too long: {length} bytes (max 4096)")]
    FileNameTooLong { length: usize },

    /// The manifest claims a file size that exceeds the maximum.
    #[error("file size {size} exceeds maximum {max}")]
    FileSizeTooLarge { size: u64, max: u64 },

    /// The manifest block count is invalid.
    #[error("invalid block count in manifest: {count}")]
    InvalidBlockCount { count: u32 },

    /// The manifest session ID does not match.
    #[error("manifest session ID mismatch")]
    SessionMismatch,
}

/// Top-level error type for the crypt crate.
#[derive(Debug, Error)]
pub enum CryptError {
    /// Key handling error.
    #[error("key error: {0}")]
    Key(#[from] KeyError),

    /// AEAD error.
    #[error("aead error: {0}")]
    Aead(#[from] AeadError),

    /// Signing error.
    #[error("signing error: {0}")]
    Signing(#[from] SigningError),

    /// Manifest error.
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),

    /// An unexpected internal error.
    #[error("internal error: {details}")]
    Internal { details: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_error_display() {
        let err = KeyError::InvalidKey {
            details: "bad key".into(),
        };
        assert!(err.to_string().contains("invalid key"));
    }

    #[test]
    fn test_aead_error_display() {
        let err = AeadError::DecryptionFailed {
            details: "wrong key".into(),
        };
        assert!(err.to_string().contains("decryption failed"));
    }

    #[test]
    fn test_signing_error_display() {
        let err = SigningError::VerificationFailed;
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn test_manifest_error_display() {
        let err = ManifestError::PathTraversal {
            name: "../../etc/passwd".into(),
        };
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn test_crypt_error_from_key() {
        let key_err = KeyError::ZeroizationFailed;
        let crypt_err = CryptError::from(key_err);
        assert!(crypt_err.to_string().contains("key error"));
    }

    #[test]
    fn test_crypt_error_from_aead() {
        let aead_err = AeadError::InvalidNonce {
            details: "bad nonce".into(),
        };
        let crypt_err = CryptError::from(aead_err);
        assert!(crypt_err.to_string().contains("aead error"));
    }

    #[test]
    fn test_crypt_error_from_signing() {
        let signing_err = SigningError::SigningFailed {
            details: "bad key".into(),
        };
        let crypt_err = CryptError::from(signing_err);
        assert!(crypt_err.to_string().contains("signing error"));
    }

    #[test]
    fn test_crypt_error_from_manifest() {
        let manifest_err = ManifestError::CrcMismatch;
        let crypt_err = CryptError::from(manifest_err);
        assert!(crypt_err.to_string().contains("manifest error"));
    }
}
