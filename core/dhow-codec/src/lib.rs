//! dhow-codec: fountain coding (RaptorQ), chunking, and framing for Dhow.
//!
//! This crate owns the correctness-critical encoding and decoding logic.
//! It is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

pub mod blake3;
pub mod chunker;
pub mod crc32c;
pub mod fec;
#[cfg(test)]
mod fec_test;
pub mod frame;
#[cfg(test)]
mod frame_test;
#[cfg(test)]
mod integrity_test;
pub mod manifest;
#[cfg(test)]
mod manifest_test;
pub mod qr;
#[cfg(test)]
mod qr_test;
pub mod resume;
#[cfg(test)]
mod resume_test;
pub mod session;
#[cfg(test)]
mod session_test;

use thiserror::Error;

/// Errors that can occur during payload chunking.
#[derive(Debug, Error)]
pub enum ChunkError {
    /// The payload size exceeds the maximum allowed (4 GiB).
    #[error("payload size {size} exceeds maximum {max}")]
    PayloadTooLarge { size: u64, max: u64 },

    /// The block count is zero or exceeds the maximum.
    #[error("invalid block count: {count}")]
    InvalidBlockCount { count: u32 },

    /// The symbol size is zero or exceeds the maximum.
    #[error("invalid symbol size: {size}")]
    InvalidSymbolSize { size: u32 },

    /// The payload is empty.
    #[error("payload is empty")]
    EmptyPayload,

    /// The block index is out of range.
    #[error("block index {index} out of range (0..{count})")]
    BlockIndexOutOfRange { index: u32, count: u32 },

    /// The symbol index is out of range.
    #[error("symbol index {index} out of range (0..{count})")]
    SymbolIndexOutOfRange { index: u32, count: u32 },

    /// The payload is truncated (fewer bytes than expected).
    #[error("payload truncated: expected {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },
}

/// Errors that can occur during frame encoding or decoding.
#[derive(Debug, Error)]
pub enum FrameError {
    /// The magic bytes do not match "DHOW".
    #[error("invalid magic bytes: expected DHOW, got {got:?}")]
    InvalidMagic { got: [u8; 4] },

    /// The version byte is not supported.
    #[error("unsupported version: {version}")]
    UnsupportedVersion { version: u8 },

    /// The CRC32C check failed.
    #[error("CRC32C mismatch: expected {expected:#010x}, got {actual:#010x}")]
    CrcMismatch { expected: u32, actual: u32 },

    /// The payload length exceeds the maximum (65535 bytes).
    #[error("payload length {length} exceeds maximum 65535")]
    PayloadTooLarge { length: u32 },

    /// The frame is truncated (fewer bytes than declared).
    #[error("frame truncated: expected {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// The frame type is not recognized.
    #[error("unknown frame type: {frame_type}")]
    UnknownFrameType { frame_type: u8 },

    /// The session ID does not match the expected session.
    #[error("session ID mismatch: expected {expected:?}, got {actual:?}")]
    SessionMismatch {
        expected: [u8; 16],
        actual: [u8; 16],
    },

    /// The truncated MAC does not match.
    #[error("MAC verification failed")]
    MacVerificationFailed,

    /// The frame header is too short.
    #[error("frame header too short: {length} bytes (minimum 46)")]
    HeaderTooShort { length: usize },

    /// The reserved field is non-zero.
    #[error("reserved field must be zero, got {value}")]
    ReservedFieldNonZero { value: u16 },
}

/// Errors that can occur during session operations.
#[derive(Debug, Error)]
pub enum SessionError {
    /// The session was not initialized.
    #[error("session not initialized")]
    NotInitialized,

    /// The session ID is all zeros (invalid).
    #[error("session ID is all zeros")]
    InvalidSessionId,

    /// The session parameters are invalid.
    #[error("invalid session parameters: {details}")]
    InvalidParameters { details: String },

    /// The payload digest does not match.
    #[error("payload digest mismatch")]
    DigestMismatch,
}

/// Errors that can occur during resume state operations.
#[derive(Debug, Error)]
pub enum ResumeError {
    /// The resume file has invalid magic bytes.
    #[error("invalid resume file magic: expected DHRS, got {got:?}")]
    InvalidMagic { got: [u8; 4] },

    /// The resume file version is not supported.
    #[error("unsupported resume version: {version}")]
    UnsupportedVersion { version: u8 },

    /// The integrity digest does not match (resume file was tampered).
    #[error("resume file integrity check failed (possible tampering)")]
    IntegrityCheckFailed,

    /// The resume file is truncated.
    #[error("resume file truncated: expected {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// The session ID in the resume file does not match.
    #[error("resume session ID mismatch")]
    SessionMismatch,

    /// The block index in the resume file is out of range.
    #[error("resume block index {index} out of range")]
    BlockIndexOutOfRange { index: u32 },

    /// The symbol count in the resume file is invalid.
    #[error("invalid symbol count: {count}")]
    InvalidSymbolCount { count: u32 },
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

    /// The manifest file count is invalid.
    #[error("invalid file count in manifest: {count}")]
    InvalidFileCount { count: u32 },

    /// The manifest session ID does not match.
    #[error("manifest session ID mismatch")]
    SessionMismatch,

    /// The manifest signature is invalid.
    #[error("invalid manifest signature: {details}")]
    InvalidKey { details: String },
}

/// Errors that can occur during FEC encoding or decoding.
#[derive(Debug, Error)]
pub enum FecError {
    /// The input data is too large for RaptorQ encoding.
    #[error("payload too large for FEC encoding")]
    PayloadTooLarge,

    /// The source block size is invalid.
    #[error("invalid source block size: {details}")]
    InvalidSourceBlock { details: String },

    /// Decoding failed (insufficient packets received).
    #[error("decoding failed: insufficient packets")]
    InsufficientPackets,

    /// The MTU is too small.
    #[error("MTU {mtu} is below minimum {min}")]
    MtuTooSmall { mtu: u16, min: u16 },
}

/// Top-level error type for the codec crate.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Chunking error.
    #[error("chunking error: {0}")]
    Chunk(#[from] ChunkError),

    /// Frame encoding/decoding error.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),

    /// Frame payload exceeds maximum size.
    #[error("frame payload too large: {length} bytes (max {max}")]
    FramePayloadTooLarge { length: usize, max: usize },

    /// Session error.
    #[error("session error: {0}")]
    Session(#[from] SessionError),

    /// Manifest error.
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),

    /// Resume state error.
    #[error("resume error: {0}")]
    Resume(#[from] ResumeError),

    /// RaptorQ encoding/decoding error.
    #[error("raptorq error: {details}")]
    RaptorQ { details: String },

    /// RaptorQ encoding/decoding error.
    #[error("FEC error: {0}")]
    Fec(#[from] FecError),

    /// An unexpected internal error.
    #[error("internal error: {details}")]
    Internal { details: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_error_display() {
        let err = ChunkError::PayloadTooLarge { size: 100, max: 50 };
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_frame_error_display() {
        let err = FrameError::InvalidMagic { got: [0, 0, 0, 0] };
        assert!(err.to_string().contains("invalid magic"));
    }

    #[test]
    fn test_frame_error_reserved_nonzero() {
        let err = FrameError::ReservedFieldNonZero { value: 1 };
        assert!(err.to_string().contains("must be zero"));
    }

    #[test]
    fn test_frame_error_crc_mismatch() {
        let err = FrameError::CrcMismatch {
            expected: 1,
            actual: 2,
        };
        assert!(err.to_string().contains("CRC32C mismatch"));
    }

    #[test]
    fn test_frame_error_mac_verification() {
        let err = FrameError::MacVerificationFailed;
        assert!(err.to_string().contains("MAC verification"));
    }

    #[test]
    fn test_manifest_error_display() {
        let err = ManifestError::PathTraversal {
            name: "test".into(),
        };
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn test_manifest_error_crc_mismatch() {
        let err = ManifestError::CrcMismatch;
        assert!(err.to_string().contains("CRC"));
    }

    #[test]
    fn test_manifest_error_invalid_magic() {
        let err = ManifestError::InvalidMagic { got: [0, 0, 0, 0] };
        assert!(err.to_string().contains("manifest magic"));
    }

    #[test]
    fn test_codec_error_from_manifest() {
        let manifest_err = ManifestError::SignatureVerificationFailed;
        let codec_err = CodecError::from(manifest_err);
        assert!(codec_err.to_string().contains("manifest"));
    }

    #[test]
    fn test_session_error_display() {
        let err = SessionError::NotInitialized;
        assert!(err.to_string().contains("not initialized"));
    }

    #[test]
    fn test_resume_error_display() {
        let err = ResumeError::IntegrityCheckFailed;
        assert!(err.to_string().contains("integrity"));
    }

    #[test]
    fn test_resume_error_invalid_magic() {
        let err = ResumeError::InvalidMagic { got: [0, 0, 0, 0] };
        assert!(err.to_string().contains("invalid resume file magic"));
    }

    #[test]
    fn test_codec_error_from_chunk() {
        let chunk_err = ChunkError::EmptyPayload;
        let codec_err = CodecError::from(chunk_err);
        assert!(codec_err.to_string().contains("chunking error"));
    }

    #[test]
    fn test_codec_error_from_frame() {
        let frame_err = FrameError::UnsupportedVersion { version: 99 };
        let codec_err = CodecError::from(frame_err);
        assert!(codec_err.to_string().contains("frame error"));
    }

    #[test]
    fn test_codec_error_frame_payload_too_large() {
        let codec_err = CodecError::FramePayloadTooLarge {
            length: 70000,
            max: 65535,
        };
        assert!(codec_err.to_string().contains("too large"));
    }

    #[test]
    fn test_codec_error_from_session() {
        let session_err = SessionError::InvalidSessionId;
        let codec_err = CodecError::from(session_err);
        assert!(codec_err.to_string().contains("session error"));
    }

    #[test]
    fn test_codec_error_from_resume() {
        let resume_err = ResumeError::Truncated {
            expected: 100,
            actual: 50,
        };
        let codec_err = CodecError::from(resume_err);
        assert!(codec_err.to_string().contains("resume error"));
    }
}
