//! dhow-codec: fountain coding (RaptorQ), chunking, and framing for Dhow.
//!
//! This crate owns the correctness-critical encoding and decoding logic.
//! It is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

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
    SessionMismatch { expected: [u8; 16], actual: [u8; 16] },

    /// The truncated MAC does not match.
    #[error("MAC verification failed")]
    MacVerificationFailed,

    /// The frame header is too short.
    #[error("frame header too short: {length} bytes (minimum 46)")]
    HeaderTooShort { length: usize },
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

/// Top-level error type for the codec crate.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Chunking error.
    #[error("chunking error: {0}")]
    Chunk(#[from] ChunkError),

    /// Frame encoding/decoding error.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),

    /// Session error.
    #[error("session error: {0}")]
    Session(#[from] SessionError),

    /// Resume state error.
    #[error("resume error: {0}")]
    Resume(#[from] ResumeError),

    /// RaptorQ encoding/decoding error.
    #[error("raptorq error: {details}")]
    RaptorQ { details: String },

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
    fn test_codec_error_from_session() {
        let session_err = SessionError::InvalidSessionId;
        let codec_err = CodecError::from(session_err);
        assert!(codec_err.to_string().contains("session error"));
    }

    #[test]
    fn test_codec_error_from_resume() {
        let resume_err = ResumeError::Truncated { expected: 100, actual: 50 };
        let codec_err = CodecError::from(resume_err);
        assert!(codec_err.to_string().contains("resume error"));
    }
}
