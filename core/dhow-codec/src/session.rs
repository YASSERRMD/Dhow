//! Session header wire format.
//!
//! Implements the session header format described in `proto/session.md`.
//! The session header is carried in a frame of type 0 (Session) and contains
//! all parameters needed by the receiver to decode the transfer.
//!
//! ## Header Layout
//!
//! ```text
//!  Offset  Size  Field
//!  0       4     Magic ("DSES")
//!  4       1     Version (0x01)
//!  5       3     Reserved
//!  8       16    Session ID
//!  24      8     Payload Size
//!  32      4     Block Count
//!  36      4     Symbol Size
//!  40      4     Source Symbols Per Block (K)
//!  44      4     Total Symbols Per Block
//!  48      4     RaptorQ Z
//!  52      4     RaptorQ N
//!  56      2     RaptorQ PSI
//!  58      32    Payload Digest
//!  90      32    Reserved
//!  122     4     CRC32C
//! ```
//!
//! Fixed header: 126 bytes.
//!
//! ## Integrity
//!
//! The CRC32C covers bytes 4..122 (version through reserved field 2),
//! excluding the trailing CRC32C field itself. The payload digest is a
//! BLAKE3 hash of the complete encrypted payload, recorded by the sender
//! and verified by the receiver after reassembly.
//!
//! # Example
//!
//! ```
//! use dhow_codec::session::{SessionHeader, SessionParams, RaptorQParams};
//!
//! let params = SessionParams {
//!     payload_size: 1000,
//!     block_count: 2,
//!     symbol_size: 256,
//!     source_symbols_per_block: 2,
//!     total_symbols_per_block: 3,
//!     raptorq: RaptorQParams { z: 2, n: 1, psi: 1 },
//!     payload_digest: [0; 32],
//! };
//! let header = SessionHeader::new([0u8; 16], params);
//! let bytes = header.to_vec();
//! let parsed = SessionHeader::from_bytes(&bytes).unwrap();
//! assert_eq!(parsed.params(), header.params());
//! ```

use crate::blake3::blake3_digest;
use crate::crc32c::crc32c_digest;
use crate::SessionError;

/// Magic bytes for Dhow session headers (ASCII "DSES").
pub const SESSION_MAGIC: [u8; 4] = *b"DSES";

/// Session header version.
pub const SESSION_VERSION: u8 = 1;

/// Total session header size in bytes.
pub const SESSION_HEADER_SIZE: usize = 126;

/// RaptorQ parameters for the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaptorQParams {
    /// Number of source blocks (Z).
    pub z: u32,
    /// Sub-block count per source block (N).
    pub n: u32,
    /// Pre-coded symbol count (PSI).
    pub psi: u16,
}

/// Session parameters extracted from the session header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionParams {
    /// Total size of the encrypted payload in bytes.
    pub payload_size: u64,
    /// Number of source blocks.
    pub block_count: u32,
    /// Size of each symbol in bytes.
    pub symbol_size: u32,
    /// Source symbols per block (K).
    pub source_symbols_per_block: u32,
    /// Total symbols per block (K + repair overhead).
    pub total_symbols_per_block: u32,
    /// RaptorQ-specific parameters.
    pub raptorq: RaptorQParams,
    /// BLAKE3 digest of the encrypted payload.
    pub payload_digest: [u8; 32],
}

/// Parsed session header (126 bytes).
#[derive(Debug, Clone)]
pub struct SessionHeader {
    magic: [u8; 4],
    version: u8,
    reserved1: [u8; 3],
    session_id: [u8; 16],
    params: SessionParams,
    reserved2: [u8; 32],
    crc32c: u32,
}

impl SessionHeader {
    /// Creates a new session header.
    pub fn new(
        session_id: [u8; 16],
        params: SessionParams,
    ) -> Self {
        // Build the bytes to compute CRC over
        let mut bytes = Vec::with_capacity(SESSION_HEADER_SIZE - 4);
        bytes.push(SESSION_VERSION);
        bytes.extend_from_slice(&[0u8; 3]); // reserved1
        bytes.extend_from_slice(&session_id);
        bytes.extend_from_slice(&params.payload_size.to_le_bytes());
        bytes.extend_from_slice(&params.block_count.to_le_bytes());
        bytes.extend_from_slice(&params.symbol_size.to_le_bytes());
        bytes.extend_from_slice(&params.source_symbols_per_block.to_le_bytes());
        bytes.extend_from_slice(&params.total_symbols_per_block.to_le_bytes());
        bytes.extend_from_slice(&params.raptorq.z.to_le_bytes());
        bytes.extend_from_slice(&params.raptorq.n.to_le_bytes());
        bytes.extend_from_slice(&params.raptorq.psi.to_le_bytes());
        bytes.extend_from_slice(&params.payload_digest);
        bytes.extend_from_slice(&[0u8; 32]); // reserved2
        let crc32c = crc32c_digest(&bytes);

        Self {
            magic: SESSION_MAGIC,
            version: SESSION_VERSION,
            reserved1: [0; 3],
            session_id,
            params,
            reserved2: [0; 32],
            crc32c,
        }
    }

    /// Serializes the session header to a 126-byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SESSION_HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);
        buf.extend_from_slice(&self.reserved1);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.params.payload_size.to_le_bytes());
        buf.extend_from_slice(&self.params.block_count.to_le_bytes());
        buf.extend_from_slice(&self.params.symbol_size.to_le_bytes());
        buf.extend_from_slice(&self.params.source_symbols_per_block.to_le_bytes());
        buf.extend_from_slice(&self.params.total_symbols_per_block.to_le_bytes());
        buf.extend_from_slice(&self.params.raptorq.z.to_le_bytes());
        buf.extend_from_slice(&self.params.raptorq.n.to_le_bytes());
        buf.extend_from_slice(&self.params.raptorq.psi.to_le_bytes());
        buf.extend_from_slice(&self.params.payload_digest);
        buf.extend_from_slice(&self.reserved2);
        buf.extend_from_slice(&self.crc32c.to_le_bytes());
        debug_assert_eq!(buf.len(), SESSION_HEADER_SIZE);
        buf
    }

    /// Deserializes a session header from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SessionError> {
        if bytes.len() < SESSION_HEADER_SIZE {
            return Err(SessionError::InvalidParameters {
                details: format!(
                    "header too short: {} bytes (minimum {})",
                    bytes.len(),
                    SESSION_HEADER_SIZE
                ),
            });
        }

        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        if magic != SESSION_MAGIC {
            return Err(SessionError::InvalidParameters {
                details: format!("invalid magic: expected DSES, got {:?}", magic),
            });
        }

        let version = bytes[4];
        if version != SESSION_VERSION {
            return Err(SessionError::InvalidParameters {
                details: format!("unsupported version: {}", version),
            });
        }

        let mut reserved1 = [0u8; 3];
        reserved1.copy_from_slice(&bytes[5..8]);
        if reserved1 != [0u8; 3] {
            return Err(SessionError::InvalidParameters {
                details: "reserved field must be zero".to_string(),
            });
        }

        let session_id: [u8; 16] = bytes[8..24].try_into().unwrap();
        let payload_size = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let block_count = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let symbol_size = u32::from_le_bytes(bytes[36..40].try_into().unwrap());
        let source_symbols_per_block = u32::from_le_bytes(bytes[40..44].try_into().unwrap());
        let total_symbols_per_block = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
        let z = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
        let n = u32::from_le_bytes(bytes[52..56].try_into().unwrap());
        let psi = u16::from_le_bytes([bytes[56], bytes[57]]);
        let payload_digest: [u8; 32] = bytes[58..90].try_into().unwrap();

        let mut reserved2 = [0u8; 32];
        reserved2.copy_from_slice(&bytes[90..122]);
        if reserved2 != [0u8; 32] {
            return Err(SessionError::InvalidParameters {
                details: "reserved field 2 must be zero".to_string(),
            });
        }

        let crc32c = u32::from_le_bytes(bytes[122..126].try_into().unwrap());

        // Compute expected CRC32C over bytes 4..122 (version through reserved2)
        let expected_crc = crc32c_digest(&bytes[4..122]);
        if crc32c != expected_crc {
            return Err(SessionError::InvalidParameters {
                details: format!(
                    "CRC32C mismatch: expected {:#010x}, got {:#010x}",
                    expected_crc, crc32c
                ),
            });
        }

        Ok(Self {
            magic,
            version,
            reserved1,
            session_id,
            params: SessionParams {
                payload_size,
                block_count,
                symbol_size,
                source_symbols_per_block,
                total_symbols_per_block,
                raptorq: RaptorQParams { z, n, psi },
                payload_digest,
            },
            reserved2,
            crc32c,
        })
    }

    pub fn magic(&self) -> [u8; 4] { self.magic }
    pub fn version(&self) -> u8 { self.version }
    pub fn session_id(&self) -> [u8; 16] { self.session_id }
    pub fn params(&self) -> &SessionParams { &self.params }
    /// Returns the CRC32C checksum of the session header.
    pub fn crc32c(&self) -> u32 { self.crc32c }

    /// Returns the payload digest for verification.
    pub fn payload_digest(&self) -> [u8; 32] {
        self.params.payload_digest
    }
}

/// Verifies that the payload digest matches the given data.
///
/// # Example
///
/// ```
/// use dhow_codec::session::verify_payload_digest;
/// use dhow_codec::blake3::blake3_digest;
///
/// let data = b"test data";
/// let digest = blake3_digest(data);
/// assert!(verify_payload_digest(data, &digest));
/// ```
pub fn verify_payload_digest(data: &[u8], expected: &[u8; 32]) -> bool {
    let actual = blake3_digest(data);
    actual == *expected
}
