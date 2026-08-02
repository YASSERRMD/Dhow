//! Resume file wire format.
//!
//! Implements the resume file format described in `proto/resume.md`.
//! Resume files allow the receiver to save and restore transfer progress
//! on disk, with integrity protection via CRC32C and BLAKE3 digest.
//!
//! ## Fixed Header (96 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 4 | Magic ("DHRS") |
//! | 4 | 1 | Version (0x01) |
//! | 5 | 3 | Reserved |
//! | 8 | 16 | Session ID |
//! | 24 | 4 | Block Count |
//! | 28 | 32 | Reserved |
//! | 60 | 4 | CRC32C |
//! | 64 | 32 | Integrity Digest (BLAKE3 of 0..64) |
//! | 96 | var | Block Entries |
//!
//! ## Block Entry
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 4 | Block Index |
//! | 4 | 4 | Symbol Count |
//! | 8 | 4 | Symbols Held |
//! | 12 | variable | Symbol Bitmap |
//!
//! ## Integrity
//!
//! - **CRC32C**: Covers bytes 0..60 (magic through reserved2).
//! - **Integrity Digest**: BLAKE3 of bytes 0..64 (includes CRC32C).
//!
//! # Example
//!
//! ```
//! use dhow_codec::resume::{ResumeFile, ResumeHeader, BlockEntry};
//!
//! let mut bitmap = vec![0u8; 4];
//! bitmap[0] = 0b00000101;
//! let entries = vec![BlockEntry::new(0, 8, 2, &bitmap)];
//! let header = ResumeHeader::new([0u8; 16], &entries);
//! let resume = ResumeFile::build(&header, &entries);
//! let bytes = resume.to_vec();
//! let parsed = ResumeFile::from_bytes(&bytes).unwrap();
//! assert_eq!(parsed.entries().len(), 1);
//! ```

use crate::blake3::blake3_digest;
use crate::crc32c::crc32c_digest;
use crate::ResumeError;

/// Magic bytes for Dhow resume files (ASCII "DHRS").
pub const RESUME_MAGIC: [u8; 4] = *b"DHRS";

/// Resume file version.
pub const RESUME_VERSION: u8 = 1;

/// Fixed resume header size before block entries.
pub const RESUME_HEADER_SIZE: usize = 96;

/// Fixed header size used for CRC (bytes 0..60).
pub const CRC_COVER_BYTES: usize = 60;

/// One block entry within the resume file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    /// Index of the block.
    pub block_index: u32,
    /// Total number of symbols in the block.
    pub symbol_count: u32,
    /// Number of symbols currently held.
    pub symbols_held: u32,
    /// Bitmap of held symbols (1 bit per symbol).
    pub symbol_bitmap: Vec<u8>,
}

impl BlockEntry {
    /// Creates a new block entry.
    pub fn new(
        block_index: u32,
        symbol_count: u32,
        symbols_held: u32,
        symbol_bitmap: &[u8],
    ) -> Self {
        Self {
            block_index,
            symbol_count,
            symbols_held,
            symbol_bitmap: symbol_bitmap.to_vec(),
        }
    }

    /// Serializes the block entry to bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.symbol_bitmap.len());
        buf.extend_from_slice(&self.block_index.to_le_bytes());
        buf.extend_from_slice(&self.symbol_count.to_le_bytes());
        buf.extend_from_slice(&self.symbols_held.to_le_bytes());
        buf.extend_from_slice(&self.symbol_bitmap);
        buf
    }

    /// Deserializes a block entry from bytes.
    /// Returns the entry and the number of bytes consumed.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), ResumeError> {
        if bytes.len() < 12 {
            return Err(ResumeError::Truncated {
                expected: 12,
                actual: bytes.len(),
            });
        }

        let block_index = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let symbol_count = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let symbols_held = u32::from_le_bytes(bytes[8..12].try_into().unwrap());

        // Bitmap size = ceil(symbol_count / 8)
        let bitmap_len = ((symbol_count as usize) + 7) / 8;
        if bytes.len() < 12 + bitmap_len {
            return Err(ResumeError::Truncated {
                expected: 12 + bitmap_len,
                actual: bytes.len(),
            });
        }

        let symbol_bitmap = bytes[12..12 + bitmap_len].to_vec();

        Ok((Self {
            block_index,
            symbol_count,
            symbols_held,
            symbol_bitmap,
        }, 12 + bitmap_len))
    }
}

/// Parsed resume file header (96 bytes).
#[derive(Debug, Clone)]
pub struct ResumeHeader {
    magic: [u8; 4],
    version: u8,
    reserved1: [u8; 3],
    session_id: [u8; 16],
    block_count: u32,
    reserved2: [u8; 32],
    crc32c: u32,
    integrity_digest: [u8; 32],
}

impl ResumeHeader {
    /// Creates a new resume header.
    pub fn new(session_id: [u8; 16], entries: &[BlockEntry]) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&RESUME_MAGIC);
        bytes.push(RESUME_VERSION);
        bytes.extend_from_slice(&[0u8; 3]);
        bytes.extend_from_slice(&session_id);
        bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]);

        let crc32c = crc32c_digest(&bytes);
        bytes.extend_from_slice(&crc32c.to_le_bytes());

        let full_hash = blake3_digest(&bytes);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&full_hash);

        Self {
            magic: RESUME_MAGIC,
            version: RESUME_VERSION,
            reserved1: [0; 3],
            session_id,
            block_count: entries.len() as u32,
            reserved2: [0; 32],
            crc32c,
            integrity_digest: digest,
        }
    }

    /// Serializes the header to a 96-byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RESUME_HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);
        buf.extend_from_slice(&self.reserved1);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.block_count.to_le_bytes());
        buf.extend_from_slice(&self.reserved2);
        buf.extend_from_slice(&self.crc32c.to_le_bytes());
        buf.extend_from_slice(&self.integrity_digest);
        debug_assert_eq!(buf.len(), RESUME_HEADER_SIZE);
        buf
    }

    /// Deserializes the header from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ResumeError> {
        if bytes.len() < RESUME_HEADER_SIZE {
            return Err(ResumeError::Truncated {
                expected: RESUME_HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        if magic != RESUME_MAGIC {
            return Err(ResumeError::InvalidMagic { got: magic });
        }

        let version = bytes[4];
        if version != RESUME_VERSION {
            return Err(ResumeError::UnsupportedVersion { version });
        }

        let mut reserved1 = [0u8; 3];
        reserved1.copy_from_slice(&bytes[5..8]);
        if reserved1 != [0u8; 3] {
            return Err(ResumeError::Truncated {
                expected: 0,
                actual: 0,
            });
        }

        let session_id: [u8; 16] = bytes[8..24].try_into().unwrap();
        let block_count = u32::from_le_bytes(bytes[24..28].try_into().unwrap());

        let mut reserved2 = [0u8; 32];
        reserved2.copy_from_slice(&bytes[28..60]);
        if reserved2 != [0u8; 32] {
            return Err(ResumeError::Truncated {
                expected: 0,
                actual: 0,
            });
        }

        let crc32c = u32::from_le_bytes(bytes[60..64].try_into().unwrap());
        let integrity_digest: [u8; 32] = bytes[64..96].try_into().unwrap();

        // Verify CRC32C
        let expected_crc = crc32c_digest(&bytes[0..60]);
        if crc32c != expected_crc {
            return Err(ResumeError::IntegrityCheckFailed);
        }

        // Verify integrity digest
        let expected_digest = blake3_digest(&bytes[0..64]);
        if integrity_digest != expected_digest {
            return Err(ResumeError::IntegrityCheckFailed);
        }

        Ok(Self {
            magic,
            version,
            reserved1,
            session_id,
            block_count,
            reserved2,
            crc32c,
            integrity_digest,
        })
    }

    pub fn magic(&self) -> [u8; 4] { self.magic }
    pub fn version(&self) -> u8 { self.version }
    pub fn session_id(&self) -> [u8; 16] { self.session_id }
    pub fn block_count(&self) -> u32 { self.block_count }
    pub fn crc32c(&self) -> u32 { self.crc32c }
    pub fn integrity_digest(&self) -> [u8; 32] { self.integrity_digest }
}

/// A complete resume file: header + block entries.
#[derive(Debug, Clone)]
pub struct ResumeFile {
    header: ResumeHeader,
    entries: Vec<BlockEntry>,
}

impl ResumeFile {
    /// Builds a resume file from a header and block entries.
    pub fn build(header: &ResumeHeader, entries: &[BlockEntry]) -> Self {
        Self {
            header: header.clone(),
            entries: entries.to_vec(),
        }
    }

    /// Serializes the entire resume file to bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = self.header.to_vec();
        for entry in &self.entries {
            buf.extend_from_slice(&entry.to_vec());
        }
        buf
    }

    /// Parses a resume file from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ResumeError> {
        let header = ResumeHeader::from_bytes(bytes)?;
        let block_count = header.block_count() as usize;

        let mut entries = Vec::with_capacity(block_count);
        let mut offset = RESUME_HEADER_SIZE;
        for _ in 0..block_count {
            if offset >= bytes.len() {
                return Err(ResumeError::Truncated {
                    expected: bytes.len() + 1,
                    actual: bytes.len(),
                });
            }
            let (entry, consumed) = BlockEntry::from_bytes(&bytes[offset..])?;
            entries.push(entry);
            offset += consumed;
        }

        Ok(Self { header, entries })
    }

    pub fn header(&self) -> &ResumeHeader { &self.header }
    pub fn entries(&self) -> &[BlockEntry] { &self.entries }

    /// Returns the session ID from the header.
    pub fn session_id(&self) -> [u8; 16] {
        self.header.session_id()
    }

    /// Returns the block count from the header.
    pub fn block_count(&self) -> u32 {
        self.header.block_count()
    }
}
