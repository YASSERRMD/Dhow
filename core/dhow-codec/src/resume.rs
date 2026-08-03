//! Resume file wire format.
//!
//! Implements the resume file format described in `proto/resume.md`.
//! A receiver saves its progress here so a restart picks the transfer up where
//! it stopped rather than from zero.
//!
//! ## What a resume file is for
//!
//! RaptorQ's decoder state is opaque and cannot be serialized, so progress is
//! preserved by keeping the accepted frames in a *journal* and replaying them
//! into a fresh decoder. The resume file is the index over that journal: it
//! says which session the journal belongs to, how many of its bytes are
//! covered, what the replay must reproduce, and which symbols each block
//! should end up holding. A replay that does not match is rejected rather than
//! trusted.
//!
//! The journal is covered by length as well as by digest. A receiver appends
//! to the journal continuously and rewrites the index periodically, so a crash
//! routinely leaves a journal longer than its index. `journal_bytes` names the
//! prefix the digest was taken over; anything past it is discarded on load.
//!
//! ## Fixed Header (128 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 4 | Magic ("DHRS") |
//! | 4 | 1 | Version (0x02) |
//! | 5 | 3 | Reserved |
//! | 8 | 16 | Session ID |
//! | 24 | 4 | Block Count |
//! | 28 | 8 | Journal Bytes |
//! | 36 | 32 | Journal Digest |
//! | 68 | 24 | Reserved |
//! | 92 | 4 | CRC32C (of 0..92) |
//! | 96 | 32 | Integrity Digest (BLAKE3 of 0..96) |
//! | 128 | var | Block Entries |
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
//! - **CRC32C**: covers bytes 0..92, catching accidental corruption cheaply.
//! - **Integrity Digest**: BLAKE3 of bytes 0..96, which includes the CRC.
//!
//! Neither is a signature. A resume file is local state, and an attacker who
//! can rewrite it can also recompute both. What the digests buy is that a
//! *corrupted* file is never silently believed; what stops a doctored journal
//! is that every replayed frame is re-authenticated against the session key,
//! which local state does not contain.
//!
//! # Example
//!
//! ```
//! use dhow_codec::resume::{ResumeFile, ResumeHeader, BlockEntry};
//!
//! let mut bitmap = vec![0u8; 1];
//! bitmap[0] = 0b00000101;
//! let entries = vec![BlockEntry::new(0, 8, 2, &bitmap)];
//! let header = ResumeHeader::new([0u8; 16], 512, [7u8; 32], &entries);
//! let resume = ResumeFile::build(&header, &entries);
//! let bytes = resume.to_vec();
//! let parsed = ResumeFile::from_bytes(&bytes).unwrap();
//! assert_eq!(parsed.entries().len(), 1);
//! assert_eq!(parsed.journal_bytes(), 512);
//! ```

use crate::ResumeError;
use crate::blake3::blake3_digest;
use crate::crc32c::crc32c_digest;

/// Magic bytes for Dhow resume files (ASCII "DHRS").
pub const RESUME_MAGIC: [u8; 4] = *b"DHRS";

/// Resume file version.
pub const RESUME_VERSION: u8 = 2;

/// Fixed resume header size before block entries.
pub const RESUME_HEADER_SIZE: usize = 128;

/// Bytes covered by the header CRC32C (0..92).
pub const CRC_COVER_BYTES: usize = 92;

/// Bytes covered by the integrity digest (0..96, including the CRC).
pub const INTEGRITY_COVER_BYTES: usize = 96;

/// Fixed size of a block entry before its bitmap.
pub const BLOCK_ENTRY_HEADER_SIZE: usize = 12;

/// One block entry within the resume file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    /// Index of the block.
    pub block_index: u32,
    /// Total number of symbols in the block.
    pub symbol_count: u32,
    /// Number of symbols currently held.
    pub symbols_held: u32,
    /// Bitmap of held symbols, one bit per symbol, LSB of byte 0 first.
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
        let mut buf = Vec::with_capacity(BLOCK_ENTRY_HEADER_SIZE + self.symbol_bitmap.len());
        buf.extend_from_slice(&self.block_index.to_le_bytes());
        buf.extend_from_slice(&self.symbol_count.to_le_bytes());
        buf.extend_from_slice(&self.symbols_held.to_le_bytes());
        buf.extend_from_slice(&self.symbol_bitmap);
        buf
    }

    /// Deserializes a block entry from bytes.
    ///
    /// Returns the entry and the number of bytes consumed. The declared
    /// `symbols_held` must equal the number of set bits in the bitmap: the two
    /// are two views of the same fact, and a file where they disagree is
    /// telling us at least one of them is wrong.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), ResumeError> {
        if bytes.len() < BLOCK_ENTRY_HEADER_SIZE {
            return Err(ResumeError::Truncated {
                expected: BLOCK_ENTRY_HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        let block_index = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let symbol_count = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let symbols_held = u32::from_le_bytes(bytes[8..12].try_into().unwrap());

        if symbols_held > symbol_count {
            return Err(ResumeError::InvalidSymbolCount {
                count: symbols_held,
            });
        }

        // A hostile symbol_count would otherwise size an allocation. Bound it
        // by what is actually present before reserving anything.
        let bitmap_len = (symbol_count as usize).div_ceil(8);
        let end = BLOCK_ENTRY_HEADER_SIZE.checked_add(bitmap_len).ok_or(
            ResumeError::InvalidSymbolCount {
                count: symbol_count,
            },
        )?;
        if bytes.len() < end {
            return Err(ResumeError::Truncated {
                expected: end,
                actual: bytes.len(),
            });
        }

        let symbol_bitmap = bytes[BLOCK_ENTRY_HEADER_SIZE..end].to_vec();

        let set: u32 = symbol_bitmap.iter().map(|b| b.count_ones()).sum();
        if set != symbols_held {
            return Err(ResumeError::HeldCountMismatch {
                declared: symbols_held,
                bitmap: set,
            });
        }

        // Bits past symbol_count would claim symbols the session does not have.
        if let Some(last) = symbol_bitmap.last() {
            let used = symbol_count % 8;
            if used != 0 && last >> used != 0 {
                return Err(ResumeError::InvalidSymbolCount {
                    count: symbol_count,
                });
            }
        }

        Ok((
            Self {
                block_index,
                symbol_count,
                symbols_held,
                symbol_bitmap,
            },
            end,
        ))
    }
}

/// Parsed resume file header (128 bytes).
#[derive(Debug, Clone)]
pub struct ResumeHeader {
    magic: [u8; 4],
    version: u8,
    reserved1: [u8; 3],
    session_id: [u8; 16],
    block_count: u32,
    journal_bytes: u64,
    journal_digest: [u8; 32],
    reserved2: [u8; 24],
    crc32c: u32,
    integrity_digest: [u8; 32],
}

impl ResumeHeader {
    /// Creates a new resume header over a journal prefix.
    ///
    /// `journal_bytes` is the length of the journal the digest was taken over,
    /// and `journal_digest` is the receiver's rolling digest at that point.
    pub fn new(
        session_id: [u8; 16],
        journal_bytes: u64,
        journal_digest: [u8; 32],
        entries: &[BlockEntry],
    ) -> Self {
        let block_count = entries.len() as u32;

        let mut bytes = Vec::with_capacity(INTEGRITY_COVER_BYTES);
        bytes.extend_from_slice(&RESUME_MAGIC);
        bytes.push(RESUME_VERSION);
        bytes.extend_from_slice(&[0u8; 3]);
        bytes.extend_from_slice(&session_id);
        bytes.extend_from_slice(&block_count.to_le_bytes());
        bytes.extend_from_slice(&journal_bytes.to_le_bytes());
        bytes.extend_from_slice(&journal_digest);
        bytes.extend_from_slice(&[0u8; 24]);
        debug_assert_eq!(bytes.len(), CRC_COVER_BYTES);

        let crc32c = crc32c_digest(&bytes);
        bytes.extend_from_slice(&crc32c.to_le_bytes());

        let integrity_digest = blake3_digest(&bytes);

        Self {
            magic: RESUME_MAGIC,
            version: RESUME_VERSION,
            reserved1: [0; 3],
            session_id,
            block_count,
            journal_bytes,
            journal_digest,
            reserved2: [0; 24],
            crc32c,
            integrity_digest,
        }
    }

    /// Serializes the header to a 128-byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RESUME_HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);
        buf.extend_from_slice(&self.reserved1);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.block_count.to_le_bytes());
        buf.extend_from_slice(&self.journal_bytes.to_le_bytes());
        buf.extend_from_slice(&self.journal_digest);
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

        let reserved1: [u8; 3] = bytes[5..8].try_into().unwrap();
        if reserved1 != [0u8; 3] {
            return Err(ResumeError::ReservedNotZero { offset: 5 });
        }

        let session_id: [u8; 16] = bytes[8..24].try_into().unwrap();
        let block_count = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let journal_bytes = u64::from_le_bytes(bytes[28..36].try_into().unwrap());
        let journal_digest: [u8; 32] = bytes[36..68].try_into().unwrap();

        let reserved2: [u8; 24] = bytes[68..92].try_into().unwrap();
        if reserved2 != [0u8; 24] {
            return Err(ResumeError::ReservedNotZero { offset: 68 });
        }

        let crc32c = u32::from_le_bytes(bytes[92..96].try_into().unwrap());
        let integrity_digest: [u8; 32] = bytes[96..128].try_into().unwrap();

        if crc32c != crc32c_digest(&bytes[0..CRC_COVER_BYTES]) {
            return Err(ResumeError::IntegrityCheckFailed);
        }
        if integrity_digest != blake3_digest(&bytes[0..INTEGRITY_COVER_BYTES]) {
            return Err(ResumeError::IntegrityCheckFailed);
        }

        Ok(Self {
            magic,
            version,
            reserved1,
            session_id,
            block_count,
            journal_bytes,
            journal_digest,
            reserved2,
            crc32c,
            integrity_digest,
        })
    }

    pub fn magic(&self) -> [u8; 4] {
        self.magic
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }
    pub fn block_count(&self) -> u32 {
        self.block_count
    }
    pub fn journal_bytes(&self) -> u64 {
        self.journal_bytes
    }
    pub fn journal_digest(&self) -> [u8; 32] {
        self.journal_digest
    }
    pub fn crc32c(&self) -> u32 {
        self.crc32c
    }
    pub fn integrity_digest(&self) -> [u8; 32] {
        self.integrity_digest
    }
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

    /// Builds a resume file describing a journal prefix and per-block progress.
    pub fn new(
        session_id: [u8; 16],
        journal_bytes: u64,
        journal_digest: [u8; 32],
        entries: &[BlockEntry],
    ) -> Self {
        let header = ResumeHeader::new(session_id, journal_bytes, journal_digest, entries);
        Self::build(&header, entries)
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
    ///
    /// Entries must appear in block order with no gaps, and the file must end
    /// exactly at the last entry. Both are true of every file this code
    /// writes, so anything else is either corruption or a forgery, and neither
    /// deserves the benefit of the doubt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ResumeError> {
        let header = ResumeHeader::from_bytes(bytes)?;
        let block_count = header.block_count() as usize;

        let mut entries = Vec::new();
        let mut offset = RESUME_HEADER_SIZE;
        for index in 0..block_count {
            let (entry, consumed) = BlockEntry::from_bytes(&bytes[offset..])?;
            if entry.block_index as usize != index {
                return Err(ResumeError::BlockIndexOutOfRange {
                    index: entry.block_index,
                });
            }
            entries.push(entry);
            offset += consumed;
        }

        if offset != bytes.len() {
            return Err(ResumeError::TrailingBytes {
                extra: bytes.len() - offset,
            });
        }

        Ok(Self { header, entries })
    }

    pub fn header(&self) -> &ResumeHeader {
        &self.header
    }
    pub fn entries(&self) -> &[BlockEntry] {
        &self.entries
    }

    /// Returns the session ID from the header.
    pub fn session_id(&self) -> [u8; 16] {
        self.header.session_id()
    }

    /// Returns the block count from the header.
    pub fn block_count(&self) -> u32 {
        self.header.block_count()
    }

    /// Returns the length of the journal prefix this file describes.
    pub fn journal_bytes(&self) -> u64 {
        self.header.journal_bytes()
    }

    /// Returns the digest the journal prefix must reproduce.
    pub fn journal_digest(&self) -> [u8; 32] {
        self.header.journal_digest()
    }
}
