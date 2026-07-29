//! Deterministic payload chunking into source blocks and symbols.
//!
//! This module implements the chunking algorithm described in `proto/block.md`:
//!
//! - The payload is divided into `B` blocks. The first `S mod B` blocks have
//!   `ceil(S / B)` bytes; the remaining blocks have `floor(S / B)` bytes.
//! - Each block is divided into symbols of fixed size `N`. The last symbol of
//!   a block is zero-padded to `N` bytes if the block size is not a multiple of `N`.
//!
//! All operations are deterministic: given the same input parameters, the same
//! chunk layout is always produced.

/// Maximum payload size: 4 GiB.
pub const MAX_PAYLOAD_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Minimum symbol size in bytes.
pub const MIN_SYMBOL_SIZE: u32 = 1;

/// Maximum symbol size in bytes (limited by the frame payload length field, u16).
pub const MAX_SYMBOL_SIZE: u32 = 65535;

/// Minimum block count.
pub const MIN_BLOCK_COUNT: u32 = 1;

/// Maximum block count.
pub const MAX_BLOCK_COUNT: u32 = 1024;

use crate::ChunkError;

/// Chunking parameters that define how a payload is divided into blocks and symbols.
///
/// # Fields
///
/// - `payload_size`: Total size of the encrypted payload in bytes.
/// - `block_count`: Number of source blocks (must be >= 1).
/// - `symbol_size`: Size of each symbol in bytes (must be >= 1, <= 65535).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkParams {
    /// Total payload size in bytes.
    pub payload_size: u64,
    /// Number of source blocks.
    pub block_count: u32,
    /// Symbol size in bytes.
    pub symbol_size: u32,
}

impl ChunkParams {
    /// Creates new chunking parameters with validation.
    ///
    /// Returns an error if any parameter is out of range.
    pub fn new(payload_size: u64, block_count: u32, symbol_size: u32) -> Result<Self, ChunkError> {
        if payload_size > MAX_PAYLOAD_SIZE {
            return Err(ChunkError::PayloadTooLarge {
                size: payload_size,
                max: MAX_PAYLOAD_SIZE,
            });
        }
        if block_count < MIN_BLOCK_COUNT || block_count > MAX_BLOCK_COUNT {
            return Err(ChunkError::InvalidBlockCount { count: block_count });
        }
        if symbol_size < MIN_SYMBOL_SIZE || symbol_size > MAX_SYMBOL_SIZE {
            return Err(ChunkError::InvalidSymbolSize { size: symbol_size });
        }
        Ok(Self {
            payload_size,
            block_count,
            symbol_size,
        })
    }
}

/// Information about a single source block within the chunk map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockInfo {
    /// Block index (0-based).
    pub index: u32,
    /// Start offset of this block within the payload.
    pub start: u64,
    /// Size of this block in bytes.
    pub size: u64,
    /// Number of symbols in this block.
    pub symbol_count: u32,
}

/// Information about a single symbol within a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolInfo {
    /// Symbol index within the block (0-based).
    pub index: u32,
    /// Start offset of this symbol within the block.
    pub start: u64,
    /// Size of actual data in this symbol (may be less than symbol_size for the last symbol).
    pub size: u64,
    /// Whether this symbol is padded to reach the full symbol size.
    pub padded: bool,
}

/// The chunk map describing how a payload is divided into blocks and symbols.
///
/// A `ChunkMap` is created from `ChunkParams` and provides methods to query
/// the layout, extract blocks and symbols, and reassemble the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMap {
    /// The chunking parameters used to create this map.
    pub params: ChunkParams,
    /// Information about each block.
    pub blocks: Vec<BlockInfo>,
}
