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

impl ChunkMap {
    /// Computes the block layout from chunking parameters.
    ///
    /// The payload is divided into `B` blocks. The first `S mod B` blocks have
    /// `ceil(S / B)` bytes; the remaining blocks have `floor(S / B)` bytes.
    fn compute_blocks(params: &ChunkParams) -> Result<Vec<BlockInfo>, ChunkError> {
        let s = params.payload_size;
        let b = params.block_count as u64;
        let n = params.symbol_size as u64;

        let remainder = s % b;
        let large_size = (s + b - 1) / b;
        let small_size = s / b;

        let mut blocks = Vec::with_capacity(b as usize);
        let mut offset = 0u64;

        for i in 0..b {
            let size = if i < remainder { large_size } else { small_size };
            let symbol_count = if size == 0 {
                0u32
            } else {
                let sc = (size + n - 1) / n;
                if sc > u32::MAX as u64 {
                    return Err(ChunkError::InvalidSymbolSize {
                        size: params.symbol_size,
                    });
                }
                sc as u32
            };
            blocks.push(BlockInfo {
                index: i as u32,
                start: offset,
                size,
                symbol_count,
            });
            offset += size;
        }

        Ok(blocks)
    }

    /// Creates a new chunk map from chunking parameters.
    ///
    /// Returns an error if the parameters are invalid.
    pub fn new(params: ChunkParams) -> Result<Self, ChunkError> {
        let blocks = Self::compute_blocks(&params)?;
        Ok(Self { params, blocks })
    }

    /// Returns the number of blocks.
    pub fn block_count(&self) -> u32 {
        self.blocks.len() as u32
    }

    /// Returns the total number of symbols across all blocks.
    pub fn total_symbols(&self) -> u32 {
        self.blocks.iter().map(|b| b.symbol_count).sum()
    }

    /// Returns information about a specific block.
    ///
    /// Returns `ChunkError::BlockIndexOutOfRange` if the index is out of range.
    pub fn block_info(&self, index: u32) -> Result<&BlockInfo, ChunkError> {
        if index >= self.block_count() {
            return Err(ChunkError::BlockIndexOutOfRange {
                index,
                count: self.block_count(),
            });
        }
        Ok(&self.blocks[index as usize])
    }

    /// Returns information about a specific symbol within a block.
    ///
    /// The symbol size is fixed at `params.symbol_size`. The last symbol of a
    /// block may contain less actual data and be zero-padded.
    ///
    /// Returns `ChunkError::BlockIndexOutOfRange` if the block index is out of range,
    /// or `ChunkError::SymbolIndexOutOfRange` if the symbol index is out of range.
    pub fn symbol_info(&self, block_index: u32, symbol_index: u32) -> Result<SymbolInfo, ChunkError> {
        let block = self.block_info(block_index)?;
        if symbol_index >= block.symbol_count {
            return Err(ChunkError::SymbolIndexOutOfRange {
                index: symbol_index,
                count: block.symbol_count,
            });
        }
        let n = self.params.symbol_size as u64;
        let start = symbol_index as u64 * n;
        let size = if block.size % n != 0 && symbol_index == block.symbol_count - 1 {
            block.size % n
        } else {
            n
        };
        let padded = size < n;
        Ok(SymbolInfo {
            index: symbol_index,
            start,
            size,
            padded,
        })
    }

    /// Extracts a block's payload from the full payload.
    ///
    /// Returns a slice of the payload corresponding to the given block.
    /// Returns `ChunkError::Truncated` if the payload is shorter than expected.
    pub fn extract_block<'a>(&self, payload: &'a [u8], block_index: u32) -> Result<&'a [u8], ChunkError> {
        let block = self.block_info(block_index)?;
        let start = block.start as usize;
        let end = start + block.size as usize;
        if end > payload.len() {
            return Err(ChunkError::Truncated {
                expected: end,
                actual: payload.len(),
            });
        }
        Ok(&payload[start..end])
    }
}
