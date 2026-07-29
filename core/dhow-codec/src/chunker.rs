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

    /// Extracts a symbol's bytes from a block's payload, with zero-padding.
    ///
    /// The returned vector is always `symbol_size` bytes. If the symbol is the
    /// last in its block and the block size is not a multiple of the symbol size,
    /// the trailing bytes are zero-padded.
    ///
    /// Returns `ChunkError::Truncated` if the block payload is shorter than expected.
    pub fn extract_symbol(
        &self,
        block_payload: &[u8],
        block_index: u32,
        symbol_index: u32,
    ) -> Result<Vec<u8>, ChunkError> {
        let info = self.symbol_info(block_index, symbol_index)?;
        let n = self.params.symbol_size as usize;
        let start = info.start as usize;
        let end = start + info.size as usize;
        if end > block_payload.len() {
            return Err(ChunkError::Truncated {
                expected: end,
                actual: block_payload.len(),
            });
        }
        let mut symbol = vec![0u8; n];
        symbol[..info.size as usize].copy_from_slice(&block_payload[start..end]);
        Ok(symbol)
    }

    /// Reassembles the payload from a list of block payloads.
    ///
    /// Each block payload must be at least as large as the corresponding block's
    /// declared size. Only the declared size bytes are used from each block.
    ///
    /// Returns `ChunkError::Truncated` if any block payload is too short.
    pub fn reassemble(&self, blocks: &[&[u8]]) -> Result<Vec<u8>, ChunkError> {
        if blocks.len() != self.block_count() as usize {
            return Err(ChunkError::BlockIndexOutOfRange {
                index: blocks.len() as u32,
                count: self.block_count(),
            });
        }
        let mut payload = Vec::with_capacity(self.params.payload_size as usize);
        for (i, block) in blocks.iter().enumerate() {
            let info = &self.blocks[i];
            let size = info.size as usize;
            if block.len() < size {
                return Err(ChunkError::Truncated {
                    expected: size,
                    actual: block.len(),
                });
            }
            payload.extend_from_slice(&block[..size]);
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_params_validation() {
        assert!(ChunkParams::new(0, 1, 256).is_ok());
        assert!(ChunkParams::new(1000, 1, 256).is_ok());
        assert!(ChunkParams::new(1000, 2, 256).is_ok());
        assert!(ChunkParams::new(1000, 1, 1).is_ok());
        assert!(ChunkParams::new(1000, 1, 65535).is_ok());

        assert!(ChunkParams::new(MAX_PAYLOAD_SIZE + 1, 1, 256).is_err());
        assert!(ChunkParams::new(1000, 0, 256).is_err());
        assert!(ChunkParams::new(1000, MAX_BLOCK_COUNT + 1, 256).is_err());
        assert!(ChunkParams::new(1000, 1, 0).is_err());
        assert!(ChunkParams::new(1000, 1, MAX_SYMBOL_SIZE + 1).is_err());
    }

    #[test]
    fn test_chunk_map_simple() {
        let params = ChunkParams::new(1000, 2, 256).unwrap();
        let map = ChunkMap::new(params).unwrap();

        assert_eq!(map.block_count(), 2);
        assert_eq!(map.total_symbols(), 4);

        let block0 = map.block_info(0).unwrap();
        assert_eq!(block0.start, 0);
        assert_eq!(block0.size, 500);
        assert_eq!(block0.symbol_count, 2);

        let block1 = map.block_info(1).unwrap();
        assert_eq!(block1.start, 500);
        assert_eq!(block1.size, 500);
        assert_eq!(block1.symbol_count, 2);
    }

    #[test]
    fn test_block_boundaries() {
        let params = ChunkParams::new(1001, 2, 256).unwrap();
        let map = ChunkMap::new(params).unwrap();

        let block0 = map.block_info(0).unwrap();
        assert_eq!(block0.start, 0);
        assert_eq!(block0.size, 501);

        let block1 = map.block_info(1).unwrap();
        assert_eq!(block1.start, 501);
        assert_eq!(block1.size, 500);
    }

    #[test]
    fn test_symbol_boundaries() {
        let params = ChunkParams::new(1000, 2, 256).unwrap();
        let map = ChunkMap::new(params).unwrap();

        let sym0 = map.symbol_info(0, 0).unwrap();
        assert_eq!(sym0.start, 0);
        assert_eq!(sym0.size, 256);
        assert!(!sym0.padded);

        let sym1 = map.symbol_info(0, 1).unwrap();
        assert_eq!(sym1.start, 256);
        assert_eq!(sym1.size, 244);
        assert!(sym1.padded);
    }

    #[test]
    fn test_block_extraction() {
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let params = ChunkParams::new(1000, 2, 256).unwrap();
        let map = ChunkMap::new(params).unwrap();

        let block0 = map.extract_block(&payload, 0).unwrap();
        assert_eq!(block0.len(), 500);
        assert_eq!(&block0[0..4], &[0, 1, 2, 3]);

        let block1 = map.extract_block(&payload, 1).unwrap();
        assert_eq!(block1.len(), 500);
        assert_eq!(&block1[0..4], &[244, 245, 246, 247]);
    }

    #[test]
    fn test_symbol_extraction() {
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let params = ChunkParams::new(1000, 2, 256).unwrap();
        let map = ChunkMap::new(params).unwrap();

        let block = map.extract_block(&payload, 0).unwrap();
        let sym0 = map.extract_symbol(block, 0, 0).unwrap();
        assert_eq!(sym0.len(), 256);
        assert_eq!(&sym0[0..4], &[0, 1, 2, 3]);

        let sym1 = map.extract_symbol(block, 0, 1).unwrap();
        assert_eq!(sym1.len(), 256);
        assert_eq!(&sym1[0..4], &[0, 1, 2, 3]);
        assert_eq!(&sym1[244..256], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_reassembly() {
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let params = ChunkParams::new(1000, 2, 256).unwrap();
        let map = ChunkMap::new(params).unwrap();

        let block0 = map.extract_block(&payload, 0).unwrap();
        let block1 = map.extract_block(&payload, 1).unwrap();
        let reassembled = map.reassemble(&[block0, block1]).unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn test_block_index_out_of_range() {
        let params = ChunkParams::new(1000, 2, 256).unwrap();
        let map = ChunkMap::new(params).unwrap();
        assert!(map.block_info(2).is_err());
    }

    #[test]
    fn test_symbol_index_out_of_range() {
        let params = ChunkParams::new(1000, 1, 256).unwrap();
        let map = ChunkMap::new(params).unwrap();
        assert!(map.symbol_info(0, 4).is_err());
    }
}
