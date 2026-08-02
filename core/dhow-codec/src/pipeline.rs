//! Frame assembly pipeline.
//!
//! Combines chunking, FEC encoding, and frame header construction
//! into a single pipeline that converts payload bytes into QR-ready
//! frames.
//!
//! # Pipeline
//!
//! 1. Chunk payload into source blocks and symbols
//! 2. Encode each block with RaptorQ (generate repair symbols)
//! 3. Wrap each symbol in a frame header
//!
//! # Example
//!
//! ```
//! use dhow_codec::pipeline::Pipeline;
//! use dhow_codec::session::{SessionParams, RaptorQParams};
//! use dhow_codec::frame::FrameType;
//!
//! let params = SessionParams {
//!     payload_size: 55,
//!     block_count: 1,
//!     symbol_size: 8,
//!     source_symbols_per_block: 5,
//!     total_symbols_per_block: 8,
//!     raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
//!     payload_digest: [0u8; 32],
//! };
//! let pipeline = Pipeline::new([0u8; 16], params, [0u8; 32]);
//! let frames = pipeline.encode(b"Hello, Dhow!").unwrap();
//! assert!(frames.len() > 0);
//! ```

use crate::chunker::{ChunkMap, ChunkParams};
use crate::fec::{encode as fec_encode, FecParams};
use crate::frame::{Frame, FrameHeader, FrameType};
use crate::session::SessionParams;
use crate::CodecError;
use crate::FrameError;

/// The session key for MAC computation.
pub type SessionKey = [u8; 32];

/// A single frame ready for QR encoding.
pub struct PreparedFrame {
    /// The complete frame (header + payload).
    pub frame: Frame,
}

/// Pipeline that converts payload data into QR-ready frames.
pub struct Pipeline {
    session_id: [u8; 16],
    params: SessionParams,
    session_key: SessionKey,
}

impl Pipeline {
    /// Creates a new pipeline with the given session parameters.
    pub fn new(
        session_id: [u8; 16],
        params: SessionParams,
        session_key: SessionKey,
    ) -> Self {
        Self {
            session_id,
            params,
            session_key,
        }
    }

    /// Encodes a payload into a list of prepared frames.
    ///
    /// This performs the full encoding pipeline:
    /// 1. Chunk the payload
    /// 2. Apply RaptorQ FEC encoding per block
    /// 3. Wrap each symbol in a frame
    pub fn encode(&self, payload: &[u8]) -> Result<Vec<PreparedFrame>, CodecError> {
        let mut frames = Vec::new();

        // Validate payload size
        if payload.len() != self.params.payload_size as usize {
            return Err(FrameError::PayloadTooLarge { length: payload.len() as u32 }.into());
        }

        // Create chunker
        let chunk_params = ChunkParams::new(
            self.params.payload_size,
            self.params.block_count,
            self.params.symbol_size,
        )?;
        let chunk_map = ChunkMap::new(chunk_params)?;

        // Get block boundaries
        let block_count = self.params.block_count as usize;

        for block_idx in 0..block_count {
            let block = chunk_map.extract_block(payload, block_idx as u32)?;

            // FEC encode this block
            let fec_params = FecParams::with_mtu(self.params.symbol_size as u16);
            let encoder = fec_encode(block, &fec_params);

            // Generate repair packets (1.5x overhead)
            let repair_count = self.params.total_symbols_per_block - self.params.source_symbols_per_block;
            let source_packets = encoder.source_packets();
            let repair_packets = encoder.repair_packets(repair_count);

            // Create frames for source symbols
            for (symbol_idx, packet) in source_packets.iter().enumerate() {
                let header = FrameHeader::new(
                    FrameType::Repair,
                    self.session_id,
                    block_idx as u32,
                    symbol_idx as u32,
                    &packet.data(),
                );
                let frame = Frame::build(&header, &packet.data(), &self.session_key);
                frames.push(PreparedFrame { frame });
            }

            // Create frames for repair symbols
            for (i, packet) in repair_packets.iter().enumerate() {
                let symbol_idx = self.params.source_symbols_per_block + i as u32;
                let header = FrameHeader::new(
                    FrameType::Repair,
                    self.session_id,
                    block_idx as u32,
                    symbol_idx,
                    &packet.data(),
                );
                let frame = Frame::build(&header, &packet.data(), &self.session_key);
                frames.push(PreparedFrame { frame });
            }
        }

        Ok(frames)
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Returns the session parameters.
    pub fn params(&self) -> &SessionParams {
        &self.params
    }

    /// Returns the QR frames as raw bytes (header + payload concatenated).
    pub fn encode_to_bytes(&self, payload: &[u8]) -> Result<Vec<Vec<u8>>, CodecError> {
        let frames = self.encode(payload)?;
        Ok(frames.iter().map(|f| f.frame.to_vec()).collect())
    }
}
