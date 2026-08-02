//! Frame assembly and reassembly pipeline.
//!
//! The sending half ([`Pipeline`]) turns payload bytes into QR-ready frames.
//! The receiving half ([`PipelineDecoder`]) turns frames back into the payload.
//!
//! # Sending
//!
//! 1. Chunk the payload into source blocks.
//! 2. Encode each block with RaptorQ, producing source and repair symbols.
//! 3. Wrap every symbol in a session-bound, MAC'd, CRC'd frame.
//!
//! # Receiving
//!
//! 1. Parse and authenticate each frame (MAC, CRC, session binding).
//! 2. Feed its symbol into the RaptorQ decoder for the frame's block.
//! 3. Once every block decodes, reassemble and verify the payload digest.
//!
//! # Symbol framing
//!
//! A frame payload is a serialized RaptorQ [`EncodingPacket`]: a 4-byte
//! `PayloadId` followed by the symbol data. The `PayloadId` is what lets the
//! receiver place a symbol within its block, so it travels with the symbol
//! rather than being reconstructed from the frame header. The header's
//! `symbol_index` is transmission bookkeeping (which symbol of the block this
//! is, for progress and de-duplication); RaptorQ's own identifier is
//! authoritative for decoding.
//!
//! # Example
//!
//! ```
//! use dhow_codec::pipeline::{Pipeline, PipelineDecoder};
//! use dhow_codec::session::{SessionParams, RaptorQParams};
//! use dhow_codec::blake3::blake3_digest;
//!
//! let payload = b"Hello, Dhow!";
//! let params = SessionParams {
//!     payload_size: payload.len() as u64,
//!     block_count: 1,
//!     symbol_size: 64,
//!     source_symbols_per_block: 1,
//!     total_symbols_per_block: 4,
//!     raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
//!     payload_digest: blake3_digest(payload),
//! };
//!
//! let pipeline = Pipeline::new([7u8; 16], params, [0xAB; 32]).unwrap();
//! let frames = pipeline.encode_to_bytes(payload).unwrap();
//!
//! let mut decoder = PipelineDecoder::new([7u8; 16], params, [0xAB; 32]).unwrap();
//! for frame in &frames {
//!     decoder.accept(frame).unwrap();
//! }
//! assert_eq!(decoder.finish().unwrap(), payload);
//! ```

use crate::blake3::blake3_digest;
use crate::chunker::{ChunkMap, ChunkParams};
use crate::frame::{FRAME_HEADER_SIZE, Frame, FrameHeader, FrameType, MAX_PAYLOAD_LEN};
use crate::session::SessionParams;
use crate::{CodecError, FecError, FrameError, SessionError};
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};

/// The session key used for frame MAC computation.
pub type SessionKey = [u8; 32];

/// Bytes a serialized RaptorQ `PayloadId` prepends to each symbol.
pub const PAYLOAD_ID_LEN: usize = 4;

/// Smallest symbol size RaptorQ will accept as a transmission unit.
pub const MIN_FEC_SYMBOL_SIZE: u32 = 64;

/// Largest symbol size that still fits a frame payload alongside its
/// `PayloadId`.
pub const MAX_FEC_SYMBOL_SIZE: u32 = MAX_PAYLOAD_LEN as u32 - PAYLOAD_ID_LEN as u32;

/// A single frame ready for QR encoding.
pub struct PreparedFrame {
    /// The complete frame (header + payload).
    pub frame: Frame,
}

/// Validates the session parameters this pipeline depends on.
///
/// Both the encoder and the decoder must agree on these bounds, so the check
/// lives in one place and is applied on both sides. Out-of-range values return
/// a typed error rather than panicking inside RaptorQ.
fn validate_params(params: &SessionParams) -> Result<(), CodecError> {
    params.validate()?;

    if !(MIN_FEC_SYMBOL_SIZE..=MAX_FEC_SYMBOL_SIZE).contains(&params.symbol_size) {
        return Err(SessionError::InvalidParameters {
            details: format!(
                "symbol_size {} out of range {}..={}",
                params.symbol_size, MIN_FEC_SYMBOL_SIZE, MAX_FEC_SYMBOL_SIZE
            ),
        }
        .into());
    }

    Ok(())
}

/// Builds the chunk map implied by the session parameters.
///
/// The map is derived, never transmitted: sender and receiver compute the same
/// block layout from the same parameters.
fn chunk_map_for(params: &SessionParams) -> Result<ChunkMap, CodecError> {
    let chunk_params =
        ChunkParams::new(params.payload_size, params.block_count, params.symbol_size)?;
    Ok(ChunkMap::new(chunk_params)?)
}

/// Returns the RaptorQ configuration for a block of `block_size` bytes.
///
/// This mirrors what `Encoder::with_defaults` derives internally, which is how
/// the receiver rebuilds the encoder's configuration without it being sent.
fn config_for_block(block_size: u64, symbol_size: u32) -> ObjectTransmissionInformation {
    ObjectTransmissionInformation::with_defaults(block_size, symbol_size as u16)
}

/// Converts a payload into session-bound frames.
pub struct Pipeline {
    session_id: [u8; 16],
    params: SessionParams,
    session_key: SessionKey,
    chunk_map: ChunkMap,
}

impl Pipeline {
    /// Creates a pipeline, validating the session parameters up front.
    pub fn new(
        session_id: [u8; 16],
        params: SessionParams,
        session_key: SessionKey,
    ) -> Result<Self, CodecError> {
        validate_params(&params)?;
        let chunk_map = chunk_map_for(&params)?;
        Ok(Self {
            session_id,
            params,
            session_key,
            chunk_map,
        })
    }

    /// Encodes a payload into frames covering every block.
    ///
    /// Each block yields its source symbols followed by
    /// `total_symbols_per_block - source_symbols_per_block` repair symbols.
    pub fn encode(&self, payload: &[u8]) -> Result<Vec<PreparedFrame>, CodecError> {
        if payload.len() as u64 != self.params.payload_size {
            return Err(SessionError::InvalidParameters {
                details: format!(
                    "payload is {} bytes but session declares {}",
                    payload.len(),
                    self.params.payload_size
                ),
            }
            .into());
        }

        let repair_count = self
            .params
            .total_symbols_per_block
            .saturating_sub(self.params.source_symbols_per_block);

        let mut frames = Vec::new();

        for block in &self.chunk_map.blocks {
            // A zero-length block carries nothing; RaptorQ cannot encode it.
            if block.size == 0 {
                continue;
            }

            let block_bytes = self.chunk_map.extract_block(payload, block.index)?;
            let encoder = Encoder::new(
                block_bytes,
                config_for_block(block.size, self.params.symbol_size),
            );

            // One call returns the source symbols followed by the requested
            // repair symbols. Calling separately would re-emit the source set.
            for (symbol_index, packet) in
                encoder.get_encoded_packets(repair_count).iter().enumerate()
            {
                let serialized = packet.serialize();
                if serialized.len() > MAX_PAYLOAD_LEN as usize {
                    return Err(CodecError::FramePayloadTooLarge {
                        length: serialized.len(),
                        max: MAX_PAYLOAD_LEN as usize,
                    });
                }

                let header = FrameHeader::new(
                    FrameType::Repair,
                    self.session_id,
                    block.index,
                    symbol_index as u32,
                    &serialized,
                );
                frames.push(PreparedFrame {
                    frame: Frame::build(&header, &serialized, &self.session_key),
                });
            }
        }

        Ok(frames)
    }

    /// Encodes a payload and serializes each frame to bytes.
    pub fn encode_to_bytes(&self, payload: &[u8]) -> Result<Vec<Vec<u8>>, CodecError> {
        Ok(self
            .encode(payload)?
            .iter()
            .map(|f| f.frame.to_vec())
            .collect())
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Returns the session parameters.
    pub fn params(&self) -> &SessionParams {
        &self.params
    }

    /// Returns the block layout this pipeline encodes against.
    pub fn chunk_map(&self) -> &ChunkMap {
        &self.chunk_map
    }
}

/// What a decoder did with an accepted frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOutcome {
    /// The symbol was added to a block that still needs more symbols.
    Accepted,
    /// The symbol completed its block.
    BlockComplete {
        /// Index of the block that just finished decoding.
        block_index: u32,
    },
    /// The symbol belonged to a block that had already decoded.
    Redundant,
}

/// Per-block decode progress.
enum BlockState {
    /// Still collecting symbols.
    Pending(Box<Decoder>),
    /// Decoded to its original bytes.
    Done(Vec<u8>),
}

/// Reassembles a payload from frames arriving in any order.
///
/// Every frame is treated as hostile input: frames are authenticated before
/// their contents are used, symbols from other sessions are discarded, and
/// malformed symbol payloads are rejected with typed errors rather than
/// reaching RaptorQ, which indexes its input unchecked.
pub struct PipelineDecoder {
    session_id: [u8; 16],
    params: SessionParams,
    session_key: SessionKey,
    chunk_map: ChunkMap,
    blocks: Vec<BlockState>,
}

impl PipelineDecoder {
    /// Creates a decoder for a session, validating its parameters.
    pub fn new(
        session_id: [u8; 16],
        params: SessionParams,
        session_key: SessionKey,
    ) -> Result<Self, CodecError> {
        validate_params(&params)?;
        let chunk_map = chunk_map_for(&params)?;

        let blocks = chunk_map
            .blocks
            .iter()
            .map(|block| {
                if block.size == 0 {
                    // An empty block is complete on arrival.
                    BlockState::Done(Vec::new())
                } else {
                    BlockState::Pending(Box::new(Decoder::new(config_for_block(
                        block.size,
                        params.symbol_size,
                    ))))
                }
            })
            .collect();

        Ok(Self {
            session_id,
            params,
            session_key,
            chunk_map,
            blocks,
        })
    }

    /// Parses, authenticates, and consumes one serialized frame.
    ///
    /// Returns an error for any frame that fails authentication, belongs to
    /// another session, or carries a malformed symbol. The decoder's state is
    /// unchanged when an error is returned, so a rejected frame cannot poison
    /// an in-progress decode.
    pub fn accept(&mut self, bytes: &[u8]) -> Result<FrameOutcome, CodecError> {
        // Verifies magic, version, MAC, declared length, and CRC.
        let frame = Frame::from_bytes(bytes, &self.session_key)?;
        let header = frame.header();

        if header.session_id() != self.session_id {
            return Err(FrameError::SessionMismatch {
                expected: self.session_id,
                actual: header.session_id(),
            }
            .into());
        }

        if header.frame_type() != FrameType::Repair {
            return Err(FrameError::UnknownFrameType {
                frame_type: header.frame_type_raw(),
            }
            .into());
        }

        let block_index = header.block_index();
        let state =
            self.blocks
                .get_mut(block_index as usize)
                .ok_or(FrameError::SessionMismatch {
                    expected: self.session_id,
                    actual: header.session_id(),
                })?;

        let BlockState::Pending(decoder) = state else {
            return Ok(FrameOutcome::Redundant);
        };

        // RaptorQ's deserializer indexes the first four bytes unchecked, so a
        // short payload would panic. Reject it here instead.
        let payload = frame.payload();
        if payload.len() <= PAYLOAD_ID_LEN {
            return Err(FecError::InvalidSourceBlock {
                details: format!(
                    "symbol payload is {} bytes, need more than {}",
                    payload.len(),
                    PAYLOAD_ID_LEN
                ),
            }
            .into());
        }

        decoder.add_new_packet(EncodingPacket::deserialize(payload));

        match decoder.get_result() {
            Some(data) => {
                self.blocks[block_index as usize] = BlockState::Done(data);
                Ok(FrameOutcome::BlockComplete { block_index })
            }
            None => Ok(FrameOutcome::Accepted),
        }
    }

    /// Returns true once every block has decoded.
    pub fn is_complete(&self) -> bool {
        self.blocks.iter().all(|b| matches!(b, BlockState::Done(_)))
    }

    /// Returns the number of blocks that have decoded.
    pub fn blocks_complete(&self) -> u32 {
        self.blocks
            .iter()
            .filter(|b| matches!(b, BlockState::Done(_)))
            .count() as u32
    }

    /// Reassembles the payload and verifies it against the session digest.
    ///
    /// Fails if any block is still outstanding, or if the reassembled bytes do
    /// not match the digest the sender committed to. Payload bytes are never
    /// returned unverified.
    pub fn finish(&self) -> Result<Vec<u8>, CodecError> {
        let mut blocks = Vec::with_capacity(self.blocks.len());
        for (index, state) in self.blocks.iter().enumerate() {
            match state {
                BlockState::Done(data) => blocks.push(data.as_slice()),
                BlockState::Pending(_) => {
                    return Err(SessionError::InvalidParameters {
                        details: format!("block {index} is not yet decoded"),
                    }
                    .into());
                }
            }
        }

        let payload = self.chunk_map.reassemble(&blocks)?;

        if blake3_digest(&payload) != self.params.payload_digest {
            return Err(SessionError::DigestMismatch.into());
        }

        Ok(payload)
    }

    /// Returns the session ID this decoder accepts frames for.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Returns the session parameters.
    pub fn params(&self) -> &SessionParams {
        &self.params
    }
}

/// Returns true if a byte slice is long enough to hold a frame header.
///
/// Useful as a cheap pre-filter before a full parse attempt.
pub fn is_plausible_frame(bytes: &[u8]) -> bool {
    bytes.len() >= FRAME_HEADER_SIZE
}
