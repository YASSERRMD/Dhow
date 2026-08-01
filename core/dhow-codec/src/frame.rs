//! Frame wire format (RFC-style binary framing).
//!
//! Implements the frame header and payload format described in `proto/frame.md`.
//! Each QR frame consists of a 46-byte fixed header followed by a variable-length
//! payload.
//!
//! ## Header Fields
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 4 | Magic ("DHOW") |
//! | 4 | 1 | Version (0x01) |
//! | 5 | 1 | Frame Type |
//! | 6 | 2 | Reserved |
//! | 8 | 16 | Session ID |
//! | 24 | 8 | Truncated MAC |
//! | 32 | 4 | Block Index |
//! | 36 | 4 | Symbol Index |
//! | 40 | 2 | Payload Length |
//! | 42 | 4 | CRC32C |
//! | 46 | var | Payload |
//!
//! ## Integrity
//!
//! Two integrity mechanisms protect each frame:
//!
//! - **MAC**: HMAC-BLAKE3(session_key, header_fields) truncated to 8 bytes.
//!   Verifies authenticity and binding to the session.
//! - **CRC32C**: CRC32C of the payload, covering detection of corruption
//!   in the payload field itself.
//!
//! # Example
//!
//! ```
//! use dhow_codec::frame::{Frame, FrameType, FrameHeader};
//!
//! let session_id = [0u8; 16];
//! let key = [0u8; 32];
//! let header = FrameHeader::new(FrameType::Repair, session_id, 0, 1, b"hello");
//! let frame = Frame::build(&header, b"hello", &key);
//! let bytes = frame.to_vec();
//!
//! let parsed = Frame::from_bytes(&bytes, &key).unwrap();
//! assert_eq!(parsed.payload(), b"hello");
//! ```

use crate::crc32c::crc32c_digest;
use crate::{FrameError};
use byteorder::{LittleEndian, WriteBytesExt};

/// Magic bytes for Dhow frames (ASCII "DHOW").
pub const MAGIC: [u8; 4] = *b"DHOW";

/// Supported protocol version.
pub const VERSION: u8 = 1;

/// Size of the fixed frame header in bytes.
pub const FRAME_HEADER_SIZE: usize = 46;

/// Maximum payload length per frame (u16::MAX).
pub const MAX_PAYLOAD_LEN: u16 = 65535;

/// Size of the truncated MAC in bytes.
pub const MAC_LEN: usize = 8;

/// Frame types as defined in proto/frame.md.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// Session header frame.
    Session = 0,
    /// RaptorQ repair symbol frame.
    Repair = 1,
    /// Manifest frame.
    Manifest = 2,
}

impl TryFrom<u8> for FrameType {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(FrameType::Session),
            1 => Ok(FrameType::Repair),
            2 => Ok(FrameType::Manifest),
            _ => Err(FrameError::UnknownFrameType { frame_type: value }),
        }
    }
}

/// Fixed-size frame header (46 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    magic: [u8; 4],
    version: u8,
    frame_type: FrameType,
    reserved: u16,
    session_id: [u8; 16],
    truncated_mac: [u8; 8],
    block_index: u32,
    symbol_index: u32,
    payload_length: u16,
    crc32c: u32,
}

impl FrameHeader {
    /// Creates a new frame header, computing the CRC32C automatically.
    pub fn new(
        frame_type: FrameType,
        session_id: [u8; 16],
        block_index: u32,
        symbol_index: u32,
        payload: &[u8],
    ) -> Self {
        assert!(payload.len() <= MAX_PAYLOAD_LEN as usize, "payload too large");
        let crc32c = crc32c_digest(payload);
        Self {
            magic: MAGIC,
            version: VERSION,
            frame_type,
            reserved: 0,
            session_id,
            truncated_mac: [0; 8],
            block_index,
            symbol_index,
            payload_length: payload.len() as u16,
            crc32c,
        }
    }

    /// Serializes the header to a 46-byte vector.
    /// The `truncated_mac` field must be set before serialization via `set_mac`.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);
        buf.push(self.frame_type as u8);
        buf.write_u16::<LittleEndian>(self.reserved).unwrap();
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.truncated_mac);
        buf.write_u32::<LittleEndian>(self.block_index).unwrap();
        buf.write_u32::<LittleEndian>(self.symbol_index).unwrap();
        buf.write_u16::<LittleEndian>(self.payload_length).unwrap();
        buf.write_u32::<LittleEndian>(self.crc32c).unwrap();
        debug_assert_eq!(buf.len(), FRAME_HEADER_SIZE);
        buf
    }

    /// Deserializes a header from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < FRAME_HEADER_SIZE {
            return Err(FrameError::HeaderTooShort { length: bytes.len() });
        }

        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        if magic != MAGIC {
            return Err(FrameError::InvalidMagic { got: magic });
        }

        let version = bytes[4];
        if version != VERSION {
            return Err(FrameError::UnsupportedVersion { version });
        }

        let frame_type = FrameType::try_from(bytes[5])?;

        let reserved = u16::from_le_bytes([bytes[6], bytes[7]]);
        if reserved != 0 {
            return Err(FrameError::ReservedFieldNonZero { value: reserved });
        }

        let session_id: [u8; 16] = bytes[8..24].try_into().unwrap();
        let truncated_mac: [u8; 8] = bytes[24..32].try_into().unwrap();
        let block_index = u32::from_le_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35],
        ]);
        let symbol_index = u32::from_le_bytes([
            bytes[36], bytes[37], bytes[38], bytes[39],
        ]);
        let payload_length = u16::from_le_bytes([bytes[40], bytes[41]]);
        let crc32c = u32::from_le_bytes([
            bytes[42], bytes[43], bytes[44], bytes[45],
        ]);

        if payload_length > MAX_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLarge { length: payload_length as u32 });
        }

        Ok(Self {
            magic,
            version,
            frame_type,
            reserved,
            session_id,
            truncated_mac,
            block_index,
            symbol_index,
            payload_length,
            crc32c,
        })
    }

    /// Sets the truncated MAC field.
    pub fn set_mac(&mut self, mac: [u8; 8]) {
        self.truncated_mac = mac;
    }

    /// Computes the HMAC-BLAKE3 MAC for this header.
    /// MAC = HMAC-BLAKE3(session_key, magic || version || frame_type ||
    ///       session_id || block_index || symbol_index || payload_length)
    pub fn compute_mac(&self, session_key: &[u8; 32]) -> [u8; 8] {
        let mut h = blake3::Hasher::new_keyed(session_key);
        h.update(&self.magic);
        h.update(&[self.version]);
        h.update(&[self.frame_type as u8]);
        h.update(&self.session_id);
        // Write block_index and symbol_index as LE bytes
        let block_bytes = self.block_index.to_le_bytes();
        let symbol_bytes = self.symbol_index.to_le_bytes();
        h.update(&block_bytes);
        h.update(&symbol_bytes);
        let plen_bytes = self.payload_length.to_le_bytes();
        h.update(&plen_bytes);
        let full = h.finalize();
        let mut mac = [0u8; 8];
        mac.copy_from_slice(&full.as_bytes()[..8]);
        mac
    }

    pub fn magic(&self) -> [u8; 4] { self.magic }
    pub fn version(&self) -> u8 { self.version }
    /// Returns the frame type.
    pub fn frame_type(&self) -> FrameType { self.frame_type }
    pub fn session_id(&self) -> [u8; 16] { self.session_id }
    pub fn truncated_mac(&self) -> [u8; 8] { self.truncated_mac }
    pub fn block_index(&self) -> u32 { self.block_index }
    pub fn symbol_index(&self) -> u32 { self.symbol_index }
    pub fn payload_length(&self) -> u16 { self.payload_length }
    pub fn crc32c(&self) -> u32 { self.crc32c }

    /// Returns the frame type as a raw u8.
    pub fn frame_type_raw(&self) -> u8 {
        self.frame_type as u8
    }

    /// Returns the reserved field value.
    pub fn reserved(&self) -> u16 {
        self.reserved
    }
}

/// A complete frame: header + payload.
#[derive(Debug, Clone)]
pub struct Frame {
    header: FrameHeader,
    payload: Vec<u8>,
}

impl Frame {
    /// Builds a frame, computing the MAC using the session key.
    pub fn build(header: &FrameHeader, payload: &[u8], session_key: &[u8; 32]) -> Self {
        let mac = header.compute_mac(session_key);
        let mut h = header.clone();
        h.set_mac(mac);
        Self {
            header: h,
            payload: payload.to_vec(),
        }
    }

    /// Serializes the entire frame (header + payload) to a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = self.header.to_vec();
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parses a frame from bytes, verifying the MAC and CRC32C.
    pub fn from_bytes(bytes: &[u8], session_key: &[u8; 32]) -> Result<Self, FrameError> {
        let header = FrameHeader::from_bytes(bytes)?;

        // Verify MAC
        let expected_mac = header.compute_mac(session_key);
        if header.truncated_mac() != expected_mac {
            return Err(FrameError::MacVerificationFailed);
        }

        // Verify payload length
        if bytes.len() < FRAME_HEADER_SIZE + header.payload_length() as usize {
            return Err(FrameError::Truncated {
                expected: FRAME_HEADER_SIZE + header.payload_length() as usize,
                actual: bytes.len(),
            });
        }

        let payload = bytes[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + header.payload_length() as usize].to_vec();

        // Verify CRC32C
        let actual_crc = crc32c_digest(&payload);
        if actual_crc != header.crc32c() {
            return Err(FrameError::CrcMismatch {
                expected: header.crc32c(),
                actual: actual_crc,
            });
        }

        Ok(Self { header, payload })
    }

    pub fn header(&self) -> &FrameHeader { &self.header }
    pub fn payload(&self) -> &[u8] { &self.payload }
}
