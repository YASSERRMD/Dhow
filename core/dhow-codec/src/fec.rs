//! RaptorQ (RFC 6330) forward error correction.
//!
//! Provides encoding of payload data into source and repair symbols,
//! and decoding from any sufficient subset of received symbols.
//!
//! This is the core FEC primitive that allows Dhow to recover from
//! packet loss during transmission.
//!
//! # Example
//!
//! ```
//! use dhow_codec::fec::{FecParams, encode, decode};
//!
//! let data = b"Hello, Dhow!".to_vec();
//! let params = FecParams::new();
//! let encoder = encode(&data, &params);
//! let config = encoder.config();
//! let packets = encoder.packets(10);
//!
//! let decoded = decode(&packets, &config);
//! assert_eq!(decoded.unwrap(), data);
//! ```

use raptorq::{Decoder, Encoder};

/// Default maximum packet size for FEC encoding.
pub const DEFAULT_MTU: u16 = 1024;

/// Parameters for FEC encoding/decoding.
#[derive(Debug, Clone)]
pub struct FecParams {
    /// Maximum packet size in bytes (MTU).
    mtu: u16,
}

impl FecParams {
    /// Creates FEC parameters with the default MTU.
    pub fn new() -> Self {
        Self {
            mtu: DEFAULT_MTU,
        }
    }

    /// Creates FEC parameters with a custom MTU.
    ///
    /// The MTU must be at least 64 bytes.
    pub fn with_mtu(mtu: u16) -> Self {
        assert!(mtu >= 64, "MTU must be at least 64");
        Self { mtu }
    }

    /// Returns the MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
}

impl Default for FecParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes data into source and repair packets.
pub fn encode(data: &[u8], params: &FecParams) -> EncoderWrapper {
    let encoder = Encoder::with_defaults(data, params.mtu);
    EncoderWrapper {
        inner: encoder,
        params: params.clone(),
    }
}

/// Wrapper around the raptorq Encoder.
pub struct EncoderWrapper {
    inner: Encoder,
    params: FecParams,
}

impl EncoderWrapper {
    /// Returns the encoding configuration.
    pub fn config(&self) -> raptorq::ObjectTransmissionInformation {
        self.inner.get_config()
    }

    /// Returns source and repair packets.
    ///
    /// The number of repair packets per block is specified by
    /// `repair_packets_per_block`.
    pub fn packets(&self, repair_packets_per_block: u32) -> Vec<raptorq::EncodingPacket> {
        self.inner.get_encoded_packets(repair_packets_per_block)
    }

    /// Returns only source packets (no repair).
    pub fn source_packets(&self) -> Vec<raptorq::EncodingPacket> {
        self.inner.get_encoded_packets(0)
    }

    /// Returns only repair packets.
    pub fn repair_packets(&self, count: u32) -> Vec<raptorq::EncodingPacket> {
        self.inner.get_encoded_packets(count)
    }

    /// Convenience: generate enough repair packets to recover from
    /// up to `loss_rate` fraction of packet loss.
    pub fn repair_packets_for_loss_rate(&self, loss_rate: f64) -> Vec<raptorq::EncodingPacket> {
        let source_count = self.source_packets().len() as f64;
        let repair_count = (source_count * loss_rate).ceil() as u32;
        self.repair_packets(repair_count)
    }
}

/// Decodes packets back into the original payload.
pub fn decode(packets: &[raptorq::EncodingPacket], config: &raptorq::ObjectTransmissionInformation) -> Option<Vec<u8>> {
    let mut decoder = Decoder::new(*config);
    for packet in packets {
        decoder.add_new_packet(packet.clone());
    }
    decoder.get_result()
}
