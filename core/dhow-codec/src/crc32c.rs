//! CRC32C (Castagnoli) integrity checks.
//!
//! Provides both one-shot and streaming CRC32C computation. CRC32C is used
//! for fast integrity checks in the frame header and session header.
//!
//! The polynomial used is Castagnoli (0x82F63B78 reversed), which provides
//! better error detection than standard CRC32 for small messages.

use crc32c::crc32c;

/// Computes the CRC32C checksum of the given data (one-shot).
///
/// This is the simplest interface for computing a CRC32C when the entire
/// input is available in memory.
pub fn crc32c_digest(data: &[u8]) -> u32 {
    crc32c(data)
}

/// A streaming CRC32C hasher.
///
/// Allows computing the CRC32C of data that arrives in chunks, without
/// needing to buffer the entire input.
#[derive(Debug, Clone)]
pub struct Crc32cHasher {
    state: u32,
}

impl Crc32cHasher {
    /// Creates a new CRC32C hasher.
    pub fn new() -> Self {
        Self { state: 0 }
    }

    /// Updates the hash with more data.
    pub fn update(&mut self, data: &[u8]) {
        self.state = crc32c_append(self.state, data);
    }

    /// Returns the final CRC32C checksum.
    pub fn finalize(self) -> u32 {
        self.state
    }
}

impl Default for Crc32cHasher {
    fn default() -> Self {
        Self::new()
    }
}

fn crc32c_append(state: u32, data: &[u8]) -> u32 {
    let mut crc = state ^ 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_known_answers() {
        assert_eq!(crc32c_digest(b""), 0);
        assert_eq!(crc32c_digest(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c_digest(b"Hello world!"), 0x7B98_E751);
    }

    #[test]
    fn test_crc32c_streaming_equals_one_shot() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let one_shot = crc32c_digest(&data);

        let mut hasher = Crc32cHasher::new();
        hasher.update(&data[..100]);
        hasher.update(&data[100..500]);
        hasher.update(&data[500..]);
        let streaming = hasher.finalize();

        assert_eq!(one_shot, streaming);
    }

    #[test]
    fn test_crc32c_streaming_empty() {
        let hasher = Crc32cHasher::new();
        let result = hasher.finalize();
        assert_eq!(result, crc32c_digest(b""));
    }

    #[test]
    fn test_crc32c_streaming_single_byte() {
        let mut hasher = Crc32cHasher::new();
        hasher.update(&[0x42]);
        let result = hasher.finalize();
        assert_eq!(result, crc32c_digest(&[0x42]));
    }

    #[test]
    fn test_crc32c_streaming_single_byte_incremental() {
        let mut hasher = Crc32cHasher::new();
        for i in 0..256u8 {
            hasher.update(&[i]);
        }
        let result = hasher.finalize();
        let data: Vec<u8> = (0..256).collect();
        assert_eq!(result, crc32c_digest(&data));
    }
}
