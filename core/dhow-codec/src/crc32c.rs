//! CRC32C (Castagnoli) integrity checks.
//!
//! Provides both one-shot and streaming CRC32C computation. CRC32C is used
//! for fast integrity checks in the frame header and session header.
//!
//! The polynomial used is Castagnoli (0x82F63B78 reflected), which provides
//! better error detection than standard CRC32 for small messages.
//!
//! # Algorithm
//!
//! Slicing-by-eight: eight precomputed 256-entry tables, consuming eight bytes
//! per iteration. All eight are generated at compile time by a `const fn`, the
//! first by the standard bit-by-bit algorithm and the rest derived from it.
//!
//! The obvious byte-at-a-time table was what shipped until Phase 31, when a
//! benchmark measured it at 513 MiB/s against BLAKE3's 2.1 GiB/s. A CRC whose
//! whole job is to be the cheap check *before* the cryptographic one, running
//! four times slower than the cryptographic one, is not doing that job: it was
//! the single largest per-frame cost in the encoder, ahead of the keyed MAC it
//! precedes.
//!
//! Slicing-by-eight is the standard answer and needs no `unsafe` and no
//! dependency, which matters because this crate is `#![forbid(unsafe_code)]`
//! and a hardware CRC intrinsic would need one or the other. The output is
//! unchanged by construction, and the golden vectors in `proto/vectors.json`
//! would catch it if it were not.
//!
//! # Parameters
//!
//! - Polynomial: 0x104C11DB7 (normal), 0x82F63B78 (reflected)
//! - Initial value: 0xFFFFFFFF
//! - Final XOR: 0xFFFFFFFF
//! - Reflect input: true
//! - Reflect output: true
//!
//! # Example
//!
//! ```
//! use dhow_codec::crc32c::crc32c_digest;
//! assert_eq!(crc32c_digest(b"123456789"), 0xE3069283);
//! assert_eq!(crc32c_digest(b"Hello world!"), 0x7B98E751);
//! ```

const CRC32C_POLY: u32 = 0x82F63B78;

const fn make_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut n = 0u32;
    while n < 256 {
        let mut crc = n;
        let mut i = 0u32;
        while i < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32C_POLY;
            } else {
                crc >>= 1;
            }
            i += 1;
        }
        t[n as usize] = crc;
        n += 1;
    }
    t
}

/// Derives the eight slicing tables from the byte-at-a-time one.
///
/// Table `k` answers "what does this byte contribute after `k` more bytes have
/// been shifted through", which is what lets eight bytes be folded in at once.
const fn make_slicing_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    tables[0] = make_table();

    let mut k = 1;
    while k < 8 {
        let mut n = 0;
        while n < 256 {
            let previous = tables[k - 1][n];
            tables[k][n] = (previous >> 8) ^ tables[0][(previous & 0xFF) as usize];
            n += 1;
        }
        k += 1;
    }
    tables
}

const CRC_TABLES: [[u32; 256]; 8] = make_slicing_tables();
const CRC_TABLE: [u32; 256] = CRC_TABLES[0];

/// Folds `data` into a running CRC state.
///
/// The state here is the raw register, without the initial or final inversion;
/// both callers apply those themselves.
fn fold(mut crc: u32, data: &[u8]) -> u32 {
    let mut rest = data;

    // Eight at a time while there are eight to take.
    while rest.len() >= 8 {
        let (chunk, tail) = rest.split_at(8);
        rest = tail;

        // The first four bytes are folded into the register; the second four
        // index their own tables directly. This is what makes the eight
        // independent of each other, and therefore pipelineable.
        crc ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

        crc = CRC_TABLES[7][(crc & 0xFF) as usize]
            ^ CRC_TABLES[6][((crc >> 8) & 0xFF) as usize]
            ^ CRC_TABLES[5][((crc >> 16) & 0xFF) as usize]
            ^ CRC_TABLES[4][((crc >> 24) & 0xFF) as usize]
            ^ CRC_TABLES[3][chunk[4] as usize]
            ^ CRC_TABLES[2][chunk[5] as usize]
            ^ CRC_TABLES[1][chunk[6] as usize]
            ^ CRC_TABLES[0][chunk[7] as usize];
    }

    // The tail, byte at a time.
    for &byte in rest {
        crc = CRC_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// Computes the CRC32C checksum of the given data (one-shot).
///
/// This is the simplest interface for computing a CRC32C when the entire
/// input is available in memory.
pub fn crc32c_digest(data: &[u8]) -> u32 {
    fold(0xFFFFFFFF, data) ^ 0xFFFFFFFF
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
    fold(state ^ 0xFFFFFFFF, data) ^ 0xFFFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_crc32c_known_answers() {
        assert_eq!(crc32c_digest(b""), 0);
        assert_eq!(crc32c_digest(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c_digest(b"Hello world!"), 0x7B98_E751);
        assert_eq!(crc32c_digest(b"a"), 0xC1D0_4330);
        assert_eq!(crc32c_digest(b"\x00"), 0x527D_5351);
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
        for i in 0..=255u8 {
            hasher.update(&[i]);
        }
        let result = hasher.finalize();
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(result, crc32c_digest(&data));
    }

    #[test]
    fn test_crc32c_streaming_empty_update() {
        let data = b"test data for empty update";
        let one_shot = crc32c_digest(data);
        let mut hasher = Crc32cHasher::new();
        hasher.update(&[]);
        hasher.update(data);
        hasher.update(&[]);
        assert_eq!(hasher.finalize(), one_shot);
    }

    #[test]
    fn test_crc32c_large_input_consistency() {
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let one_shot = crc32c_digest(&data);
        let mut hasher = Crc32cHasher::new();
        for chunk in data.chunks(997) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), one_shot);
    }

    proptest! {
        #[test]
        fn prop_crc32c_streaming_arbitrary_chunks(
            data in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..1000usize),
            chunk_size in 1usize..=100
        ) {
            let one_shot = crc32c_digest(&data);
            let mut hasher = Crc32cHasher::new();
            for chunk in data.chunks(chunk_size) {
                hasher.update(chunk);
            }
            prop_assert_eq!(hasher.finalize(), one_shot);
        }
    }
}
