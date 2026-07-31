//! BLAKE3 cryptographic hashing.
//!
//! Provides both one-shot and streaming BLAKE3 computation. BLAKE3 is used
//! for per-block decode verification and whole-payload integrity in the
//! signed manifest.
//!
//! BLAKE3 produces 32-byte (256-bit) digests.

/// The length of a BLAKE3 digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// Computes the BLAKE3 digest of the given data (one-shot).
///
/// Returns a 32-byte digest.
pub fn blake3_digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let hash = blake3::hash(data);
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// A streaming BLAKE3 hasher.
///
/// Allows computing the BLAKE3 digest of data that arrives in chunks,
/// without needing to buffer the entire input.
#[derive(Debug, Clone)]
pub struct Blake3Hasher {
    state: blake3::Hasher,
}

impl Blake3Hasher {
    /// Creates a new BLAKE3 hasher.
    pub fn new() -> Self {
        Self {
            state: blake3::Hasher::new(),
        }
    }

    /// Updates the hash with more data.
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// Returns the final BLAKE3 digest.
    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        let hash = self.state.finalize();
        let mut out = [0u8; DIGEST_LEN];
        out.copy_from_slice(hash.as_bytes());
        out
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; DIGEST_LEN] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn test_blake3_known_answers() {
        assert_eq!(
            blake3_digest(b""),
            hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        );
        assert_eq!(
            blake3_digest(b"123456789"),
            hex("b7d65b48420d1033cb2595293263b6f72eabee20d55e699d0df1973b3c9deed1")
        );
        assert_eq!(
            blake3_digest(b"Hello world!"),
            hex("793c10bc0b28c378330d39edace7260af9da81d603b8ffede2706a21eda893f4")
        );
    }

    #[test]
    fn test_blake3_streaming_equals_one_shot() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let one_shot = blake3_digest(&data);

        let mut hasher = Blake3Hasher::new();
        hasher.update(&data[..100]);
        hasher.update(&data[100..500]);
        hasher.update(&data[500..]);
        let streaming = hasher.finalize();

        assert_eq!(one_shot, streaming);
    }

    #[test]
    fn test_blake3_streaming_empty() {
        let hasher = Blake3Hasher::new();
        let result = hasher.finalize();
        assert_eq!(result, blake3_digest(b""));
    }

    #[test]
    fn test_blake3_streaming_single_byte() {
        let mut hasher = Blake3Hasher::new();
        hasher.update(&[0x42]);
        let result = hasher.finalize();
        assert_eq!(result, blake3_digest(&[0x42]));
    }
}
