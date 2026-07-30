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
