//! Round-trip integrity tests for CRC32C and BLAKE3.
//!
//! Verifies that one-shot and streaming implementations agree across
//! multiple chunking strategies, and that digests are deterministic
//! and fixed-length.

#[cfg(test)]
mod tests {
    use crate::blake3::{blake3_digest, Blake3Hasher, DIGEST_LEN};
    use crate::crc32c::{crc32c_digest, Crc32cHasher};

    #[test]
    fn test_crc32c_round_trip_deterministic() {
        let data = b"integrity payload for round-trip testing";
        let h1 = crc32c_digest(data);
        let h2 = crc32c_digest(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_blake3_round_trip_deterministic() {
        let data = b"integrity payload for round-trip testing";
        let h1 = blake3_digest(data);
        let h2 = blake3_digest(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_crc32c_streaming_chunked() {
        let data: Vec<u8> = (0..5000).map(|i| (i * 7) as u8).collect();

        let one_shot = crc32c_digest(&data);

        let mut hasher = Crc32cHasher::new();
        for chunk in data.chunks(7) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), one_shot);
    }

    #[test]
    fn test_blake3_streaming_chunked() {
        let data: Vec<u8> = (0..5000).map(|i| (i * 7) as u8).collect();

        let one_shot = blake3_digest(&data);

        let mut hasher = Blake3Hasher::new();
        for chunk in data.chunks(13) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), one_shot);
    }

    #[test]
    fn test_blake3_digest_length() {
        let digest = blake3_digest(b"test");
        assert_eq!(digest.len(), DIGEST_LEN);
    }

    #[test]
    fn test_crc32c_and_blake3_different_inputs() {
        let data1 = b"first payload";
        let data2 = b"second payload";

        assert_ne!(crc32c_digest(data1), crc32c_digest(data2));
        assert_ne!(blake3_digest(data1), blake3_digest(data2));
    }
}
