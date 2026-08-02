//! HKDF over BLAKE3.
//!
//! Every key Dhow uses on the wire is derived from the shared operator key
//! rather than being the operator key. A fresh random salt per transfer means
//! two transfers between the same pair of operators share no key material, so
//! a compromise of one session's keys does not extend to any other session.
//!
//! # Construction
//!
//! This is RFC 5869 HKDF with BLAKE3's keyed hash as the PRF:
//!
//! ```text
//! PRK      = BLAKE3_keyed(salt, ikm)
//! T(0)     = ""
//! T(i)     = BLAKE3_keyed(PRK, T(i-1) || info || i)
//! OKM      = T(1) || T(2) || ...
//! ```
//!
//! BLAKE3's keyed mode is a PRF over a 32-byte key, which is what HKDF asks of
//! its underlying primitive. The salt is a full 32 bytes so it can be used
//! directly as the extract key without the padding step HMAC would need.
//!
//! Distinct `info` strings give independent keys from one extract step, which
//! is how the payload key and the frame session key are kept separate: neither
//! can be computed from the other.

use crate::AeadError;
use zeroize::Zeroize;

/// Length of a derivation salt in bytes.
pub const SALT_LEN: usize = 32;

/// Maximum bytes obtainable from a single expand, as HKDF allows 255 blocks.
pub const MAX_OKM_LEN: usize = 255 * 32;

/// Domain separation string for the payload encryption key.
pub const INFO_PAYLOAD_KEY: &[u8] = b"dhow v1 payload encryption key";

/// Domain separation string for the frame MAC session key.
pub const INFO_SESSION_KEY: &[u8] = b"dhow v1 frame session key";

/// A per-transfer derivation salt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Salt([u8; SALT_LEN]);

impl Salt {
    /// Draws a fresh salt from the system CSPRNG.
    pub fn generate() -> Result<Self, AeadError> {
        let mut bytes = [0u8; SALT_LEN];
        getrandom::fill(&mut bytes).map_err(|e| AeadError::KeyDerivationFailed {
            details: format!("system randomness unavailable: {e}"),
        })?;
        Ok(Self(bytes))
    }

    /// Wraps existing salt bytes, as read from a manifest.
    pub fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the salt bytes. A salt is public and travels in the manifest.
    pub fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The salt is not secret, but printing it wholesale in logs is noise
        // and invites confusion with key material.
        write!(f, "Salt({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// Performs the HKDF extract step, returning a pseudorandom key.
fn extract(salt: &Salt, ikm: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(salt.as_bytes(), ikm).as_bytes()
}

/// Performs the HKDF expand step.
///
/// Returns an error when more output is requested than the 255-block limit
/// allows, rather than silently truncating or wrapping the block counter.
fn expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Result<Vec<u8>, AeadError> {
    if out_len > MAX_OKM_LEN {
        return Err(AeadError::KeyDerivationFailed {
            details: format!("requested {out_len} bytes, maximum is {MAX_OKM_LEN}"),
        });
    }

    let mut okm = Vec::with_capacity(out_len);
    let mut previous: Vec<u8> = Vec::new();

    // Counters run 1..=255. Iterating over that range rather than incrementing
    // past the last block keeps the u8 from overflowing on a full-length
    // derivation, and the length check above guarantees the range suffices.
    for counter in 1u8..=255 {
        if okm.len() >= out_len {
            break;
        }

        let mut hasher = blake3::Hasher::new_keyed(prk);
        hasher.update(&previous);
        hasher.update(info);
        hasher.update(&[counter]);
        let block = *hasher.finalize().as_bytes();

        let take = (out_len - okm.len()).min(block.len());
        okm.extend_from_slice(&block[..take]);

        previous.zeroize();
        previous = block.to_vec();
    }

    previous.zeroize();
    Ok(okm)
}

/// Derives `out_len` bytes of key material from input keying material.
///
/// `info` separates domains: two calls differing only in `info` produce
/// independent outputs.
pub fn derive(salt: &Salt, ikm: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, AeadError> {
    let mut prk = extract(salt, ikm);
    let result = expand(&prk, info, out_len);
    prk.zeroize();
    result
}

/// Derives exactly 32 bytes, the size of every key Dhow derives.
pub fn derive_key(salt: &Salt, ikm: &[u8], info: &[u8]) -> Result<[u8; 32], AeadError> {
    let bytes = derive(salt, ikm, info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}
