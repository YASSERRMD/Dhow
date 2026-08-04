//! Payload encryption with XChaCha20-Poly1305.
//!
//! The whole payload is encrypted and authenticated before it is chunked, so
//! every byte that reaches the optical channel is ciphertext. The channel is
//! treated as fully public: anyone may photograph the screen, and doing so must
//! reveal nothing beyond the payload's length.
//!
//! # Keys
//!
//! Nothing here takes the operator key directly. A transfer draws a random
//! salt, derives a payload key and a frame session key from the operator key
//! through [`crate::kdf`], and uses those. The salt travels in the manifest,
//! so a receiver holding the same operator key can repeat the derivation while
//! an observer cannot.
//!
//! # Nonces
//!
//! XChaCha20's nonce is 192 bits, which is wide enough to choose at random per
//! transfer without tracking a counter across sessions. The nonce travels in
//! the manifest alongside the salt.
//!
//! Reusing a nonce with the same key is catastrophic for a stream cipher, so
//! the salt and nonce are drawn together in [`TransferSecrets::generate`] and
//! a fresh salt alone would be enough to make each transfer's key unique.
//!
//! # Associated data
//!
//! The session ID is authenticated as associated data. Ciphertext captured
//! from one session therefore fails to decrypt if replayed into another, even
//! if an attacker can induce the same key and nonce.

use crate::AeadError;
use crate::kdf::{INFO_PAYLOAD_KEY, INFO_SESSION_KEY, Salt, derive_key};
use crate::key::OperatorKey;
use chacha20poly1305::aead::{Aead, AeadInOut, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroize;

/// Length of an XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 24;

/// Length of the Poly1305 authentication tag appended to every ciphertext.
pub const TAG_LEN: usize = 16;

/// A per-transfer XChaCha20 nonce.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Draws a fresh nonce from the system CSPRNG.
    pub fn generate() -> Result<Self, AeadError> {
        let mut bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut bytes).map_err(|e| AeadError::InvalidNonce {
            details: format!("system randomness unavailable: {e}"),
        })?;
        Ok(Self(bytes))
    }

    /// Wraps existing nonce bytes, as read from a manifest.
    pub fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce bytes. A nonce is public and travels in the manifest.
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// The keys a single transfer uses, derived from the operator key.
///
/// Zeroized on drop; `Debug` omits the key bytes.
pub struct TransferKeys {
    payload_key: [u8; 32],
    session_key: [u8; 32],
}

impl TransferKeys {
    /// Derives a transfer's keys from the operator key and a salt.
    ///
    /// The payload key and the session key come from the same extract step
    /// under different domain separation strings, so neither can be computed
    /// from the other: disclosing the frame MAC key does not disclose the key
    /// protecting the payload.
    pub fn derive(operator: &OperatorKey, salt: &Salt) -> Result<Self, AeadError> {
        let ikm = operator.expose_bytes();
        Ok(Self {
            payload_key: derive_key(salt, ikm, INFO_PAYLOAD_KEY)?,
            session_key: derive_key(salt, ikm, INFO_SESSION_KEY)?,
        })
    }

    /// Returns the key protecting the payload.
    pub fn payload_key(&self) -> &[u8; 32] {
        &self.payload_key
    }

    /// Returns the key that authenticates frame headers.
    pub fn session_key(&self) -> &[u8; 32] {
        &self.session_key
    }
}

impl Drop for TransferKeys {
    fn drop(&mut self) {
        self.payload_key.zeroize();
        self.session_key.zeroize();
    }
}

impl std::fmt::Debug for TransferKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransferKeys(<redacted>)")
    }
}

/// The public per-transfer values a receiver needs to reproduce the keys.
///
/// Both are carried in the signed manifest. Neither is secret; both must be
/// unpredictable, which is why they come from the CSPRNG rather than a
/// counter or a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferSecrets {
    /// Salt for key derivation.
    pub salt: Salt,
    /// Nonce for payload encryption.
    pub nonce: Nonce,
}

impl TransferSecrets {
    /// Draws a fresh salt and nonce for a new transfer.
    pub fn generate() -> Result<Self, AeadError> {
        Ok(Self {
            salt: Salt::generate()?,
            nonce: Nonce::generate()?,
        })
    }
}

/// Encrypts a payload for a session.
///
/// The returned buffer is the ciphertext with the 16-byte Poly1305 tag
/// appended, so it is `plaintext.len() + TAG_LEN` bytes long. The session ID is
/// authenticated but not encrypted.
pub fn encrypt_payload(
    keys: &TransferKeys,
    nonce: &Nonce,
    session_id: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new_from_slice(keys.payload_key()).map_err(|_| {
        AeadError::EncryptionFailed {
            details: "payload key is not a valid XChaCha20-Poly1305 key".to_string(),
        }
    })?;

    cipher
        .encrypt(
            &XNonce::from(*nonce.as_bytes()),
            Payload {
                msg: plaintext,
                aad: session_id,
            },
        )
        .map_err(|_| AeadError::EncryptionFailed {
            // The underlying error carries no detail by design, and anything
            // we could add here would describe the plaintext.
            details: "AEAD encryption failed".to_string(),
        })
}

/// Decrypts and authenticates a payload.
///
/// Returns an error if the ciphertext, the tag, the session ID, the nonce, or
/// the key is wrong. The failure is deliberately indistinguishable between
/// those cases: revealing which part failed would tell an attacker probing
/// with modified captures what to change next.
/// Decrypts a payload in the buffer that holds it.
///
/// Takes the ciphertext by value and returns the plaintext in the same
/// allocation, truncated by the tag length. The borrowing form allocates a
/// second buffer the size of the whole payload and holds both until the caller
/// drops the first, which on the receiver - the machine in the deployment least
/// likely to have the memory - is a whole extra copy of the dataset.
///
/// The construction is unchanged: this is the same AEAD over the same
/// associated data producing the same plaintext, and
/// `aead_test::in_place_decryption_matches_the_borrowing_form` says so.
pub fn decrypt_payload_in_place(
    keys: &TransferKeys,
    nonce: &Nonce,
    session_id: &[u8; 16],
    mut buffer: Vec<u8>,
) -> Result<Vec<u8>, AeadError> {
    if buffer.len() < TAG_LEN {
        return Err(AeadError::DecryptionFailed {
            details: format!("ciphertext is shorter than the {TAG_LEN}-byte tag"),
        });
    }

    let cipher = XChaCha20Poly1305::new_from_slice(keys.payload_key()).map_err(|_| {
        AeadError::DecryptionFailed {
            details: "payload key is not a valid XChaCha20-Poly1305 key".to_string(),
        }
    })?;

    cipher
        .decrypt_in_place(&XNonce::from(*nonce.as_bytes()), session_id, &mut buffer)
        .map_err(|_| AeadError::DecryptionFailed {
            details: "authentication failed".to_string(),
        })?;

    Ok(buffer)
}

pub fn decrypt_payload(
    keys: &TransferKeys,
    nonce: &Nonce,
    session_id: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext.len() < TAG_LEN {
        return Err(AeadError::DecryptionFailed {
            details: format!("ciphertext is shorter than the {TAG_LEN}-byte tag"),
        });
    }

    let cipher = XChaCha20Poly1305::new_from_slice(keys.payload_key()).map_err(|_| {
        AeadError::DecryptionFailed {
            details: "payload key is not a valid XChaCha20-Poly1305 key".to_string(),
        }
    })?;

    cipher
        .decrypt(
            &XNonce::from(*nonce.as_bytes()),
            Payload {
                msg: ciphertext,
                aad: session_id,
            },
        )
        .map_err(|_| AeadError::DecryptionFailed {
            details: "authentication failed".to_string(),
        })
}

/// Returns the ciphertext length for a given plaintext length.
pub fn ciphertext_len(plaintext_len: usize) -> usize {
    plaintext_len + TAG_LEN
}
