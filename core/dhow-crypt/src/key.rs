//! Key generation, storage, and loading.
//!
//! Dhow uses two kinds of key material:
//!
//! - An **identity key**: an Ed25519 keypair. The secret half signs manifests;
//!   the public half is what a receiving operator pins to decide whose
//!   transfers it will accept.
//! - An **operator key**: a 32-byte symmetric secret shared out of band between
//!   the two operators. Every per-transfer key is derived from it, so it is
//!   never used to encrypt anything directly.
//!
//! # Key files
//!
//! Secret key files carry a fixed header, the key material, and a keyed
//! checksum that detects corruption before the bytes are used. The layout is:
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 4 | Magic (`DHKY`) |
//! | 4 | 1 | Version (0x01) |
//! | 5 | 1 | Key kind (1 = identity, 2 = operator) |
//! | 6 | 2 | Reserved (must be zero) |
//! | 8 | 32 | Key material |
//! | 40 | 32 | BLAKE3 checksum of bytes 0..40 |
//!
//! Total: 72 bytes.
//!
//! # Handling rules
//!
//! Secret key files must be readable only by their owner. [`save_secret`]
//! writes them with mode 0600 and [`load_secret`] refuses a file that any
//! group or other user can read, since a permissive mode means the secret
//! should be treated as disclosed.
//!
//! Key material is wrapped in types that zeroize on drop and whose `Debug`
//! output is a placeholder, so a secret cannot reach a log or a panic message
//! by being formatted.

use crate::KeyError;
use ed25519_dalek::{SECRET_KEY_LENGTH, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::fs;
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Magic bytes for Dhow key files (ASCII `DHKY`).
pub const KEY_MAGIC: [u8; 4] = *b"DHKY";

/// Key file format version.
pub const KEY_VERSION: u8 = 1;

/// Length of the key material in a key file.
pub const KEY_MATERIAL_LEN: usize = 32;

/// Total size of a secret key file in bytes.
pub const KEY_FILE_SIZE: usize = 72;

/// Offset at which the checksum begins.
const CHECKSUM_OFFSET: usize = 40;

/// Permission bits that must not be set on a secret key file.
#[cfg(unix)]
const FORBIDDEN_MODE_BITS: u32 = 0o077;

/// Which kind of secret a key file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyKind {
    /// An Ed25519 signing key.
    Identity = 1,
    /// A symmetric operator key.
    Operator = 2,
}

impl KeyKind {
    fn from_u8(value: u8) -> Result<Self, KeyError> {
        match value {
            1 => Ok(KeyKind::Identity),
            2 => Ok(KeyKind::Operator),
            _ => Err(KeyError::InvalidKey {
                details: format!("unknown key kind {value}"),
            }),
        }
    }
}

/// Fills a buffer with bytes from the operating system CSPRNG.
fn random_bytes(buf: &mut [u8]) -> Result<(), KeyError> {
    getrandom::fill(buf).map_err(|e| KeyError::GenerationFailed {
        details: format!("system randomness unavailable: {e}"),
    })
}

/// A 32-byte symmetric operator key.
///
/// Zeroized on drop. `Debug` deliberately omits the key bytes.
#[derive(Clone)]
pub struct OperatorKey {
    bytes: [u8; KEY_MATERIAL_LEN],
}

impl Drop for OperatorKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl OperatorKey {
    /// Generates a new operator key from the system CSPRNG.
    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = [0u8; KEY_MATERIAL_LEN];
        random_bytes(&mut bytes)?;
        Ok(Self { bytes })
    }

    /// Wraps existing key bytes.
    pub fn from_bytes(bytes: [u8; KEY_MATERIAL_LEN]) -> Self {
        Self { bytes }
    }

    /// Returns the raw key bytes.
    ///
    /// Callers must not copy these into anything that outlives the key, and
    /// must never log or display them.
    pub fn expose_bytes(&self) -> &[u8; KEY_MATERIAL_LEN] {
        &self.bytes
    }
}

impl std::fmt::Debug for OperatorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperatorKey(<redacted>)")
    }
}

impl PartialEq for OperatorKey {
    /// Compares in constant time; key comparison must not leak via timing.
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for OperatorKey {}

/// An Ed25519 identity keypair.
///
/// Zeroized on drop. `Debug` deliberately omits the secret half.
pub struct IdentityKey {
    signing: SigningKey,
}

impl IdentityKey {
    /// Generates a new identity keypair from the system CSPRNG.
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        random_bytes(&mut seed)?;
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self { signing })
    }

    /// Reconstructs an identity from its 32-byte secret seed.
    pub fn from_seed(seed: &[u8; SECRET_KEY_LENGTH]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Returns the public half, which is safe to publish.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Signs a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// Returns the secret seed.
    ///
    /// Used only to serialize the key file; never crosses the FFI boundary.
    fn expose_seed(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing.to_bytes()
    }
}

impl Drop for IdentityKey {
    fn drop(&mut self) {
        // SigningKey zeroizes its own scalar on drop; this makes the intent
        // explicit and survives a future change of representation.
        let mut seed = self.signing.to_bytes();
        seed.zeroize();
    }
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentityKey(<redacted>)")
    }
}

/// The public half of an identity, used to verify signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicIdentity {
    verifying: VerifyingKey,
}

impl PublicIdentity {
    /// Parses a public identity from its 32-byte encoding.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeyError> {
        VerifyingKey::from_bytes(bytes)
            .map(|verifying| Self { verifying })
            .map_err(|e| KeyError::InvalidKey {
                details: format!("not a valid Ed25519 public key: {e}"),
            })
    }

    /// Returns the 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// Verifies a signature over a message.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verifying.verify(message, signature).is_ok()
    }

    /// Returns a short human-readable fingerprint for operator comparison.
    ///
    /// This is for eyeballing that two machines hold the same identity. It is
    /// truncated and must not be used as an identifier in any security check.
    pub fn fingerprint(&self) -> String {
        let digest = blake3::hash(&self.to_bytes());
        digest
            .as_bytes()
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Serializes key material into the key file layout.
fn encode_key_file(kind: KeyKind, material: &[u8; KEY_MATERIAL_LEN]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(KEY_FILE_SIZE);
    buf.extend_from_slice(&KEY_MAGIC);
    buf.push(KEY_VERSION);
    buf.push(kind as u8);
    buf.extend_from_slice(&[0u8; 2]); // reserved
    buf.extend_from_slice(material);
    debug_assert_eq!(buf.len(), CHECKSUM_OFFSET);
    let checksum = blake3::hash(&buf);
    buf.extend_from_slice(checksum.as_bytes());
    debug_assert_eq!(buf.len(), KEY_FILE_SIZE);
    buf
}

/// Parses a key file, validating the header and checksum.
///
/// Every field is checked before the key material is returned, so a truncated
/// or corrupted file cannot yield a usable key.
fn decode_key_file(bytes: &[u8]) -> Result<(KeyKind, [u8; KEY_MATERIAL_LEN]), KeyError> {
    if bytes.len() != KEY_FILE_SIZE {
        return Err(KeyError::Truncated {
            expected: KEY_FILE_SIZE,
            actual: bytes.len(),
        });
    }

    let magic: [u8; 4] = bytes[0..4].try_into().unwrap_or_default();
    if magic != KEY_MAGIC {
        return Err(KeyError::InvalidMagic {
            expected: KEY_MAGIC,
            got: magic,
        });
    }

    let version = bytes[4];
    if version != KEY_VERSION {
        return Err(KeyError::UnsupportedVersion { version });
    }

    let kind = KeyKind::from_u8(bytes[5])?;

    if bytes[6..8] != [0u8; 2] {
        return Err(KeyError::InvalidKey {
            details: "reserved field must be zero".to_string(),
        });
    }

    let expected = blake3::hash(&bytes[..CHECKSUM_OFFSET]);
    let found = &bytes[CHECKSUM_OFFSET..];
    if !bool::from(expected.as_bytes().ct_eq(found)) {
        return Err(KeyError::InvalidKey {
            details: "key file checksum mismatch".to_string(),
        });
    }

    let mut material = [0u8; KEY_MATERIAL_LEN];
    material.copy_from_slice(&bytes[8..CHECKSUM_OFFSET]);
    Ok((kind, material))
}

/// Writes bytes to `path` with owner-only permissions.
///
/// The mode is applied at creation rather than afterwards, so the file is
/// never briefly readable by others.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| KeyError::GenerationFailed {
                details: format!("cannot create key file: {e}"),
            })?;
        file.write_all(bytes)
            .map_err(|e| KeyError::GenerationFailed {
                details: format!("cannot write key file: {e}"),
            })?;
        // An existing file keeps its old mode through OpenOptions, so set it
        // explicitly as well.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            KeyError::GenerationFailed {
                details: format!("cannot set key file permissions: {e}"),
            }
        })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, bytes).map_err(|e| KeyError::GenerationFailed {
            details: format!("cannot write key file: {e}"),
        })
    }
}

/// Rejects a key file that is readable beyond its owner.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;

    let meta = fs::metadata(path).map_err(|e| KeyError::InvalidKey {
        details: format!("cannot stat key file: {e}"),
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & FORBIDDEN_MODE_BITS != 0 {
        return Err(KeyError::InsecurePermissions { perms: mode });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), KeyError> {
    Ok(())
}

/// A secret loaded from a key file.
#[derive(Debug)]
pub enum SecretKey {
    /// An Ed25519 identity keypair.
    Identity(IdentityKey),
    /// A symmetric operator key.
    Operator(OperatorKey),
}

/// Writes an identity key to `path` with mode 0600.
pub fn save_identity(path: &Path, key: &IdentityKey) -> Result<(), KeyError> {
    let mut seed = key.expose_seed();
    let bytes = encode_key_file(KeyKind::Identity, &seed);
    seed.zeroize();
    write_owner_only(path, &bytes)
}

/// Writes an operator key to `path` with mode 0600.
pub fn save_operator(path: &Path, key: &OperatorKey) -> Result<(), KeyError> {
    let bytes = encode_key_file(KeyKind::Operator, key.expose_bytes());
    write_owner_only(path, &bytes)
}

/// Loads a secret key file, enforcing owner-only permissions.
pub fn load_secret(path: &Path) -> Result<SecretKey, KeyError> {
    check_permissions(path)?;

    let bytes = fs::read(path).map_err(|e| KeyError::InvalidKey {
        details: format!("cannot read key file: {e}"),
    })?;

    let (kind, mut material) = decode_key_file(&bytes)?;
    let secret = match kind {
        KeyKind::Identity => SecretKey::Identity(IdentityKey::from_seed(&material)),
        KeyKind::Operator => SecretKey::Operator(OperatorKey::from_bytes(material)),
    };
    material.zeroize();
    Ok(secret)
}

/// Loads a key file and requires it to hold an identity key.
pub fn load_identity(path: &Path) -> Result<IdentityKey, KeyError> {
    match load_secret(path)? {
        SecretKey::Identity(k) => Ok(k),
        SecretKey::Operator(_) => Err(KeyError::InvalidKey {
            details: "expected an identity key, found an operator key".to_string(),
        }),
    }
}

/// Loads a key file and requires it to hold an operator key.
pub fn load_operator(path: &Path) -> Result<OperatorKey, KeyError> {
    match load_secret(path)? {
        SecretKey::Operator(k) => Ok(k),
        SecretKey::Identity(_) => Err(KeyError::InvalidKey {
            details: "expected an operator key, found an identity key".to_string(),
        }),
    }
}

/// Writes a public identity to `path`.
///
/// Public keys carry no secret, so they are written with default permissions.
pub fn save_public(path: &Path, identity: &PublicIdentity) -> Result<(), KeyError> {
    fs::write(path, identity.to_bytes()).map_err(|e| KeyError::GenerationFailed {
        details: format!("cannot write public key file: {e}"),
    })
}

/// Reads a public identity from `path`.
pub fn load_public(path: &Path) -> Result<PublicIdentity, KeyError> {
    let bytes = fs::read(path).map_err(|e| KeyError::InvalidKey {
        details: format!("cannot read public key file: {e}"),
    })?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| KeyError::Truncated {
            expected: 32,
            actual: bytes.len(),
        })?;
    PublicIdentity::from_bytes(&arr)
}
