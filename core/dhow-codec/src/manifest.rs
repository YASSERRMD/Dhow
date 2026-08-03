//! Manifest wire format.
//!
//! Implements the manifest format described in `proto/manifest.md`.
//! The manifest is a signed metadata structure describing the dataset
//! being transferred, carried in a frame of type 2 (Manifest).
//!
//! ## Fixed Header Layout (228 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 4 | Magic ("DHMF") |
//! | 4 | 1 | Version (0x02) |
//! | 5 | 3 | Reserved |
//! | 8 | 16 | Session ID |
//! | 24 | 4 | File Count |
//! | 28 | 8 | Total Size |
//! | 36 | 32 | Payload Digest |
//! | 68 | 32 | Salt |
//! | 100 | 24 | Nonce |
//! | 124 | 8 | Payload Size |
//! | 132 | 4 | Block Count |
//! | 136 | 4 | Symbol Size |
//! | 140 | 4 | Source Symbols Per Block |
//! | 144 | 4 | Total Symbols Per Block |
//! | 148 | 4 | RaptorQ Z |
//! | 152 | 4 | RaptorQ N |
//! | 156 | 2 | RaptorQ PSI |
//! | 158 | 2 | Reserved |
//! | 160 | 4 | CRC32C |
//! | 164 | 64 | Ed25519 Signature |
//! | 228 | var | File Entries |
//!
//! ## File Entry Layout
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 2 | Name Length |
//! | 2 | variable | Name (UTF-8) |
//! | 2+len | 8 | File Size |
//! | 10+len | 32 | File Digest |
//! | 42+len | 1 | Flags (bit 0: executable) |
//!
//! ## Why the session parameters are in here
//!
//! The salt, nonce, and coding parameters also travel in the session header,
//! which is unsigned framing. A receiver that took them only from there would
//! decode whatever the channel handed it and then check the *result* against a
//! signature, which is the wrong order: the parameters are inputs to the
//! transfer, and an input nobody signed is an input an attacker can choose.
//!
//! ## Integrity
//!
//! - **CRC32C**: Covers bytes 0..160, everything up to the CRC field itself.
//! - **Ed25519 Signature**: Covers the entire manifest, file entries included,
//!   with the signature field itself zeroed. See [`Manifest::signing_bytes`].
//!   A signature over the fixed header alone would leave every file name, size,
//!   and digest unauthenticated.
//! - **Payload Digest**: BLAKE3 of the encrypted payload, for end-to-end
//!   verification. Taken from the session parameters, so the manifest cannot
//!   describe a payload the session header does not.
//!
//! ## Safety
//!
//! File names are sanitized against path traversal by [`validate_name`], which
//! inspects every `/`-separated component rather than only the start of the
//! string. Rejected: empty names, absolute paths, Windows drive prefixes,
//! backslashes, NUL bytes, any `..` component, and names over 4096 bytes.
//!
//! # Example
//!
//! ```
//! use dhow_codec::manifest::{Manifest, ManifestHeader, FileEntry};
//! use dhow_codec::session::{SessionParams, RaptorQParams};
//!
//! let params = SessionParams {
//!     payload_size: 64,
//!     block_count: 1,
//!     symbol_size: 64,
//!     source_symbols_per_block: 1,
//!     total_symbols_per_block: 2,
//!     raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
//!     payload_digest: [9u8; 32],
//! };
//! let entries = vec![
//!     FileEntry::with_mode("hello.txt", 5, [0u8; 32], true),
//! ];
//! let header = ManifestHeader::new([0u8; 16], &entries, 5, [1u8; 32], [2u8; 24], params);
//! let manifest = Manifest::build(&header, &entries, &[0u8; 64]);
//! let bytes = manifest.to_vec();
//! let parsed = Manifest::from_bytes(&bytes).unwrap();
//! assert_eq!(parsed.entries().len(), 1);
//! assert!(parsed.entries()[0].executable);
//! assert_eq!(parsed.header().salt(), [1u8; 32]);
//! ```

use crate::ManifestError;
use crate::crc32c::crc32c_digest;
use crate::session::{RaptorQParams, SessionParams};

/// Magic bytes for Dhow manifests (ASCII "DHMF").
pub const MANIFEST_MAGIC: [u8; 4] = *b"DHMF";

/// Manifest version.
pub const MANIFEST_VERSION: u8 = 2;

/// Fixed manifest header size before file entries.
pub const MANIFEST_HEADER_SIZE: usize = 228;

/// Offset of the CRC32C field, and therefore the length it covers.
pub const CRC_OFFSET: usize = 160;

/// Size of the Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Maximum file name length.
pub const MAX_NAME_LEN: usize = 4096;

/// Maximum number of file entries a manifest may declare.
///
/// The declared count drives an allocation during parsing, so it is bounded
/// before it is trusted. Without this a manifest could claim `u32::MAX` entries
/// and exhaust memory before a single entry was read.
pub const MAX_FILE_COUNT: u32 = 1_000_000;

/// Offset of the signature field within the fixed header.
pub const SIGNATURE_OFFSET: usize = 164;

/// Rejects a file name that could escape the extraction directory.
///
/// The name is treated as a relative path with `/` separators. A name is
/// rejected when it is empty, absolute, contains a NUL, contains a `..`
/// component anywhere, carries a Windows drive prefix, or uses a backslash.
///
/// Checking only the start of the string is not enough: `a/../../etc/passwd`
/// begins with a harmless component and still escapes. Every component is
/// inspected.
pub fn validate_name(name: &str) -> Result<(), ManifestError> {
    if name.is_empty() {
        return Err(ManifestError::PathTraversal {
            name: name.to_string(),
        });
    }

    if name.len() > MAX_NAME_LEN {
        return Err(ManifestError::FileNameTooLong { length: name.len() });
    }

    // A backslash is a separator on the receiving side if it is Windows, and
    // is a legal filename character on Unix. Treating it as data would let a
    // name that looks like one component become two. Reject it outright.
    if name.contains('\0') || name.contains('\\') {
        return Err(ManifestError::PathTraversal {
            name: name.to_string(),
        });
    }

    // Absolute paths, and drive-relative names such as `C:file`.
    if name.starts_with('/') || name.chars().nth(1) == Some(':') {
        return Err(ManifestError::PathTraversal {
            name: name.to_string(),
        });
    }

    for component in name.split('/') {
        if component == ".." {
            return Err(ManifestError::PathTraversal {
                name: name.to_string(),
            });
        }
    }

    Ok(())
}

/// Bit 0 of an entry's flag byte: the owner execute bit.
pub const ENTRY_FLAG_EXECUTABLE: u8 = 1;

/// Every flag bit this version defines.
///
/// A byte with anything outside this mask is rejected rather than masked off.
/// The flags travel inside a signature, and quietly discarding a bit a future
/// version gives meaning to would let an old receiver act on a manifest it did
/// not fully understand while believing it had checked it.
const ENTRY_FLAG_KNOWN: u8 = ENTRY_FLAG_EXECUTABLE;

/// Bytes an entry occupies beyond its name.
const ENTRY_FIXED_LEN: usize = 2 + 8 + 32 + 1;

/// A file entry within the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// File name (UTF-8, sanitized).
    pub name: String,
    /// Uncompressed file size.
    pub size: u64,
    /// BLAKE3 digest of the uncompressed file content.
    pub digest: [u8; 32],
    /// Whether the owner execute bit was set on the sender.
    ///
    /// The only mode bit the manifest carries. Every other permission bit
    /// varies by machine and umask, and would make the same dataset produce
    /// different manifests on different senders.
    pub executable: bool,
}

impl FileEntry {
    /// Creates a new file entry for a non-executable file.
    pub fn new(name: &str, size: u64, digest: [u8; 32]) -> Self {
        Self {
            name: name.to_string(),
            size,
            digest,
            executable: false,
        }
    }

    /// Creates a new file entry, stating whether the file is executable.
    pub fn with_mode(name: &str, size: u64, digest: [u8; 32], executable: bool) -> Self {
        Self {
            name: name.to_string(),
            size,
            digest,
            executable,
        }
    }

    /// Returns the entry's flag byte.
    pub fn flags(&self) -> u8 {
        if self.executable {
            ENTRY_FLAG_EXECUTABLE
        } else {
            0
        }
    }

    /// Serializes the file entry to bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        let name_bytes = self.name.as_bytes();
        let mut buf = Vec::with_capacity(ENTRY_FIXED_LEN + name_bytes.len());
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.digest);
        buf.push(self.flags());
        buf
    }

    /// Deserializes a file entry from bytes.
    /// Returns the entry and the number of bytes consumed.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), ManifestError> {
        if bytes.len() < 2 {
            return Err(ManifestError::Truncated {
                expected: 2,
                actual: bytes.len(),
            });
        }

        let name_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if name_len > MAX_NAME_LEN {
            return Err(ManifestError::FileNameTooLong { length: name_len });
        }

        let total_entry_len = ENTRY_FIXED_LEN + name_len;
        if bytes.len() < total_entry_len {
            return Err(ManifestError::Truncated {
                expected: total_entry_len,
                actual: bytes.len(),
            });
        }

        let name_bytes = &bytes[2..2 + name_len];
        let name =
            String::from_utf8(name_bytes.to_vec()).map_err(|_| ManifestError::Malformed {
                details: "file name contains invalid UTF-8".to_string(),
            })?;

        validate_name(&name)?;

        let size = u64::from_le_bytes(bytes[2 + name_len..10 + name_len].try_into().unwrap());

        let digest: [u8; 32] = bytes[10 + name_len..42 + name_len].try_into().unwrap();

        let flags = bytes[42 + name_len];
        if flags & !ENTRY_FLAG_KNOWN != 0 {
            return Err(ManifestError::Malformed {
                details: format!("file entry {name} sets undefined flag bits {flags:#04x}"),
            });
        }

        Ok((
            Self {
                name,
                size,
                digest,
                executable: flags & ENTRY_FLAG_EXECUTABLE != 0,
            },
            total_entry_len,
        ))
    }
}

/// Manifest header (228 bytes, signature included).
#[derive(Debug, Clone)]
pub struct ManifestHeader {
    magic: [u8; 4],
    version: u8,
    session_id: [u8; 16],
    file_count: u32,
    total_size: u64,
    salt: [u8; 32],
    nonce: [u8; 24],
    params: SessionParams,
    crc32c: u32,
    signature: [u8; 64],
}

/// Serializes the header fields the CRC covers: everything up to the CRC field.
///
/// Written once and used by both the constructor and the serializer, because a
/// CRC computed over a byte string that differs from the one transmitted is a
/// CRC that passes on the sender and fails on the receiver.
fn crc_covered_bytes(
    session_id: &[u8; 16],
    file_count: u32,
    total_size: u64,
    salt: &[u8; 32],
    nonce: &[u8; 24],
    params: &SessionParams,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CRC_OFFSET);
    buf.extend_from_slice(&MANIFEST_MAGIC);
    buf.push(MANIFEST_VERSION);
    buf.extend_from_slice(&[0u8; 3]);
    buf.extend_from_slice(session_id);
    buf.extend_from_slice(&file_count.to_le_bytes());
    buf.extend_from_slice(&total_size.to_le_bytes());
    buf.extend_from_slice(&params.payload_digest);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&params.payload_size.to_le_bytes());
    buf.extend_from_slice(&params.block_count.to_le_bytes());
    buf.extend_from_slice(&params.symbol_size.to_le_bytes());
    buf.extend_from_slice(&params.source_symbols_per_block.to_le_bytes());
    buf.extend_from_slice(&params.total_symbols_per_block.to_le_bytes());
    buf.extend_from_slice(&params.raptorq.z.to_le_bytes());
    buf.extend_from_slice(&params.raptorq.n.to_le_bytes());
    buf.extend_from_slice(&params.raptorq.psi.to_le_bytes());
    buf.extend_from_slice(&[0u8; 2]);
    debug_assert_eq!(buf.len(), CRC_OFFSET);
    buf
}

impl ManifestHeader {
    /// Creates a new manifest header with an unset signature.
    ///
    /// `total_size` is the sum of the entries' sizes; it is passed rather than
    /// derived so a caller that already computed it does not compute it twice,
    /// and so [`crate::manifest`]'s policy check has something to disagree with
    /// when a hostile manifest declares one total and carries another.
    ///
    /// The payload digest and payload size come from `params`, so the manifest
    /// cannot describe a different payload than the session header does.
    pub fn new(
        session_id: [u8; 16],
        entries: &[FileEntry],
        total_size: u64,
        salt: [u8; 32],
        nonce: [u8; 24],
        params: SessionParams,
    ) -> Self {
        let file_count = entries.len() as u32;
        let crc32c = crc32c_digest(&crc_covered_bytes(
            &session_id,
            file_count,
            total_size,
            &salt,
            &nonce,
            &params,
        ));

        Self {
            magic: MANIFEST_MAGIC,
            version: MANIFEST_VERSION,
            session_id,
            file_count,
            total_size,
            salt,
            nonce,
            params,
            crc32c,
            signature: [0; 64],
        }
    }

    /// Sets the Ed25519 signature on the header.
    ///
    /// The CRC does not cover the signature, so it does not need recomputing.
    pub fn set_signature(&mut self, signature: [u8; 64]) {
        self.signature = signature;
    }

    /// Serializes the fixed header (228 bytes, no file entries).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = crc_covered_bytes(
            &self.session_id,
            self.file_count,
            self.total_size,
            &self.salt,
            &self.nonce,
            &self.params,
        );
        buf.extend_from_slice(&self.crc32c.to_le_bytes());
        buf.extend_from_slice(&self.signature);
        debug_assert_eq!(buf.len(), MANIFEST_HEADER_SIZE);
        buf
    }

    /// Deserializes the fixed header from bytes.
    ///
    /// Magic and version are checked before the full length, because the header
    /// size is version-dependent: a v1 manifest is 168 bytes, and checking the
    /// length first would report it as truncated when it is complete and simply
    /// old. "Truncated: expected 228, got 168" tells an operator to look for
    /// lost bytes; "unsupported version 1" tells them to re-send. Only the five
    /// bytes those two checks read are required up front.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        const PREFIX_LEN: usize = 5;
        if bytes.len() < PREFIX_LEN {
            return Err(ManifestError::Truncated {
                expected: MANIFEST_HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        if magic != MANIFEST_MAGIC {
            return Err(ManifestError::InvalidMagic { got: magic });
        }

        let version = bytes[4];
        if version != MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedVersion { version });
        }

        if bytes.len() < MANIFEST_HEADER_SIZE {
            return Err(ManifestError::Truncated {
                expected: MANIFEST_HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        if bytes[5..8] != [0u8; 3] {
            return Err(ManifestError::Malformed {
                details: "reserved bytes at offset 5 must be zero".to_string(),
            });
        }

        let session_id: [u8; 16] = bytes[8..24].try_into().unwrap();
        let file_count = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let total_size = u64::from_le_bytes(bytes[28..36].try_into().unwrap());
        let payload_digest: [u8; 32] = bytes[36..68].try_into().unwrap();
        let salt: [u8; 32] = bytes[68..100].try_into().unwrap();
        let nonce: [u8; 24] = bytes[100..124].try_into().unwrap();

        let params = SessionParams {
            payload_size: u64::from_le_bytes(bytes[124..132].try_into().unwrap()),
            block_count: u32::from_le_bytes(bytes[132..136].try_into().unwrap()),
            symbol_size: u32::from_le_bytes(bytes[136..140].try_into().unwrap()),
            source_symbols_per_block: u32::from_le_bytes(bytes[140..144].try_into().unwrap()),
            total_symbols_per_block: u32::from_le_bytes(bytes[144..148].try_into().unwrap()),
            raptorq: RaptorQParams {
                z: u32::from_le_bytes(bytes[148..152].try_into().unwrap()),
                n: u32::from_le_bytes(bytes[152..156].try_into().unwrap()),
                psi: u16::from_le_bytes(bytes[156..158].try_into().unwrap()),
            },
            payload_digest,
        };

        if bytes[158..160] != [0u8; 2] {
            return Err(ManifestError::Malformed {
                details: "reserved bytes at offset 158 must be zero".to_string(),
            });
        }

        let crc32c = u32::from_le_bytes(bytes[CRC_OFFSET..CRC_OFFSET + 4].try_into().unwrap());
        let signature: [u8; 64] = bytes[SIGNATURE_OFFSET..MANIFEST_HEADER_SIZE]
            .try_into()
            .unwrap();

        let expected_crc = crc32c_digest(&bytes[0..CRC_OFFSET]);
        if crc32c != expected_crc {
            return Err(ManifestError::CrcMismatch);
        }

        Ok(Self {
            magic,
            version,
            session_id,
            file_count,
            total_size,
            salt,
            nonce,
            params,
            crc32c,
            signature,
        })
    }

    pub fn magic(&self) -> [u8; 4] {
        self.magic
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }
    pub fn file_count(&self) -> u32 {
        self.file_count
    }
    pub fn total_size(&self) -> u64 {
        self.total_size
    }
    pub fn payload_digest(&self) -> [u8; 32] {
        self.params.payload_digest
    }
    /// Returns the per-transfer HKDF salt.
    pub fn salt(&self) -> [u8; 32] {
        self.salt
    }
    /// Returns the XChaCha20-Poly1305 nonce.
    pub fn nonce(&self) -> [u8; 24] {
        self.nonce
    }
    /// Returns the coding parameters the sender used.
    pub fn params(&self) -> SessionParams {
        self.params
    }
    pub fn crc32c(&self) -> u32 {
        self.crc32c
    }
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
}

/// A complete manifest: header + signature + file entries.
#[derive(Debug, Clone)]
pub struct Manifest {
    header: ManifestHeader,
    entries: Vec<FileEntry>,
}

impl Manifest {
    /// Builds a manifest, setting the signature.
    pub fn build(header: &ManifestHeader, entries: &[FileEntry], signature: &[u8; 64]) -> Self {
        let mut h = header.clone();
        h.set_signature(*signature);
        Self {
            header: h,
            entries: entries.to_vec(),
        }
    }

    /// Serializes the entire manifest to bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = self.header.to_vec();
        for entry in &self.entries {
            buf.extend_from_slice(&entry.to_vec());
        }
        buf
    }

    /// Parses a manifest from bytes.
    ///
    /// The declared file count is bounded before it is used to size an
    /// allocation, so a hostile manifest cannot exhaust memory by claiming
    /// more entries than it carries.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        let header = ManifestHeader::from_bytes(bytes)?;

        if header.file_count() > MAX_FILE_COUNT {
            return Err(ManifestError::InvalidFileCount {
                count: header.file_count(),
            });
        }

        let file_count = header.file_count() as usize;

        // Reserve against what the buffer could actually hold rather than what
        // the header claims, so the claim alone drives no allocation.
        let min_entry_len = 2 + 8 + 32;
        let capacity =
            file_count.min(bytes.len().saturating_sub(MANIFEST_HEADER_SIZE) / min_entry_len + 1);

        let mut entries = Vec::with_capacity(capacity);
        let mut offset = MANIFEST_HEADER_SIZE;
        for _ in 0..file_count {
            if offset >= bytes.len() {
                return Err(ManifestError::Truncated {
                    expected: bytes.len() + 1,
                    actual: bytes.len(),
                });
            }
            let (entry, consumed) = FileEntry::from_bytes(&bytes[offset..])?;
            entries.push(entry);
            offset += consumed;
        }

        Ok(Self { header, entries })
    }

    pub fn header(&self) -> &ManifestHeader {
        &self.header
    }
    pub fn entries(&self) -> &[FileEntry] {
        &self.entries
    }

    /// Returns the canonical byte string an Ed25519 signature covers.
    ///
    /// This is the entire manifest, file entries included, with the 64-byte
    /// signature field itself zeroed. Signing the whole structure is the point:
    /// a signature over the fixed header alone would leave every file name,
    /// size, and digest unauthenticated, so an attacker could rewrite an entry
    /// to a traversal path and the signature would still verify.
    ///
    /// Zeroing the signature field rather than excluding its range keeps the
    /// offsets of everything after it unchanged, so signer and verifier build
    /// the same bytes without either needing to splice ranges.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_vec();
        bytes[SIGNATURE_OFFSET..MANIFEST_HEADER_SIZE].fill(0);
        bytes
    }

    /// Returns the canonical signing bytes for an already-serialized manifest.
    ///
    /// Used by a verifier, which holds bytes off the wire rather than a parsed
    /// manifest it built itself.
    pub fn signing_bytes_of(bytes: &[u8]) -> Result<Vec<u8>, ManifestError> {
        if bytes.len() < MANIFEST_HEADER_SIZE {
            return Err(ManifestError::Truncated {
                expected: MANIFEST_HEADER_SIZE,
                actual: bytes.len(),
            });
        }
        let mut owned = bytes.to_vec();
        owned[SIGNATURE_OFFSET..MANIFEST_HEADER_SIZE].fill(0);
        Ok(owned)
    }
}
