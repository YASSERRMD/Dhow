//! Manifest wire format.
//!
//! Implements the manifest format described in `proto/manifest.md`.
//! The manifest is a signed metadata structure describing the dataset
//! being transferred, carried in a frame of type 2 (Manifest).
//!
//! ## Fixed Header Layout (168 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 4 | Magic ("DHMF") |
//! | 4 | 1 | Version (0x01) |
//! | 5 | 3 | Reserved |
//! | 8 | 16 | Session ID |
//! | 24 | 4 | File Count |
//! | 28 | 8 | Total Size |
//! | 36 | 32 | Payload Digest |
//! | 68 | 32 | Reserved |
//! | 100 | 4 | CRC32C |
//! | 104 | 64 | Ed25519 Signature |
//! | 168 | var | File Entries |
//!
//! ## File Entry Layout
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 2 | Name Length |
//! | 2 | variable | Name (UTF-8) |
//! | 2+len | 8 | File Size |
//! | 10+len | 32 | File Digest |
//!
//! ## Integrity
//!
//! - **CRC32C**: Covers bytes 0..100 (magic through reserved2).
//! - **Ed25519 Signature**: Covers bytes 0..100, verified by the operator's key.
//! - **Payload Digest**: BLAKE3 of the encrypted payload, for end-to-end verification.
//!
//! ## Safety
//!
//! File names are sanitized against path traversal attacks:
//! no leading `/`, no `..`, no null bytes, max length 4096.
//!
//! # Example
//!
//! ```
//! use dhow_codec::manifest::{Manifest, ManifestHeader, FileEntry};
//!
//! let entries = vec![
//!     FileEntry::new("hello.txt", 5, [0u8; 32]),
//! ];
//! let header = ManifestHeader::new([0u8; 16], &entries, 5);
//! let manifest = Manifest::build(&header, &entries, &[0u8; 64]);
//! let bytes = manifest.to_vec();
//! let parsed = Manifest::from_bytes(&bytes).unwrap();
//! assert_eq!(parsed.entries().len(), 1);
//! ```

use crate::crc32c::crc32c_digest;
use crate::ManifestError;

/// Magic bytes for Dhow manifests (ASCII "DHMF").
pub const MANIFEST_MAGIC: [u8; 4] = *b"DHMF";

/// Manifest version.
pub const MANIFEST_VERSION: u8 = 1;

/// Fixed manifest header size before file entries.
pub const MANIFEST_HEADER_SIZE: usize = 168;

/// Size of the Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Maximum file name length.
pub const MAX_NAME_LEN: usize = 4096;

/// A file entry within the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// File name (UTF-8, sanitized).
    pub name: String,
    /// Uncompressed file size.
    pub size: u64,
    /// BLAKE3 digest of the uncompressed file content.
    pub digest: [u8; 32],
}

impl FileEntry {
    /// Creates a new file entry.
    pub fn new(name: &str, size: u64, digest: [u8; 32]) -> Self {
        Self {
            name: name.to_string(),
            size,
            digest,
        }
    }

    /// Serializes the file entry to bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        let name_bytes = self.name.as_bytes();
        let mut buf = Vec::with_capacity(2 + name_bytes.len() + 8 + 32);
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.digest);
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

        let total_entry_len = 2 + name_len + 8 + 32;
        if bytes.len() < total_entry_len {
            return Err(ManifestError::Truncated {
                expected: total_entry_len,
                actual: bytes.len(),
            });
        }

        let name_bytes = &bytes[2..2 + name_len];
        let name = String::from_utf8(name_bytes.to_vec()).map_err(|_| {
            ManifestError::InvalidKey {
                details: "file name contains invalid UTF-8".to_string(),
            }
        })?;

        // Path traversal check
        if name.starts_with('/') || name.starts_with("..") || name.contains('\0') {
            return Err(ManifestError::PathTraversal { name: name.clone() });
        }

        let size = u64::from_le_bytes(
            bytes[2 + name_len..10 + name_len]
                .try_into()
                .unwrap(),
        );

        let digest: [u8; 32] = bytes[10 + name_len..42 + name_len].try_into().unwrap();

        Ok((Self { name, size, digest }, total_entry_len))
    }
}

/// Manifest header (168 bytes) + signature.
#[derive(Debug, Clone)]
pub struct ManifestHeader {
    magic: [u8; 4],
    version: u8,
    reserved1: [u8; 3],
    session_id: [u8; 16],
    file_count: u32,
    total_size: u64,
    payload_digest: [u8; 32],
    reserved2: [u8; 32],
    crc32c: u32,
    signature: [u8; 64],
}

impl ManifestHeader {
    /// Creates a new manifest header.
    /// The CRC32C and signature must be set separately via `set_crc_and_signature`.
    pub fn new(session_id: [u8; 16], entries: &[FileEntry], total_size: u64) -> Self {
        let payload_digest = if entries.is_empty() {
            [0u8; 32]
        } else {
            // Compute digest of all file digests concatenated
            let mut h = blake3::Hasher::new();
            for entry in entries {
                h.update(&entry.digest);
            }
            let result = h.finalize();
            let mut digest = [0u8; 32];
            digest.copy_from_slice(result.as_bytes());
            digest
        };

        let crc32c = {
            let mut bytes = Vec::with_capacity(100);
            bytes.extend_from_slice(&MANIFEST_MAGIC);
            bytes.push(MANIFEST_VERSION);
            bytes.extend_from_slice(&[0u8; 3]);
            bytes.extend_from_slice(&session_id);
            bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&total_size.to_le_bytes());
            bytes.extend_from_slice(&payload_digest);
            bytes.extend_from_slice(&[0u8; 32]);
            crc32c_digest(&bytes)
        };

        Self {
            magic: MANIFEST_MAGIC,
            version: MANIFEST_VERSION,
            reserved1: [0; 3],
            session_id,
            file_count: entries.len() as u32,
            total_size,
            payload_digest,
            reserved2: [0; 32],
            crc32c,
            signature: [0; 64],
        }
    }

    /// Sets the signature and recomputes CRC32C.
    pub fn set_signature(&mut self, signature: [u8; 64]) {
        self.signature = signature;
        // CRC doesn't cover the signature, so no recompute needed
    }

    /// Serializes the fixed header (168 bytes, no file entries).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MANIFEST_HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);
        buf.extend_from_slice(&self.reserved1);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.file_count.to_le_bytes());
        buf.extend_from_slice(&self.total_size.to_le_bytes());
        buf.extend_from_slice(&self.payload_digest);
        buf.extend_from_slice(&self.reserved2);
        buf.extend_from_slice(&self.crc32c.to_le_bytes());
        buf.extend_from_slice(&self.signature);
        debug_assert_eq!(buf.len(), MANIFEST_HEADER_SIZE);
        buf
    }

    /// Deserializes the fixed header from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() < MANIFEST_HEADER_SIZE {
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

        let mut reserved1 = [0u8; 3];
        reserved1.copy_from_slice(&bytes[5..8]);
        if reserved1 != [0u8; 3] {
            return Err(ManifestError::InvalidKey {
                details: "reserved1 must be zero".to_string(),
            });
        }

        let session_id: [u8; 16] = bytes[8..24].try_into().unwrap();
        let file_count = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let total_size = u64::from_le_bytes(bytes[28..36].try_into().unwrap());
        let payload_digest: [u8; 32] = bytes[36..68].try_into().unwrap();

        let mut reserved2 = [0u8; 32];
        reserved2.copy_from_slice(&bytes[68..100]);
        if reserved2 != [0u8; 32] {
            return Err(ManifestError::InvalidKey {
                details: "reserved2 must be zero".to_string(),
            });
        }

        let crc32c = u32::from_le_bytes(bytes[100..104].try_into().unwrap());
        let signature: [u8; 64] = bytes[104..168].try_into().unwrap();

        // Verify CRC32C
        let expected_crc = crc32c_digest(&bytes[0..100]);
        if crc32c != expected_crc {
            return Err(ManifestError::CrcMismatch);
        }

        Ok(Self {
            magic,
            version,
            reserved1,
            session_id,
            file_count,
            total_size,
            payload_digest,
            reserved2,
            crc32c,
            signature,
        })
    }

    pub fn magic(&self) -> [u8; 4] { self.magic }
    pub fn version(&self) -> u8 { self.version }
    pub fn session_id(&self) -> [u8; 16] { self.session_id }
    pub fn file_count(&self) -> u32 { self.file_count }
    pub fn total_size(&self) -> u64 { self.total_size }
    pub fn payload_digest(&self) -> [u8; 32] { self.payload_digest }
    pub fn crc32c(&self) -> u32 { self.crc32c }
    pub fn signature(&self) -> [u8; 64] { self.signature }
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        let header = ManifestHeader::from_bytes(bytes)?;
        let file_count = header.file_count() as usize;

        let mut entries = Vec::with_capacity(file_count);
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

    pub fn header(&self) -> &ManifestHeader { &self.header }
    pub fn entries(&self) -> &[FileEntry] { &self.entries }
}
