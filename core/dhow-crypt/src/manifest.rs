//! Manifest signing and receiver-side verification.
//!
//! The manifest is the only thing binding a transfer to an identity. It names
//! the files, their sizes and digests, the session, and the digest of the
//! encrypted payload. A receiver that accepts an unsigned or badly-signed
//! manifest has no basis for trusting anything that follows, so verification
//! is the gate every transfer passes through before a byte is written to disk.
//!
//! # What the signature covers
//!
//! The whole manifest, file entries included, with the signature field zeroed.
//! Signing only the fixed header would leave every file name unauthenticated,
//! which would let an attacker rewrite an entry to a traversal path without
//! disturbing the signature.
//!
//! # Verification order
//!
//! [`verify_manifest`] checks cheap structural properties before expensive
//! cryptography, and applies policy only to a manifest whose signature already
//! verified. The order matters: policy limits describe what a *legitimate*
//! sender may claim, so applying them to unauthenticated bytes would report
//! attacker-controlled values as though they meant something.
//!
//! 1. Parse: magic, version, reserved fields, CRC, entry structure, names.
//! 2. Signature: Ed25519 over the canonical signing bytes.
//! 3. Policy: coding-parameter sanity, bounds on counts and sizes, session
//!    binding, digest consistency.

use crate::ManifestError;
use crate::key::{IdentityKey, PublicIdentity};
use dhow_codec::manifest::{MAX_FILE_COUNT, Manifest, validate_name};
use ed25519_dalek::{SIGNATURE_LENGTH, Signature};

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = SIGNATURE_LENGTH;

/// Limits a receiver applies to a manifest it has authenticated.
///
/// These are not security boundaries on their own; the signature is. They stop
/// a legitimate but mistaken sender, and they bound resource use during
/// extraction.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Largest total dataset size to accept, in bytes.
    pub max_total_size: u64,
    /// Largest single file to accept, in bytes.
    pub max_file_size: u64,
    /// Largest number of files to accept.
    pub max_file_count: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            // 64 GiB total, 16 GiB for any single file. Generous enough not to
            // obstruct real datasets, bounded enough that a signed-but-wrong
            // manifest cannot ask the receiver to allocate without limit.
            max_total_size: 64 * 1024 * 1024 * 1024,
            max_file_size: 16 * 1024 * 1024 * 1024,
            max_file_count: MAX_FILE_COUNT,
        }
    }
}

/// A manifest whose signature and policy checks have both passed.
///
/// This type exists so a verified manifest is distinguishable from a parsed
/// one at the type level: code that extracts files takes a `VerifiedManifest`
/// and therefore cannot be handed unauthenticated metadata by mistake.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    manifest: Manifest,
    signer: PublicIdentity,
}

impl VerifiedManifest {
    /// Returns the underlying manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Returns the identity whose signature was verified.
    pub fn signer(&self) -> &PublicIdentity {
        &self.signer
    }
}

/// Signs a manifest, returning the manifest bytes with the signature embedded.
///
/// The returned bytes are what travels in the manifest frame.
pub fn sign_manifest(identity: &IdentityKey, manifest: &Manifest) -> Vec<u8> {
    let signature = identity.sign(&manifest.signing_bytes());
    let mut bytes = manifest.to_vec();
    let start = dhow_codec::manifest::SIGNATURE_OFFSET;
    bytes[start..start + SIGNATURE_LEN].copy_from_slice(&signature.to_bytes());
    bytes
}

/// Verifies a manifest's signature against an expected signer.
///
/// Returns the parsed manifest only when the signature is valid. The signer is
/// supplied by the caller rather than read from the manifest: a key carried
/// inside the thing it signs authenticates nothing, since an attacker who
/// rewrites the manifest would simply substitute their own key.
pub fn verify_signature(
    expected_signer: &PublicIdentity,
    bytes: &[u8],
) -> Result<Manifest, ManifestError> {
    let manifest = parse(bytes)?;

    let signing_bytes = Manifest::signing_bytes_of(bytes).map_err(convert_codec_error)?;

    let signature_bytes: [u8; SIGNATURE_LEN] = manifest.header().signature();
    let signature = Signature::from_bytes(&signature_bytes);

    if !expected_signer.verify(&signing_bytes, &signature) {
        return Err(ManifestError::SignatureVerificationFailed);
    }

    Ok(manifest)
}

/// Verifies a manifest end to end: structure, signature, then policy.
///
/// `session_id` binds the manifest to the transfer being received, so a
/// correctly signed manifest captured from an earlier transfer between the
/// same operators cannot be replayed into this one.
pub fn verify_manifest(
    expected_signer: &PublicIdentity,
    bytes: &[u8],
    session_id: &[u8; 16],
    policy: &Policy,
) -> Result<VerifiedManifest, ManifestError> {
    verify_manifest_with(expected_signer, bytes, Some(session_id), policy)
}

/// Verifies a manifest, optionally binding it to a session already in hand.
///
/// `session_id` is `None` when the manifest is the receiver's *first* sight of
/// the transfer and there is nothing yet to bind it to - which is the ordinary
/// case for `dhow recv` and `dhow verify`, where the session identifier is
/// taken from the manifest because the manifest is the authenticated statement
/// of what the session is.
///
/// It is `Some` when the receiver already knows which session it is receiving:
/// resuming from saved state, or having read a session header off the wire. In
/// that case a correctly signed manifest from a *different* transfer between
/// the same operators must not be accepted, which is what the binding rejects.
///
/// Passing `None` is therefore not a weaker check, it is a different one. What
/// would be weaker is accepting a manifest whose session nobody ever compared
/// against the frames it arrived with; that comparison belongs to the caller
/// that holds both.
pub fn verify_manifest_with(
    expected_signer: &PublicIdentity,
    bytes: &[u8],
    session_id: Option<&[u8; 16]>,
    policy: &Policy,
) -> Result<VerifiedManifest, ManifestError> {
    let manifest = verify_signature(expected_signer, bytes)?;

    // Everything below runs only on authenticated bytes.
    if let Some(expected) = session_id
        && manifest.header().session_id() != *expected
    {
        return Err(ManifestError::SessionMismatch);
    }

    check_policy(&manifest, policy)?;

    Ok(VerifiedManifest {
        manifest,
        signer: *expected_signer,
    })
}

/// Parses a manifest, mapping the codec's error type onto this crate's.
fn parse(bytes: &[u8]) -> Result<Manifest, ManifestError> {
    Manifest::from_bytes(bytes).map_err(convert_codec_error)
}

/// Applies the receiver's policy limits to an authenticated manifest.
fn check_policy(manifest: &Manifest, policy: &Policy) -> Result<(), ManifestError> {
    let header = manifest.header();

    // The coding parameters are now part of the signed structure, so they get
    // checked here rather than being discovered by the decoder. A signed
    // manifest is a statement of intent, not of competence: a sender that
    // declares zero blocks has made a mistake, and the receiver should say so
    // instead of handing the values to RaptorQ to reject.
    header
        .params()
        .validate()
        .map_err(|e| ManifestError::Malformed {
            details: e.to_string(),
        })?;

    if header.file_count() > policy.max_file_count {
        return Err(ManifestError::InvalidBlockCount {
            count: header.file_count(),
        });
    }

    // The header's declared count must match what the body actually carried.
    // A mismatch means the manifest describes something other than itself.
    if manifest.entries().len() != header.file_count() as usize {
        return Err(ManifestError::InvalidBlockCount {
            count: header.file_count(),
        });
    }

    if header.total_size() > policy.max_total_size {
        return Err(ManifestError::FileSizeTooLarge {
            size: header.total_size(),
            max: policy.max_total_size,
        });
    }

    let mut summed: u64 = 0;
    for entry in manifest.entries() {
        // Re-check names here as well as at parse time. Extraction depends on
        // this being true, and the check is cheap enough that relying on a
        // caller having parsed through the same path is not worth the risk.
        validate_name(&entry.name).map_err(convert_codec_error)?;

        if entry.size > policy.max_file_size {
            return Err(ManifestError::FileSizeTooLarge {
                size: entry.size,
                max: policy.max_file_size,
            });
        }

        summed = summed
            .checked_add(entry.size)
            .ok_or(ManifestError::FileSizeTooLarge {
                size: u64::MAX,
                max: policy.max_total_size,
            })?;
    }

    // A declared total that disagrees with the entries is a decompression-bomb
    // shape: a small claimed total inviting a large extraction.
    if summed != header.total_size() {
        return Err(ManifestError::FileSizeTooLarge {
            size: summed,
            max: header.total_size(),
        });
    }

    Ok(())
}

/// Maps a `dhow_codec` manifest error onto this crate's equivalent.
///
/// The two enums are deliberately separate so the crypt crate's public surface
/// does not leak the codec's, but the variants correspond one to one.
fn convert_codec_error(err: dhow_codec::ManifestError) -> ManifestError {
    use dhow_codec::ManifestError as C;
    match err {
        C::InvalidMagic { got } => ManifestError::InvalidMagic { got },
        C::UnsupportedVersion { version } => ManifestError::UnsupportedVersion { version },
        C::SignatureVerificationFailed => ManifestError::SignatureVerificationFailed,
        C::CrcMismatch => ManifestError::CrcMismatch,
        C::Truncated { expected, actual } => ManifestError::Truncated { expected, actual },
        C::PathTraversal { name } => ManifestError::PathTraversal { name },
        C::FileNameTooLong { length } => ManifestError::FileNameTooLong { length },
        C::FileSizeTooLarge { size, max } => ManifestError::FileSizeTooLarge { size, max },
        C::InvalidFileCount { count } => ManifestError::InvalidBlockCount { count },
        C::SessionMismatch => ManifestError::SessionMismatch,
        C::Malformed { details } => ManifestError::Malformed { details },
    }
}
