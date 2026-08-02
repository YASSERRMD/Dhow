//! Tests for manifest signing and receiver-side verification.

use crate::ManifestError;
use crate::key::IdentityKey;
use crate::manifest::*;
use dhow_codec::manifest::{FileEntry, Manifest, ManifestHeader, SIGNATURE_OFFSET};

const SESSION: [u8; 16] = [0x42; 16];

fn entries() -> Vec<FileEntry> {
    vec![
        FileEntry::new("docs/readme.md", 100, [1u8; 32]),
        FileEntry::new("src/main.rs", 250, [2u8; 32]),
    ]
}

fn total_size(entries: &[FileEntry]) -> u64 {
    entries.iter().map(|e| e.size).sum()
}

/// Builds an unsigned manifest over `entries`.
fn build(entries: &[FileEntry]) -> Manifest {
    let header = ManifestHeader::new(SESSION, entries, total_size(entries));
    Manifest::build(&header, entries, &[0u8; 64])
}

/// Builds and signs a manifest, returning its wire bytes.
fn signed(identity: &IdentityKey, entries: &[FileEntry]) -> Vec<u8> {
    sign_manifest(identity, &build(entries))
}

// --- Signing round trip ---

#[test]
fn test_signed_manifest_verifies() {
    let identity = IdentityKey::generate().unwrap();
    let bytes = signed(&identity, &entries());

    let verified =
        verify_manifest(&identity.public(), &bytes, &SESSION, &Policy::default()).unwrap();
    assert_eq!(verified.manifest().entries().len(), 2);
    assert_eq!(verified.signer(), &identity.public());
}

#[test]
fn test_signing_embeds_signature_in_place() {
    let identity = IdentityKey::generate().unwrap();
    let bytes = signed(&identity, &entries());
    // The signature field must no longer be zero.
    assert_ne!(
        &bytes[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN],
        &[0u8; 64][..]
    );
}

#[test]
fn test_signing_is_deterministic() {
    // Ed25519 is deterministic, so the same manifest signs identically.
    let identity = IdentityKey::generate().unwrap();
    assert_eq!(signed(&identity, &entries()), signed(&identity, &entries()));
}

#[test]
fn test_signed_manifest_round_trips_through_bytes() {
    let identity = IdentityKey::generate().unwrap();
    let bytes = signed(&identity, &entries());
    let parsed = Manifest::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.entries()[0].name, "docs/readme.md");
    assert_eq!(parsed.entries()[1].size, 250);
}

#[test]
fn test_empty_manifest_verifies() {
    let identity = IdentityKey::generate().unwrap();
    let bytes = signed(&identity, &[]);
    assert!(verify_manifest(&identity.public(), &bytes, &SESSION, &Policy::default()).is_ok());
}

// --- The defect this phase exists to close ---

#[test]
fn test_rewriting_a_file_name_breaks_the_signature() {
    // The signature previously covered only the fixed header, leaving every
    // file name unauthenticated. An attacker could rewrite an entry to a
    // traversal path and the signature would still verify. It must not.
    let identity = IdentityKey::generate().unwrap();
    let original = vec![FileEntry::new("safe.txt", 8, [1u8; 32])];
    let mut bytes = signed(&identity, &original);

    // Overwrite the name in place with one of equal length.
    let needle = b"safe.txt";
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("name present in manifest body");
    bytes[at..at + needle.len()].copy_from_slice(b"../evil.");

    assert!(matches!(
        verify_signature(&identity.public(), &bytes),
        // Either the name policy rejects it at parse time or the signature
        // check does. Both are correct; silently accepting it is not.
        Err(ManifestError::PathTraversal { .. }) | Err(ManifestError::SignatureVerificationFailed)
    ));
}

#[test]
fn test_rewriting_a_file_size_breaks_the_signature() {
    let identity = IdentityKey::generate().unwrap();
    let original = vec![FileEntry::new("a.bin", 100, [1u8; 32])];
    let bytes = signed(&identity, &original);

    // The size field trails the 2-byte length prefix and the 5-byte name.
    let at = bytes
        .windows(5)
        .position(|w| w == b"a.bin")
        .expect("name present")
        + 5;
    let mut tampered = bytes.clone();
    tampered[at..at + 8].copy_from_slice(&999u64.to_le_bytes());

    assert!(verify_signature(&identity.public(), &tampered).is_err());
}

#[test]
fn test_rewriting_a_file_digest_breaks_the_signature() {
    let identity = IdentityKey::generate().unwrap();
    let bytes = signed(&identity, &entries());
    let mut tampered = bytes.clone();
    // Last 32 bytes of the manifest are the final entry's digest.
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(verify_signature(&identity.public(), &tampered).is_err());
}

#[test]
fn test_appending_an_entry_breaks_the_signature() {
    let identity = IdentityKey::generate().unwrap();
    let mut bytes = signed(&identity, &entries());
    bytes.extend_from_slice(&FileEntry::new("extra.txt", 1, [9u8; 32]).to_vec());
    // The header still declares 2 files, so the extra entry is either ignored
    // or rejected, but it must never be presented as verified content.
    let verified = verify_manifest(&identity.public(), &bytes, &SESSION, &Policy::default());
    if let Ok(v) = verified {
        assert_eq!(
            v.manifest().entries().len(),
            2,
            "smuggled entry was accepted"
        );
        assert!(v.manifest().entries().iter().all(|e| e.name != "extra.txt"));
    }
}

#[test]
fn test_every_single_byte_mutation_is_rejected() {
    let identity = IdentityKey::generate().unwrap();
    let bytes = signed(&identity, &entries());

    for i in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[i] ^= 0x01;
        assert!(
            verify_signature(&identity.public(), &mutated).is_err(),
            "mutation at byte {i} verified"
        );
    }
}

// --- Wrong signer ---

#[test]
fn test_another_identitys_signature_is_rejected() {
    let signer = IdentityKey::generate().unwrap();
    let other = IdentityKey::generate().unwrap();
    let bytes = signed(&signer, &entries());

    assert!(matches!(
        verify_signature(&other.public(), &bytes),
        Err(ManifestError::SignatureVerificationFailed)
    ));
}

#[test]
fn test_unsigned_manifest_is_rejected() {
    // A manifest whose signature field is still zero must not verify.
    let identity = IdentityKey::generate().unwrap();
    let bytes = build(&entries()).to_vec();
    assert!(verify_signature(&identity.public(), &bytes).is_err());
}

#[test]
fn test_zeroed_signature_is_rejected() {
    let identity = IdentityKey::generate().unwrap();
    let mut bytes = signed(&identity, &entries());
    bytes[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].fill(0);
    assert!(verify_signature(&identity.public(), &bytes).is_err());
}

// --- Structural rejection ---

#[test]
fn test_truncated_manifest_is_rejected() {
    let identity = IdentityKey::generate().unwrap();
    let bytes = signed(&identity, &entries());
    for cut in [0, 1, 100, 167, bytes.len() - 1] {
        assert!(
            verify_signature(&identity.public(), &bytes[..cut]).is_err(),
            "truncation to {cut} bytes verified"
        );
    }
}

#[test]
fn test_bad_magic_is_rejected() {
    let identity = IdentityKey::generate().unwrap();
    let mut bytes = signed(&identity, &entries());
    bytes[0] = b'X';
    assert!(verify_signature(&identity.public(), &bytes).is_err());
}

#[test]
fn test_downgraded_version_is_rejected() {
    let identity = IdentityKey::generate().unwrap();
    let mut bytes = signed(&identity, &entries());
    bytes[4] = 0;
    assert!(matches!(
        verify_signature(&identity.public(), &bytes),
        Err(ManifestError::UnsupportedVersion { version: 0 })
    ));
}

// --- Session binding ---

#[test]
fn test_manifest_from_another_session_is_rejected() {
    // A correctly signed manifest captured from an earlier transfer between
    // the same operators must not be replayed into this one.
    let identity = IdentityKey::generate().unwrap();
    let bytes = signed(&identity, &entries());

    assert!(matches!(
        verify_manifest(&identity.public(), &bytes, &[0x43; 16], &Policy::default()),
        Err(ManifestError::SessionMismatch)
    ));
}

// --- Policy ---

#[test]
fn test_policy_rejects_oversized_total() {
    let identity = IdentityKey::generate().unwrap();
    let big = vec![FileEntry::new("big.bin", 10_000, [1u8; 32])];
    let bytes = signed(&identity, &big);

    let policy = Policy {
        max_total_size: 1000,
        ..Policy::default()
    };
    assert!(matches!(
        verify_manifest(&identity.public(), &bytes, &SESSION, &policy),
        Err(ManifestError::FileSizeTooLarge { .. })
    ));
}

#[test]
fn test_policy_rejects_oversized_single_file() {
    let identity = IdentityKey::generate().unwrap();
    let big = vec![FileEntry::new("big.bin", 10_000, [1u8; 32])];
    let bytes = signed(&identity, &big);

    let policy = Policy {
        max_file_size: 1000,
        ..Policy::default()
    };
    assert!(matches!(
        verify_manifest(&identity.public(), &bytes, &SESSION, &policy),
        Err(ManifestError::FileSizeTooLarge { .. })
    ));
}

#[test]
fn test_policy_rejects_too_many_files() {
    let identity = IdentityKey::generate().unwrap();
    let bytes = signed(&identity, &entries());

    let policy = Policy {
        max_file_count: 1,
        ..Policy::default()
    };
    assert!(verify_manifest(&identity.public(), &bytes, &SESSION, &policy).is_err());
}

#[test]
fn test_policy_rejects_declared_total_that_disagrees_with_entries() {
    // A small declared total inviting a much larger extraction is the shape of
    // a decompression bomb, so the two must agree.
    let identity = IdentityKey::generate().unwrap();
    let e = entries();
    let header = ManifestHeader::new(SESSION, &e, 1); // claims 1 byte, entries sum to 350
    let manifest = Manifest::build(&header, &e, &[0u8; 64]);
    let bytes = sign_manifest(&identity, &manifest);

    assert!(matches!(
        verify_manifest(&identity.public(), &bytes, &SESSION, &Policy::default()),
        Err(ManifestError::FileSizeTooLarge { .. })
    ));
}

#[test]
fn test_default_policy_accepts_a_realistic_dataset() {
    let identity = IdentityKey::generate().unwrap();
    let many: Vec<FileEntry> = (0..500)
        .map(|i| FileEntry::new(&format!("data/file{i:04}.bin"), 1_000_000, [7u8; 32]))
        .collect();
    let bytes = signed(&identity, &many);

    let verified =
        verify_manifest(&identity.public(), &bytes, &SESSION, &Policy::default()).unwrap();
    assert_eq!(verified.manifest().entries().len(), 500);
}

#[test]
fn test_policy_defaults_are_bounded() {
    let p = Policy::default();
    assert!(p.max_total_size > 0);
    assert!(p.max_file_size <= p.max_total_size);
    assert!(p.max_file_count > 0);
}

// --- Errors must not leak content ---

#[test]
fn test_verification_errors_do_not_contain_file_digests() {
    let identity = IdentityKey::generate().unwrap();
    let other = IdentityKey::generate().unwrap();
    let bytes = signed(&identity, &entries());

    let err = verify_signature(&other.public(), &bytes).unwrap_err();
    let rendered = err.to_string();
    assert!(!rendered.contains("0101"), "digest bytes leaked into error");
}
