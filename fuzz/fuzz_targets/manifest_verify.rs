//! Fuzz manifest parsing and signature verification.
//!
//! The manifest is a receiver's first sight of a transfer and decides what it
//! extracts, with what names, at what sizes. Since the CLI was wired through
//! it, the session id, salt, nonce, and every coding parameter come from here
//! too, so anything this accepts is something the decoder is configured with.
//!
//! # Invariants asserted
//!
//! - Neither parsing nor verification panics.
//! - A parsed manifest carries exactly the number of entries its header
//!   declares, and re-serializes to exactly the bytes it came from - every
//!   byte accounted for, no trailing region quietly ignored.
//! - **Verification means verification.** Anything `verify_manifest_with`
//!   accepts must really carry a valid signature over its own canonical
//!   signing bytes, checked here independently of the code under test. This is
//!   the invariant that matters: a verifier that returns `Ok` for input the
//!   signature does not cover would make every downstream check meaningless.
//! - A verified manifest's declared total matches the sum of its entries, and
//!   its parameters pass validation.

#![no_main]

use dhow_codec::manifest::{MANIFEST_HEADER_SIZE, Manifest};
use dhow_crypt::key::IdentityKey;
use dhow_crypt::manifest::{Policy, verify_manifest_with};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

/// A fixed identity, so a run is reproducible from its corpus alone.
///
/// Derived from a constant seed rather than generated: an identity drawn from
/// the CSPRNG would make a crashing input reproduce only in the process that
/// found it, which is the one property a fuzz artifact must not have.
static SIGNER: LazyLock<IdentityKey> = LazyLock::new(|| IdentityKey::from_seed(&[0x42; 32]));

fuzz_target!(|data: &[u8]| {
    let policy = Policy::default();
    let public = SIGNER.public();

    // Parsing, on its own. Everything here runs on unauthenticated bytes and
    // is what an attacker reaches without a key.
    if let Ok(manifest) = Manifest::from_bytes(data) {
        assert_eq!(
            manifest.entries().len(),
            manifest.header().file_count() as usize,
            "a parsed manifest carries a different number of entries than it declares"
        );

        // Exact, not a prefix. The parser rejects trailing bytes, so a parsed
        // manifest accounts for every byte it was given - which is what makes
        // to_vec() a description of the input rather than of part of it.
        let serialized = manifest.to_vec();
        assert!(
            serialized.len() >= MANIFEST_HEADER_SIZE,
            "a parsed manifest serialized to {} bytes",
            serialized.len()
        );
        assert_eq!(
            serialized.len(),
            data.len(),
            "a parsed manifest left {} bytes unaccounted for",
            data.len().saturating_sub(serialized.len())
        );
        assert_eq!(
            &serialized[..],
            data,
            "a parsed manifest did not re-serialize to the bytes it came from"
        );

        // The signing bytes are the header and entries with the signature
        // zeroed, so they must be the same length as the manifest itself.
        // A mismatch means signer and verifier would cover different spans.
        assert_eq!(
            manifest.signing_bytes().len(),
            serialized.len(),
            "signing bytes and manifest bytes are different lengths"
        );
    }

    // Verification. Almost every input fails here, which is the point: the
    // assertion is about what happens when one does not.
    let Ok(verified) = verify_manifest_with(&public, data, None, &policy) else {
        return;
    };

    // Re-check the signature from the outside. If this ever fires, the
    // verifier accepted something its own signature does not cover.
    let signing_bytes = Manifest::signing_bytes_of(data)
        .expect("a manifest that verified could not produce signing bytes");
    let signature = ed25519_signature(verified.manifest().header().signature());
    assert!(
        public.verify(&signing_bytes, &signature),
        "verify_manifest_with accepted a manifest whose signature does not check out"
    );

    // Policy, restated. These are the claims extraction depends on.
    let header = verified.manifest().header();
    let summed: u64 = verified
        .manifest()
        .entries()
        .iter()
        .map(|entry| entry.size)
        .sum();
    assert_eq!(
        summed,
        header.total_size(),
        "a verified manifest declares a total its entries do not sum to"
    );
    assert!(
        header.params().validate().is_ok(),
        "a verified manifest carries parameters that do not validate"
    );
});

/// Rebuilds a signature from its 64 bytes.
fn ed25519_signature(bytes: [u8; 64]) -> ed25519_dalek::Signature {
    ed25519_dalek::Signature::from_bytes(&bytes)
}
