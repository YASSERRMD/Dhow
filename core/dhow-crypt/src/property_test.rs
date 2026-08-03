//! Property tests for the crypto layer.
//!
//! `dhow-codec` has had property tests since Phase 5 and this crate has had
//! none, which is the wrong way round: the codec's failure mode is a dataset
//! that does not reassemble, and this crate's is a dataset that reassembles
//! into something an attacker chose.
//!
//! These assert properties rather than examples. An example test says "this
//! input produced this output on the day it was written"; a property says
//! "no input produces X", and it is the second that catches the case nobody
//! thought of.
//!
//! # What is deliberately not tested here
//!
//! The primitives. XChaCha20-Poly1305, HKDF-BLAKE3, and Ed25519 come from
//! audited crates and are not reimplemented, so testing that ChaCha20 is
//! ChaCha20 would be testing someone else's code with a worse harness. What is
//! tested is how this crate composes them: what is bound to what, what a
//! changed input does, and what never leaks.

use crate::aead::{Nonce, TransferKeys, ciphertext_len, decrypt_payload, encrypt_payload};
use crate::kdf::{Salt, derive_key};
use crate::key::{IdentityKey, OperatorKey, PublicIdentity};
use crate::manifest::{Policy, sign_manifest, verify_manifest_with};
use dhow_codec::manifest::{FileEntry, Manifest, ManifestHeader};
use dhow_codec::session::{RaptorQParams, SessionParams};
use proptest::prelude::*;

/// Arbitrary payload bytes, bounded so a run stays quick.
fn payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..4096)
}

fn key_bytes() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn session_id() -> impl Strategy<Value = [u8; 16]> {
    any::<[u8; 16]>()
}

fn nonce_bytes() -> impl Strategy<Value = [u8; 24]> {
    any::<[u8; 24]>()
}

// --- AEAD ---

proptest! {
    /// Whatever goes in comes back, for every size including zero.
    #[test]
    fn aead_round_trips(
        plaintext in payload(),
        key in key_bytes(),
        salt in key_bytes(),
        sid in session_id(),
        nonce in nonce_bytes(),
    ) {
        let keys = TransferKeys::derive(
            &OperatorKey::from_bytes(key),
            &Salt::from_bytes(salt),
        ).unwrap();
        let nonce = Nonce::from_bytes(nonce);

        let ciphertext = encrypt_payload(&keys, &nonce, &sid, &plaintext).unwrap();
        let recovered = decrypt_payload(&keys, &nonce, &sid, &ciphertext).unwrap();
        prop_assert_eq!(recovered, plaintext);
    }

    /// The ciphertext length is a function of the plaintext length alone.
    ///
    /// A receiver sizes its buffers from `ciphertext_len` before it has the
    /// ciphertext, so a length that depended on the *content* would be a
    /// mis-sized allocation on the far side of an air gap.
    #[test]
    fn ciphertext_length_is_predictable(
        plaintext in payload(),
        key in key_bytes(),
        salt in key_bytes(),
        sid in session_id(),
        nonce in nonce_bytes(),
    ) {
        let keys = TransferKeys::derive(
            &OperatorKey::from_bytes(key),
            &Salt::from_bytes(salt),
        ).unwrap();
        let ciphertext = encrypt_payload(
            &keys, &Nonce::from_bytes(nonce), &sid, &plaintext,
        ).unwrap();

        prop_assert_eq!(ciphertext.len(), ciphertext_len(plaintext.len()));
    }

    /// A ciphertext altered anywhere fails to decrypt.
    ///
    /// Not "decrypts to something different" - fails. That is what the AEAD tag
    /// is for, and a transfer that silently produced altered plaintext is the
    /// one outcome this project exists to make impossible.
    #[test]
    fn any_altered_byte_fails_to_decrypt(
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        key in key_bytes(),
        salt in key_bytes(),
        sid in session_id(),
        nonce in nonce_bytes(),
        index in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let keys = TransferKeys::derive(
            &OperatorKey::from_bytes(key),
            &Salt::from_bytes(salt),
        ).unwrap();
        let nonce = Nonce::from_bytes(nonce);

        let mut ciphertext = encrypt_payload(&keys, &nonce, &sid, &plaintext).unwrap();
        let at = index.index(ciphertext.len());
        ciphertext[at] = ciphertext[at].wrapping_add(delta);

        prop_assert!(
            decrypt_payload(&keys, &nonce, &sid, &ciphertext).is_err(),
            "a ciphertext altered at byte {} decrypted", at
        );
    }

    /// The session id is bound into the ciphertext.
    ///
    /// A recording of yesterday's transfer replayed into today's session must
    /// not decrypt, even though the operator key has not changed. This is what
    /// makes the session id more than a label.
    #[test]
    fn a_foreign_session_cannot_decrypt(
        plaintext in payload(),
        key in key_bytes(),
        salt in key_bytes(),
        a in session_id(),
        b in session_id(),
        nonce in nonce_bytes(),
    ) {
        prop_assume!(a != b);

        let keys = TransferKeys::derive(
            &OperatorKey::from_bytes(key),
            &Salt::from_bytes(salt),
        ).unwrap();
        let nonce = Nonce::from_bytes(nonce);

        let ciphertext = encrypt_payload(&keys, &nonce, &a, &plaintext).unwrap();
        prop_assert!(decrypt_payload(&keys, &nonce, &b, &ciphertext).is_err());
    }

    /// A different operator key cannot decrypt.
    #[test]
    fn a_foreign_key_cannot_decrypt(
        plaintext in payload(),
        key_a in key_bytes(),
        key_b in key_bytes(),
        salt in key_bytes(),
        sid in session_id(),
        nonce in nonce_bytes(),
    ) {
        prop_assume!(key_a != key_b);

        let salt = Salt::from_bytes(salt);
        let keys_a = TransferKeys::derive(&OperatorKey::from_bytes(key_a), &salt).unwrap();
        let keys_b = TransferKeys::derive(&OperatorKey::from_bytes(key_b), &salt).unwrap();
        let nonce = Nonce::from_bytes(nonce);

        let ciphertext = encrypt_payload(&keys_a, &nonce, &sid, &plaintext).unwrap();
        prop_assert!(decrypt_payload(&keys_b, &nonce, &sid, &ciphertext).is_err());
    }

    /// A different salt derives different keys, so it cannot decrypt either.
    ///
    /// The salt is public and travels in the manifest. If it did not actually
    /// change the derivation, carrying it would be theatre.
    #[test]
    fn a_different_salt_cannot_decrypt(
        plaintext in payload(),
        key in key_bytes(),
        salt_a in key_bytes(),
        salt_b in key_bytes(),
        sid in session_id(),
        nonce in nonce_bytes(),
    ) {
        prop_assume!(salt_a != salt_b);

        let operator = OperatorKey::from_bytes(key);
        let keys_a = TransferKeys::derive(&operator, &Salt::from_bytes(salt_a)).unwrap();
        let keys_b = TransferKeys::derive(&operator, &Salt::from_bytes(salt_b)).unwrap();
        let nonce = Nonce::from_bytes(nonce);

        let ciphertext = encrypt_payload(&keys_a, &nonce, &sid, &plaintext).unwrap();
        prop_assert!(decrypt_payload(&keys_b, &nonce, &sid, &ciphertext).is_err());
    }
}

// --- Key derivation ---

proptest! {
    /// Derivation is a function: the same inputs give the same keys.
    ///
    /// Both operators derive independently and never compare results, so a
    /// derivation that varied by anything not in its inputs would produce a
    /// transfer that fails with no diagnosable cause.
    #[test]
    fn derivation_is_deterministic(key in key_bytes(), salt in key_bytes()) {
        let operator = OperatorKey::from_bytes(key);
        let salt = Salt::from_bytes(salt);

        let a = TransferKeys::derive(&operator, &salt).unwrap();
        let b = TransferKeys::derive(&operator, &salt).unwrap();

        prop_assert_eq!(a.payload_key(), b.payload_key());
        prop_assert_eq!(a.session_key(), b.session_key());
    }

    /// The payload key and the session key are never the same value.
    ///
    /// One encrypts the payload and the other authenticates frames. If the
    /// derivation ever produced one value for both, a frame MAC would be
    /// computed under the key that protects the data, and the domain
    /// separation the info strings exist for would be gone.
    #[test]
    fn the_two_derived_keys_differ(key in key_bytes(), salt in key_bytes()) {
        let keys = TransferKeys::derive(
            &OperatorKey::from_bytes(key),
            &Salt::from_bytes(salt),
        ).unwrap();
        prop_assert_ne!(keys.payload_key(), keys.session_key());
    }

    /// A change to the salt changes both derived keys.
    #[test]
    fn a_different_salt_derives_different_keys(
        key in key_bytes(),
        salt_a in key_bytes(),
        salt_b in key_bytes(),
    ) {
        prop_assume!(salt_a != salt_b);
        let operator = OperatorKey::from_bytes(key);

        let a = TransferKeys::derive(&operator, &Salt::from_bytes(salt_a)).unwrap();
        let b = TransferKeys::derive(&operator, &Salt::from_bytes(salt_b)).unwrap();

        prop_assert_ne!(a.payload_key(), b.payload_key());
        prop_assert_ne!(a.session_key(), b.session_key());
    }

    /// Different info strings derive different keys from one salt and secret.
    ///
    /// This is the whole mechanism of domain separation, asserted directly
    /// rather than inferred from the two transfer keys differing.
    #[test]
    fn different_info_strings_separate_domains(
        secret in prop::collection::vec(any::<u8>(), 1..64),
        salt in key_bytes(),
        info_a in prop::collection::vec(any::<u8>(), 0..32),
        info_b in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        prop_assume!(info_a != info_b);
        let salt = Salt::from_bytes(salt);

        let a = derive_key(&salt, &secret, &info_a).unwrap();
        let b = derive_key(&salt, &secret, &info_b).unwrap();
        prop_assert_ne!(a, b);
    }
}

// --- Manifest signing ---

/// Builds a manifest over arbitrary entries.
fn build_manifest(sid: [u8; 16], names: &[String], sizes: &[u64]) -> Manifest {
    let entries: Vec<FileEntry> = names
        .iter()
        .zip(sizes)
        .enumerate()
        .map(|(i, (name, size))| FileEntry::with_mode(name, *size, [i as u8; 32], i % 2 == 0))
        .collect();
    let total: u64 = entries.iter().map(|e| e.size).sum();

    let params = SessionParams {
        payload_size: total.max(1),
        block_count: 1,
        symbol_size: 256,
        source_symbols_per_block: 1,
        total_symbols_per_block: 2,
        raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
        payload_digest: [7u8; 32],
    };
    let header = ManifestHeader::new(sid, &entries, total, [1u8; 32], [2u8; 24], params);
    Manifest::build(&header, &entries, &[0u8; 64])
}

/// Names that are legal in a manifest: relative, no traversal, no NUL.
fn legal_names() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec("[a-zA-Z0-9_]{1,12}(/[a-zA-Z0-9_]{1,12}){0,3}", 1..8)
}

proptest! {
    /// A manifest signed by an identity verifies against that identity.
    #[test]
    fn a_signed_manifest_verifies(
        seed in key_bytes(),
        sid in session_id(),
        names in legal_names(),
    ) {
        let sizes: Vec<u64> = (0..names.len() as u64).collect();
        let identity = IdentityKey::from_seed(&seed);
        let bytes = sign_manifest(&identity, &build_manifest(sid, &names, &sizes));

        let verified = verify_manifest_with(
            &identity.public(), &bytes, None, &Policy::default(),
        );
        prop_assert!(verified.is_ok(), "{:?}", verified.err());
    }

    /// Signing is deterministic, as Ed25519 requires.
    ///
    /// A sender that produced a different signature for the same manifest
    /// would break the reproducible-build claim, since the manifest is part of
    /// what a release signs.
    #[test]
    fn signing_is_deterministic(
        seed in key_bytes(),
        sid in session_id(),
        names in legal_names(),
    ) {
        let sizes: Vec<u64> = (0..names.len() as u64).collect();
        let identity = IdentityKey::from_seed(&seed);

        let a = sign_manifest(&identity, &build_manifest(sid, &names, &sizes));
        let b = sign_manifest(&identity, &build_manifest(sid, &names, &sizes));
        prop_assert_eq!(a, b);
    }

    /// No other identity's signature verifies.
    #[test]
    fn a_foreign_identity_does_not_verify(
        seed_a in key_bytes(),
        seed_b in key_bytes(),
        sid in session_id(),
        names in legal_names(),
    ) {
        prop_assume!(seed_a != seed_b);
        let sizes: Vec<u64> = (0..names.len() as u64).collect();

        let signer = IdentityKey::from_seed(&seed_a);
        let stranger = IdentityKey::from_seed(&seed_b);
        let bytes = sign_manifest(&signer, &build_manifest(sid, &names, &sizes));

        prop_assert!(
            verify_manifest_with(&stranger.public(), &bytes, None, &Policy::default()).is_err()
        );
    }

    /// A manifest altered anywhere fails verification.
    ///
    /// Every byte, chosen by the strategy rather than sampled at fixed offsets,
    /// so a field somebody forgot to sign is found rather than assumed absent.
    #[test]
    fn any_altered_byte_fails_verification(
        seed in key_bytes(),
        sid in session_id(),
        names in legal_names(),
        index in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let sizes: Vec<u64> = (0..names.len() as u64).collect();
        let identity = IdentityKey::from_seed(&seed);
        let mut bytes = sign_manifest(&identity, &build_manifest(sid, &names, &sizes));

        let at = index.index(bytes.len());
        bytes[at] = bytes[at].wrapping_add(delta);

        prop_assert!(
            verify_manifest_with(&identity.public(), &bytes, None, &Policy::default()).is_err(),
            "a manifest altered at byte {} verified", at
        );
    }

    /// Session binding rejects every session but the manifest's own.
    #[test]
    fn session_binding_rejects_every_other_session(
        seed in key_bytes(),
        a in session_id(),
        b in session_id(),
        names in legal_names(),
    ) {
        prop_assume!(a != b);
        let sizes: Vec<u64> = (0..names.len() as u64).collect();
        let identity = IdentityKey::from_seed(&seed);
        let bytes = sign_manifest(&identity, &build_manifest(a, &names, &sizes));
        let public = identity.public();

        prop_assert!(
            verify_manifest_with(&public, &bytes, Some(&a), &Policy::default()).is_ok()
        );
        prop_assert!(
            verify_manifest_with(&public, &bytes, Some(&b), &Policy::default()).is_err()
        );
    }
}

// --- What must never leak ---

proptest! {
    /// No Debug output ever contains key material.
    ///
    /// Debug formatting reaches logs, panic messages, and error strings, all of
    /// which cross machine boundaries. A key that appeared in one would be a
    /// key that had left the machine, and no test after the fact could recall
    /// it.
    #[test]
    fn debug_output_never_contains_key_material(
        key in key_bytes(),
        seed in key_bytes(),
    ) {
        let operator = OperatorKey::from_bytes(key);
        let identity = IdentityKey::from_seed(&seed);

        let operator_debug = format!("{operator:?}");
        let identity_debug = format!("{identity:?}");

        // Any four consecutive bytes of the secret appearing in the output
        // would be a leak; four is short enough that a coincidence in a
        // redaction string is implausible and long enough to catch a partial.
        for window in key.windows(4) {
            let needle = window.iter().map(|b| format!("{b:02x}")).collect::<String>();
            prop_assert!(
                !operator_debug.to_lowercase().contains(&needle),
                "OperatorKey Debug leaked key bytes: {operator_debug}"
            );
        }
        for window in seed.windows(4) {
            let needle = window.iter().map(|b| format!("{b:02x}")).collect::<String>();
            prop_assert!(
                !identity_debug.to_lowercase().contains(&needle),
                "IdentityKey Debug leaked seed bytes: {identity_debug}"
            );
        }

        // Both impls redact rather than truncate, so the output must not grow
        // with the secret at all.
        prop_assert!(
            operator_debug.contains("redacted"),
            "OperatorKey Debug is not a redaction: {operator_debug}"
        );
        prop_assert!(
            identity_debug.contains("redacted"),
            "IdentityKey Debug is not a redaction: {identity_debug}"
        );
    }

    /// A public identity is a function of its secret and reveals nothing else.
    ///
    /// The same seed always yields the same public key - which is what lets a
    /// receiver keep a .pub file across a sender's reinstall - and two seeds
    /// never collide.
    #[test]
    fn public_identities_are_stable_and_distinct(
        seed_a in key_bytes(),
        seed_b in key_bytes(),
    ) {
        let a = IdentityKey::from_seed(&seed_a);
        prop_assert_eq!(a.public().to_bytes(), IdentityKey::from_seed(&seed_a).public().to_bytes());

        prop_assume!(seed_a != seed_b);
        let b = IdentityKey::from_seed(&seed_b);
        prop_assert_ne!(a.public().to_bytes(), b.public().to_bytes());
    }

    /// A fingerprint is stable, short, and never the key itself.
    #[test]
    fn fingerprints_are_stable_and_not_the_key(seed in key_bytes()) {
        let public = IdentityKey::from_seed(&seed).public();
        let fingerprint = public.fingerprint();

        prop_assert_eq!(fingerprint.clone(), public.fingerprint());
        prop_assert_eq!(fingerprint.len(), 23);

        // Truncated by design. A fingerprint that contained the whole key
        // would invite being used as one, and it is documented as unusable for
        // any security check.
        let full = public.to_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();
        prop_assert!(!fingerprint.replace(':', "").eq(&full));
    }

    /// A public identity parsed from its own encoding is the same identity.
    #[test]
    fn public_identity_round_trips(seed in key_bytes()) {
        let public = IdentityKey::from_seed(&seed).public();
        let parsed = PublicIdentity::from_bytes(&public.to_bytes()).unwrap();
        prop_assert_eq!(parsed.to_bytes(), public.to_bytes());
    }
}
