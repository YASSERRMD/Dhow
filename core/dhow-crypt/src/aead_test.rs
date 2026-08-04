//! Tests for payload encryption.

use crate::aead::*;
use crate::kdf::Salt;
use crate::key::OperatorKey;

const SESSION: [u8; 16] = [0x42; 16];

fn keys() -> TransferKeys {
    let operator = OperatorKey::from_bytes([0x11; 32]);
    TransferKeys::derive(&operator, &Salt::from_bytes([0x22; 32])).unwrap()
}

fn nonce() -> Nonce {
    Nonce::from_bytes([0x33; NONCE_LEN])
}

// --- Round trip ---

#[test]
fn test_encrypt_decrypt_round_trip() {
    let k = keys();
    let plaintext = b"the payload that must survive the optical channel";
    let ct = encrypt_payload(&k, &nonce(), &SESSION, plaintext).unwrap();
    assert_eq!(
        decrypt_payload(&k, &nonce(), &SESSION, &ct).unwrap(),
        plaintext
    );
}

#[test]
fn test_round_trip_over_a_range_of_sizes() {
    let k = keys();
    for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 1024, 65536] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let ct = encrypt_payload(&k, &nonce(), &SESSION, &plaintext).unwrap();
        assert_eq!(
            decrypt_payload(&k, &nonce(), &SESSION, &ct).unwrap(),
            plaintext,
            "round trip failed at length {len}"
        );
    }
}

#[test]
fn test_ciphertext_is_plaintext_length_plus_tag() {
    let k = keys();
    for len in [0usize, 1, 100, 4096] {
        let plaintext = vec![0u8; len];
        let ct = encrypt_payload(&k, &nonce(), &SESSION, &plaintext).unwrap();
        assert_eq!(ct.len(), len + TAG_LEN);
        assert_eq!(ct.len(), ciphertext_len(len));
    }
}

#[test]
fn test_ciphertext_does_not_contain_the_plaintext() {
    let k = keys();
    // A long run of one byte would survive verbatim if the payload were not
    // actually encrypted.
    let plaintext = vec![0xAAu8; 512];
    let ct = encrypt_payload(&k, &nonce(), &SESSION, &plaintext).unwrap();
    assert!(
        !ct.windows(32).any(|w| w == &plaintext[..32]),
        "plaintext appeared verbatim in the ciphertext"
    );
}

#[test]
fn test_encryption_is_deterministic_for_fixed_key_and_nonce() {
    // Determinism is required of the sender: the same transfer must produce a
    // byte-identical frame stream.
    let k = keys();
    let plaintext = b"deterministic";
    assert_eq!(
        encrypt_payload(&k, &nonce(), &SESSION, plaintext).unwrap(),
        encrypt_payload(&k, &nonce(), &SESSION, plaintext).unwrap()
    );
}

// --- Rejection ---

#[test]
fn test_decrypt_rejects_tampered_ciphertext() {
    let k = keys();
    let ct = encrypt_payload(&k, &nonce(), &SESSION, b"secret payload").unwrap();

    for i in 0..ct.len() {
        let mut tampered = ct.clone();
        tampered[i] ^= 0x01;
        assert!(
            decrypt_payload(&k, &nonce(), &SESSION, &tampered).is_err(),
            "mutation at byte {i} decrypted successfully"
        );
    }
}

#[test]
fn test_decrypt_rejects_truncated_ciphertext() {
    let k = keys();
    let ct = encrypt_payload(&k, &nonce(), &SESSION, b"secret payload").unwrap();
    for cut in 0..ct.len() {
        assert!(
            decrypt_payload(&k, &nonce(), &SESSION, &ct[..cut]).is_err(),
            "truncation to {cut} bytes decrypted successfully"
        );
    }
}

#[test]
fn test_decrypt_rejects_appended_bytes() {
    let k = keys();
    let mut ct = encrypt_payload(&k, &nonce(), &SESSION, b"secret payload").unwrap();
    ct.push(0);
    assert!(decrypt_payload(&k, &nonce(), &SESSION, &ct).is_err());
}

#[test]
fn test_decrypt_rejects_empty_input() {
    let k = keys();
    assert!(decrypt_payload(&k, &nonce(), &SESSION, &[]).is_err());
}

#[test]
fn test_decrypt_rejects_wrong_key() {
    let plaintext = b"secret payload";
    let ct = encrypt_payload(&keys(), &nonce(), &SESSION, plaintext).unwrap();

    let other = TransferKeys::derive(
        &OperatorKey::from_bytes([0x99; 32]),
        &Salt::from_bytes([0x22; 32]),
    )
    .unwrap();
    assert!(decrypt_payload(&other, &nonce(), &SESSION, &ct).is_err());
}

#[test]
fn test_decrypt_rejects_wrong_salt() {
    // Same operator key, different transfer salt: the derived key differs, so
    // a capture of one transfer cannot be decrypted as another.
    let operator = OperatorKey::from_bytes([0x11; 32]);
    let a = TransferKeys::derive(&operator, &Salt::from_bytes([0x22; 32])).unwrap();
    let b = TransferKeys::derive(&operator, &Salt::from_bytes([0x23; 32])).unwrap();

    let ct = encrypt_payload(&a, &nonce(), &SESSION, b"secret payload").unwrap();
    assert!(decrypt_payload(&b, &nonce(), &SESSION, &ct).is_err());
}

#[test]
fn test_decrypt_rejects_wrong_nonce() {
    let k = keys();
    let ct = encrypt_payload(&k, &nonce(), &SESSION, b"secret payload").unwrap();
    let other = Nonce::from_bytes([0x34; NONCE_LEN]);
    assert!(decrypt_payload(&k, &other, &SESSION, &ct).is_err());
}

#[test]
fn test_decrypt_rejects_replay_into_another_session() {
    // The session ID is authenticated as associated data, so ciphertext
    // recorded from one session must not decrypt in another.
    let k = keys();
    let ct = encrypt_payload(&k, &nonce(), &SESSION, b"secret payload").unwrap();
    assert!(decrypt_payload(&k, &nonce(), &[0x43; 16], &ct).is_err());
}

// --- Key derivation ---

#[test]
fn test_transfer_keys_are_deterministic() {
    let operator = OperatorKey::from_bytes([0x11; 32]);
    let salt = Salt::from_bytes([0x22; 32]);
    let a = TransferKeys::derive(&operator, &salt).unwrap();
    let b = TransferKeys::derive(&operator, &salt).unwrap();
    assert_eq!(a.payload_key(), b.payload_key());
    assert_eq!(a.session_key(), b.session_key());
}

#[test]
fn test_payload_and_session_keys_differ() {
    let k = keys();
    assert_ne!(k.payload_key(), k.session_key());
}

#[test]
fn test_transfer_keys_are_not_the_operator_key() {
    // The operator key must never be used directly as a wire key.
    let operator = OperatorKey::from_bytes([0x11; 32]);
    let k = TransferKeys::derive(&operator, &Salt::from_bytes([0x22; 32])).unwrap();
    assert_ne!(k.payload_key(), operator.expose_bytes());
    assert_ne!(k.session_key(), operator.expose_bytes());
}

#[test]
fn test_fresh_salt_changes_both_keys() {
    let operator = OperatorKey::from_bytes([0x11; 32]);
    let a = TransferKeys::derive(&operator, &Salt::from_bytes([0x01; 32])).unwrap();
    let b = TransferKeys::derive(&operator, &Salt::from_bytes([0x02; 32])).unwrap();
    assert_ne!(a.payload_key(), b.payload_key());
    assert_ne!(a.session_key(), b.session_key());
}

#[test]
fn test_transfer_keys_debug_is_redacted() {
    let rendered = format!("{:?}", keys());
    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("11"));
}

// --- Nonce and salt generation ---

#[test]
fn test_generated_nonces_differ() {
    assert_ne!(Nonce::generate().unwrap(), Nonce::generate().unwrap());
}

#[test]
fn test_generated_nonce_is_not_all_zeros() {
    assert_ne!(Nonce::generate().unwrap().as_bytes(), &[0u8; NONCE_LEN]);
}

#[test]
fn test_nonce_round_trips_through_bytes() {
    let n = Nonce::generate().unwrap();
    assert_eq!(Nonce::from_bytes(*n.as_bytes()), n);
}

#[test]
fn test_transfer_secrets_are_unique_across_transfers() {
    // Nonce reuse under one key is catastrophic for a stream cipher. Across a
    // batch, neither salt nor nonce may repeat.
    let mut salts = std::collections::HashSet::new();
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..256 {
        let s = TransferParameters::generate().unwrap();
        assert!(salts.insert(*s.salt.as_bytes()), "salt repeated");
        assert!(nonces.insert(*s.nonce.as_bytes()), "nonce repeated");
    }
}

#[test]
fn test_nonce_debug_is_abbreviated() {
    let rendered = format!("{:?}", Nonce::from_bytes([0xAB; NONCE_LEN]));
    assert!(rendered.contains(".."));
    assert!(rendered.len() < 32);
}

/// The in-place and borrowing decryptions must agree byte for byte.
///
/// They are two routes through the same AEAD and one of them is now on the
/// receiver's path. A divergence would not be caught by any round-trip test
/// that used only one of them, which is exactly how a "harmless refactor"
/// changes a construction.
#[test]
fn in_place_decryption_matches_the_borrowing_form() {
    let keys = keys();
    let nonce = nonce();

    for len in [0usize, 1, 15, 16, 17, 1024, 65537] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let ciphertext = encrypt_payload(&keys, &nonce, &SESSION, &plaintext).unwrap();

        let borrowed = decrypt_payload(&keys, &nonce, &SESSION, &ciphertext).unwrap();
        let in_place =
            decrypt_payload_in_place(&keys, &nonce, &SESSION, ciphertext.clone()).unwrap();

        assert_eq!(borrowed, plaintext, "borrowing form at {len} bytes");
        assert_eq!(in_place, plaintext, "in-place form at {len} bytes");
    }
}

/// A tampered ciphertext must fail in place exactly as it does borrowing, and
/// must not return the decrypted prefix it computed before the tag failed.
#[test]
fn in_place_decryption_rejects_tampering_without_leaking_a_prefix() {
    let keys = keys();
    let nonce = nonce();

    let plaintext = vec![0xA5u8; 4096];
    let ciphertext = encrypt_payload(&keys, &nonce, &SESSION, &plaintext).unwrap();

    for offset in [0usize, 1, 2048, 4095, 4096] {
        let mut damaged = ciphertext.clone();
        damaged[offset] ^= 0x01;
        assert!(
            decrypt_payload_in_place(&keys, &nonce, &SESSION, damaged).is_err(),
            "a byte flipped at offset {offset} was accepted"
        );
    }

    // Too short to hold a tag at all.
    assert!(decrypt_payload_in_place(&keys, &nonce, &SESSION, vec![0u8; 4]).is_err());
    assert!(decrypt_payload_in_place(&keys, &nonce, &SESSION, Vec::new()).is_err());
}
