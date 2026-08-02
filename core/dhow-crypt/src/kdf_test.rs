//! Tests for HKDF-BLAKE3 key derivation.

use crate::kdf::*;

const IKM: &[u8] = b"operator key material";

fn salt_a() -> Salt {
    Salt::from_bytes([1u8; SALT_LEN])
}

fn salt_b() -> Salt {
    Salt::from_bytes([2u8; SALT_LEN])
}

#[test]
fn test_derivation_is_deterministic() {
    let a = derive_key(&salt_a(), IKM, b"info").unwrap();
    let b = derive_key(&salt_a(), IKM, b"info").unwrap();
    assert_eq!(a, b);
}

#[test]
fn test_different_salts_give_different_keys() {
    let a = derive_key(&salt_a(), IKM, b"info").unwrap();
    let b = derive_key(&salt_b(), IKM, b"info").unwrap();
    assert_ne!(a, b, "salt must affect the derived key");
}

#[test]
fn test_different_info_gives_different_keys() {
    let a = derive_key(&salt_a(), IKM, b"info one").unwrap();
    let b = derive_key(&salt_a(), IKM, b"info two").unwrap();
    assert_ne!(a, b, "info must separate domains");
}

#[test]
fn test_different_ikm_gives_different_keys() {
    let a = derive_key(&salt_a(), b"key one", b"info").unwrap();
    let b = derive_key(&salt_a(), b"key two", b"info").unwrap();
    assert_ne!(a, b);
}

#[test]
fn test_payload_and_session_keys_are_independent() {
    // The two keys a transfer uses must not be derivable from one another.
    let payload = derive_key(&salt_a(), IKM, INFO_PAYLOAD_KEY).unwrap();
    let session = derive_key(&salt_a(), IKM, INFO_SESSION_KEY).unwrap();
    assert_ne!(payload, session);
}

#[test]
fn test_derive_returns_requested_length() {
    for len in [0usize, 1, 31, 32, 33, 64, 100, 1000] {
        assert_eq!(derive(&salt_a(), IKM, b"info", len).unwrap().len(), len);
    }
}

#[test]
fn test_output_is_a_prefix_stream() {
    // HKDF output of length n is the first n bytes of any longer output, so a
    // short derivation and a long one must agree on their common prefix.
    let long = derive(&salt_a(), IKM, b"info", 128).unwrap();
    for len in [1usize, 16, 32, 33, 64, 96] {
        let short = derive(&salt_a(), IKM, b"info", len).unwrap();
        assert_eq!(short, long[..len], "prefix mismatch at length {len}");
    }
}

#[test]
fn test_blocks_are_not_repeated() {
    // A counter bug would make block two equal block one.
    let out = derive(&salt_a(), IKM, b"info", 96).unwrap();
    assert_ne!(out[0..32], out[32..64]);
    assert_ne!(out[32..64], out[64..96]);
    assert_ne!(out[0..32], out[64..96]);
}

#[test]
fn test_derive_rejects_output_beyond_the_block_limit() {
    assert!(derive(&salt_a(), IKM, b"info", MAX_OKM_LEN).is_ok());
    assert!(derive(&salt_a(), IKM, b"info", MAX_OKM_LEN + 1).is_err());
}

#[test]
fn test_generated_salts_differ() {
    let a = Salt::generate().unwrap();
    let b = Salt::generate().unwrap();
    assert_ne!(a, b);
}

#[test]
fn test_generated_salt_is_not_all_zeros() {
    assert_ne!(Salt::generate().unwrap().as_bytes(), &[0u8; SALT_LEN]);
}

#[test]
fn test_salt_round_trips_through_bytes() {
    let salt = Salt::generate().unwrap();
    assert_eq!(Salt::from_bytes(*salt.as_bytes()), salt);
}

#[test]
fn test_salt_debug_is_abbreviated() {
    // The salt is not secret, but its Debug should not dump 32 bytes into logs.
    let rendered = format!("{:?}", Salt::from_bytes([0xAB; SALT_LEN]));
    assert!(rendered.contains(".."));
    assert!(rendered.len() < 32);
}

#[test]
fn test_empty_ikm_and_info_are_accepted() {
    // Edge inputs must not panic; HKDF is defined for empty IKM and info.
    assert!(derive_key(&salt_a(), b"", b"").is_ok());
}
