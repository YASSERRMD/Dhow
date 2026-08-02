//! Tests for the session header wire format module.

use crate::session::{
    RaptorQParams, SESSION_HEADER_SIZE, SESSION_MAGIC, SESSION_VERSION, SessionHeader,
    SessionParams, verify_payload_digest,
};
use proptest::prelude::*;

fn test_params() -> SessionParams {
    SessionParams {
        payload_size: 1000,
        block_count: 2,
        symbol_size: 256,
        source_symbols_per_block: 2,
        total_symbols_per_block: 3,
        raptorq: RaptorQParams { z: 2, n: 1, psi: 1 },
        payload_digest: [0xAB; 32],
    }
}

#[test]
fn test_session_header_new() {
    let session_id = [0x42; 16];
    let params = test_params();
    let header = SessionHeader::new(session_id, params);
    assert_eq!(header.magic(), SESSION_MAGIC);
    assert_eq!(header.version(), SESSION_VERSION);
    assert_eq!(header.session_id(), session_id);
    assert_ne!(header.crc32c(), 0);
}

#[test]
fn test_session_header_to_vec_size() {
    let session_id = [0u8; 16];
    let params = test_params();
    let header = SessionHeader::new(session_id, params);
    let bytes = header.to_vec();
    assert_eq!(bytes.len(), SESSION_HEADER_SIZE);
}

#[test]
fn test_session_header_from_bytes_round_trip() {
    let session_id = [0x55; 16];
    let params = test_params();
    let header = SessionHeader::new(session_id, params);
    let bytes = header.to_vec();
    let parsed = SessionHeader::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.magic(), header.magic());
    assert_eq!(parsed.version(), header.version());
    assert_eq!(parsed.session_id(), header.session_id());
    assert_eq!(parsed.params(), header.params());
    assert_eq!(parsed.crc32c(), header.crc32c());
}

#[test]
fn test_session_header_invalid_magic() {
    let mut bytes = vec![0u8; SESSION_HEADER_SIZE];
    bytes[0..4].copy_from_slice(b"XXXX");
    let result = SessionHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_session_header_unsupported_version() {
    let mut bytes = vec![0u8; SESSION_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&SESSION_MAGIC);
    bytes[4] = 99;
    let result = SessionHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_session_header_too_short() {
    let bytes = vec![0u8; SESSION_HEADER_SIZE - 1];
    let result = SessionHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_session_header_crc_mismatch() {
    let session_id = [0; 16];
    let params = test_params();
    let header = SessionHeader::new(session_id, params);
    let mut bytes = header.to_vec();
    // Corrupt the CRC
    bytes[125] = bytes[125].wrapping_add(1);
    let result = SessionHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_verify_payload_digest_correct() {
    let data = b"hello world";
    let expected = crate::blake3::blake3_digest(data);
    assert!(verify_payload_digest(data, &expected));
}

#[test]
fn test_verify_payload_digest_incorrect() {
    let data = b"hello world";
    let wrong = [0u8; 32];
    assert!(!verify_payload_digest(data, &wrong));
}

#[test]
fn test_session_header_reserved_nonzero() {
    let mut bytes = vec![0u8; SESSION_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&SESSION_MAGIC);
    bytes[4] = SESSION_VERSION;
    // Set reserved1 to non-zero
    bytes[5] = 0xFF;
    let result = SessionHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_session_header_reserved2_nonzero() {
    let session_id = [0u8; 16];
    let params = test_params();
    let header = SessionHeader::new(session_id, params);
    let mut bytes = header.to_vec();
    // Set reserved2 to non-zero (offset 90..122)
    bytes[95] = 0xFF;
    let result = SessionHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_session_params_validation_valid() {
    let params = test_params();
    assert!(params.validate().is_ok());
}

#[test]
fn test_session_params_validation_zero_blocks() {
    let mut params = test_params();
    params.block_count = 0;
    assert!(params.validate().is_err());
}

#[test]
fn test_session_params_validation_zero_symbol_size() {
    let mut params = test_params();
    params.symbol_size = 0;
    assert!(params.validate().is_err());
}

#[test]
fn test_raptorq_params_equality() {
    let p1 = RaptorQParams { z: 1, n: 2, psi: 3 };
    let p2 = RaptorQParams { z: 1, n: 2, psi: 3 };
    let p3 = RaptorQParams { z: 1, n: 2, psi: 4 };
    assert_eq!(p1, p2);
    assert_ne!(p1, p3);
}

#[test]
fn test_session_params_equality() {
    let p1 = test_params();
    let mut p2 = test_params();
    assert_eq!(p1, p2);
    p2.block_count = 99;
    assert_ne!(p1, p2);
}

#[test]
fn test_session_params_accessors() {
    let params = test_params();
    let header = SessionHeader::new([0u8; 16], params);
    let p = header.params();
    assert_eq!(p.payload_size, 1000);
    assert_eq!(p.block_count, 2);
    assert_eq!(p.symbol_size, 256);
    assert_eq!(p.source_symbols_per_block, 2);
    assert_eq!(p.total_symbols_per_block, 3);
    assert_eq!(p.raptorq.z, 2);
    assert_eq!(p.raptorq.n, 1);
    assert_eq!(p.raptorq.psi, 1);
    assert_eq!(p.payload_digest, [0xAB; 32]);
}

proptest! {
    #[test]
    fn prop_session_header_round_trip(
        session_id in proptest::array::uniform16(proptest::arbitrary::any::<u8>()),
        payload_size in 1u64..1000000,
        block_count in 1u32..100,
        symbol_size in 1u32..4096,
        source_k in 1u32..100,
        total_k in 1u32..200,
        z in 1u32..50,
        n in 1u32..50,
        psi in 1u16..1000,
    ) {
        let params = SessionParams {
            payload_size,
            block_count,
            symbol_size,
            source_symbols_per_block: source_k,
            total_symbols_per_block: total_k,
            raptorq: RaptorQParams { z, n, psi },
            payload_digest: [0xCD; 32],
        };
        let header = SessionHeader::new(session_id, params);
        let bytes = header.to_vec();
        let parsed = SessionHeader::from_bytes(&bytes).unwrap();
        prop_assert_eq!(parsed.params(), header.params());
        prop_assert_eq!(parsed.crc32c(), header.crc32c());
    }
}
