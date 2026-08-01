//! Tests for the frame wire format module.

use crate::frame::{Frame, FrameHeader, FrameType, FRAME_HEADER_SIZE, MAGIC, VERSION};
use proptest::prelude::*;

fn test_key() -> [u8; 32] {
    [0xAB; 32]
}

#[test]
fn test_frame_mac_deterministic() {
    let session_id = [0x55; 16];
    let key = [0xAB; 32];
    let header1 = FrameHeader::new(FrameType::Repair, session_id, 0, 1, b"test");
    let header2 = FrameHeader::new(FrameType::Repair, session_id, 0, 1, b"test");
    assert_eq!(header1.compute_mac(&key), header2.compute_mac(&key));
}

#[test]
fn test_frame_payload_truncated() {
    let session_id = [0; 16];
    let key = test_key();
    let header = FrameHeader::new(FrameType::Repair, session_id, 0, 0, b"full payload");
    let frame = Frame::build(&header, b"full payload", &key);
    let mut bytes = frame.to_vec();

    // Truncate the payload
    bytes.truncate(FRAME_HEADER_SIZE + 5);

    let result = Frame::from_bytes(&bytes, &key);
    assert!(result.is_err());
}

#[test]
fn test_frame_header_field_accessors() {
    let session_id = [0x42; 16];
    let header = FrameHeader::new(FrameType::Repair, session_id, 3, 7, b"test");
    assert_eq!(header.magic(), MAGIC);
    assert_eq!(header.version(), VERSION);
    assert_eq!(header.frame_type(), FrameType::Repair);
    assert_eq!(header.frame_type_raw(), 1);
    assert_eq!(header.session_id(), session_id);
    assert_eq!(header.block_index(), 3);
    assert_eq!(header.symbol_index(), 7);
    assert_eq!(header.payload_length(), 4);
    assert_eq!(header.reserved(), 0);
    assert_ne!(header.crc32c(), 0);
}

#[test]
fn test_frame_header_all_frame_types() {
    let session_id = [0; 16];
    for ft in [FrameType::Session, FrameType::Repair, FrameType::Manifest] {
        let header = FrameHeader::new(ft, session_id, 0, 0, b"x");
        assert_eq!(header.frame_type(), ft);
    }
}

#[test]
fn test_frame_type_values() {
    assert_eq!(FrameType::Session as u8, 0);
    assert_eq!(FrameType::Repair as u8, 1);
    assert_eq!(FrameType::Manifest as u8, 2);
}

#[test]
fn test_frame_type_try_from_valid() {
    assert_eq!(FrameType::try_from(0u8).unwrap(), FrameType::Session);
    assert_eq!(FrameType::try_from(1u8).unwrap(), FrameType::Repair);
    assert_eq!(FrameType::try_from(2u8).unwrap(), FrameType::Manifest);
}

#[test]
fn test_frame_type_try_from_invalid() {
    let result = FrameType::try_from(99u8);
    assert!(result.is_err());
}

#[test]
fn test_frame_header_new() {
    let session_id = [1u8; 16];
    let header = FrameHeader::new(FrameType::Repair, session_id, 0, 1, b"hello");
    assert_eq!(header.magic(), MAGIC);
    assert_eq!(header.version(), VERSION);
    assert_eq!(header.frame_type(), FrameType::Repair);
    assert_eq!(header.session_id(), session_id);
    assert_eq!(header.block_index(), 0);
    assert_eq!(header.symbol_index(), 1);
    assert_eq!(header.payload_length(), 5);
    assert_ne!(header.crc32c(), 0);
}

#[test]
fn test_frame_header_to_vec_size() {
    let session_id = [0u8; 16];
    let header = FrameHeader::new(FrameType::Session, session_id, 0, 0, b"test");
    let bytes = header.to_vec();
    assert_eq!(bytes.len(), FRAME_HEADER_SIZE);
}

#[test]
fn test_frame_header_from_bytes_round_trip() {
    let session_id = [0x42; 16];
    let header = FrameHeader::new(FrameType::Manifest, session_id, 5, 3, b"payload data here");
    let mut header = header;
    header.set_mac([0xFF; 8]);
    let bytes = header.to_vec();
    let parsed = FrameHeader::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, header);
}

#[test]
fn test_frame_header_invalid_magic() {
    let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
    bytes[0..4].copy_from_slice(b"XXXX");
    let result = FrameHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_frame_header_unsupported_version() {
    let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4] = 99;
    let result = FrameHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_frame_header_too_short() {
    let bytes = vec![0u8; FRAME_HEADER_SIZE - 1];
    let result = FrameHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_frame_round_trip() {
    let session_id = [0xAA; 16];
    let key = test_key();
    let header = FrameHeader::new(FrameType::Repair, session_id, 2, 7, b"test payload");
    let frame = Frame::build(&header, b"test payload", &key);
    let bytes = frame.to_vec();

    let parsed = Frame::from_bytes(&bytes, &key).unwrap();
    assert_eq!(parsed.payload(), b"test payload");
    assert_eq!(parsed.header().frame_type(), FrameType::Repair);
    assert_eq!(parsed.header().block_index(), 2);
    assert_eq!(parsed.header().symbol_index(), 7);
}

#[test]
fn test_frame_mac_verification() {
    let session_id = [0xBB; 16];
    let key = test_key();
    let header = FrameHeader::new(FrameType::Session, session_id, 0, 0, b"hello");
    let frame = Frame::build(&header, b"hello", &key);
    let bytes = frame.to_vec();

    // Correct key should work
    let parsed = Frame::from_bytes(&bytes, &key);
    assert!(parsed.is_ok());

    // Wrong key should fail
    let wrong_key = [0xCC; 32];
    let parsed_wrong = Frame::from_bytes(&bytes, &wrong_key);
    assert!(parsed_wrong.is_err());
}

#[test]
fn test_frame_crc_mismatch() {
    let session_id = [0; 16];
    let key = test_key();
    let header = FrameHeader::new(FrameType::Repair, session_id, 0, 1, b"original");
    let frame = Frame::build(&header, b"original", &key);
    let mut bytes = frame.to_vec();

    // Corrupt the payload
    let payload_offset = FRAME_HEADER_SIZE;
    bytes[payload_offset] = bytes[payload_offset].wrapping_add(1);

    let result = Frame::from_bytes(&bytes, &key);
    assert!(result.is_err());
}

#[test]
fn test_frame_empty_payload() {
    let session_id = [0; 16];
    let key = test_key();
    let header = FrameHeader::new(FrameType::Session, session_id, 0, 0, b"");
    let frame = Frame::build(&header, b"", &key);
    let bytes = frame.to_vec();

    let parsed = Frame::from_bytes(&bytes, &key).unwrap();
    assert!(parsed.payload().is_empty());
}

#[test]
fn test_frame_large_payload() {
    let session_id = [0; 16];
    let key = test_key();
    let payload: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
    let header = FrameHeader::new(FrameType::Manifest, session_id, 10, 5, &payload);
    let frame = Frame::build(&header, &payload, &key);
    let bytes = frame.to_vec();

    let parsed = Frame::from_bytes(&bytes, &key).unwrap();
    assert_eq!(parsed.payload(), &payload[..]);
}

#[test]
fn test_frame_mac_with_zero_key() {
    let session_id = [0; 16];
    let key = [0u8; 32];
    let header = FrameHeader::new(FrameType::Session, session_id, 0, 0, b"zero key");
    let frame = Frame::build(&header, b"zero key", &key);
    let bytes = frame.to_vec();

    let parsed = Frame::from_bytes(&bytes, &key).unwrap();
    assert_eq!(parsed.payload(), b"zero key");
}

proptest! {
    #[test]
    fn prop_frame_round_trip(
        payload in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 1..2000usize)
    ) {
        let session_id = [0x42; 16];
        let key = [0xAB; 32];
        let header = FrameHeader::new(FrameType::Repair, session_id, 0, 0, &payload);
        let frame = Frame::build(&header, &payload, &key);
        let bytes = frame.to_vec();
        let parsed = Frame::from_bytes(&bytes, &key).unwrap();
        prop_assert_eq!(parsed.payload(), &payload[..]);
    }
}
