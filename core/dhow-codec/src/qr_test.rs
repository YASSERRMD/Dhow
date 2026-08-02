//! Tests for the QR code encoding module.

use crate::qr::{QrCodeEncoder, QrError};

#[test]
fn test_qr_encode_simple() {
    let data = b"hello world";
    let qr = QrCodeEncoder::encode(data).unwrap();
    assert!(qr.version() >= 1);
    assert!(qr.size() >= 21);
}

#[test]
fn test_qr_size_consistent() {
    let data = b"test data for QR";
    let qr = QrCodeEncoder::encode(data).unwrap();
    let size = qr.size();
    // QR code version v has size v*4+17
    // For small data, version 1 (size 21) should be used
    assert!(size >= 21);
}

#[test]
fn test_qr_to_terminal_not_empty() {
    let data = b"hello";
    let qr = QrCodeEncoder::encode(data).unwrap();
    let terminal_str = qr.to_terminal();
    assert!(!terminal_str.is_empty());
    assert!(terminal_str.contains('\n'));
}

#[test]
fn test_qr_to_terminal_dimensions() {
    let data = b"hello";
    let qr = QrCodeEncoder::encode(data).unwrap();
    let terminal_str = qr.to_terminal();
    let lines: Vec<&str> = terminal_str.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), qr.size());
    for line in &lines {
        // Each line should have 2 * size characters (each module is 2 chars)
        assert_eq!(line.chars().count(), qr.size() * 2);
    }
}

#[test]
fn test_qr_encode_large_data() {
    let data: Vec<u8> = (0..200).map(|i| (i % 256) as u8).collect();
    let qr = QrCodeEncoder::encode(&data).unwrap();
    assert!(qr.version() >= 1);
}

#[test]
fn test_qr_data_too_large() {
    // Create data that exceeds even the largest QR code capacity
    let data: Vec<u8> = vec![0u8; 3000];
    let result = QrCodeEncoder::encode(&data);
    assert!(result.is_err());
}

#[test]
fn test_qr_error_message() {
    let err = QrError::DataTooLong;
    assert!(err.to_string().contains("too large"));
}

#[test]
fn test_qr_empty_data() {
    let qr = QrCodeEncoder::encode(b"").unwrap();
    assert!(qr.version() >= 1);
}

#[test]
fn test_qr_single_byte() {
    let qr = QrCodeEncoder::encode(&[42]).unwrap();
    assert!(qr.size() >= 21);
}

#[test]
fn test_qr_get_module() {
    let qr = QrCodeEncoder::encode(b"test").unwrap();
    let size = qr.size();
    // Verify get_module doesn't panic for valid coordinates
    for x in 0..size {
        for y in 0..size {
            let _ = qr.get_module(x, y);
        }
    }
}

#[test]
fn test_qr_inner() {
    let qr = QrCodeEncoder::encode(b"test").unwrap();
    let inner = qr.inner();
    assert_eq!(inner.size(), qr.size() as i32);
}

use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_qr_encode_small_data(
        data in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 1..200)
    ) {
        let qr = QrCodeEncoder::encode(&data);
        prop_assert!(qr.is_ok());
        let qr = qr.unwrap();
        prop_assert!(qr.version() >= 1);
        prop_assert!(qr.size() >= 21);
    }
}
