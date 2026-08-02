//! Tests for the manifest wire format module.

use crate::manifest::{FileEntry, Manifest, ManifestHeader, MANIFEST_MAGIC, MANIFEST_VERSION};

fn test_digest() -> [u8; 32] {
    [0xAB; 32]
}

fn test_signature() -> [u8; 64] {
    [0xCD; 64]
}

fn make_entries() -> Vec<FileEntry> {
    vec![
        FileEntry::new("hello.txt", 5, [0x01; 32]),
        FileEntry::new("world.txt", 10, [0x02; 32]),
    ]
}

#[test]
fn test_file_entry_round_trip() {
    let entry = FileEntry::new("test.txt", 100, [0xFF; 32]);
    let bytes = entry.to_vec();
    let (parsed, consumed) = FileEntry::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.name, "test.txt");
    assert_eq!(parsed.size, 100);
    assert_eq!(parsed.digest, [0xFF; 32]);
}

#[test]
fn test_file_entry_path_traversal() {
    let entry = FileEntry::new("../../etc/passwd", 0, [0; 32]);
    let bytes = entry.to_vec();
    let result = FileEntry::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_file_entry_too_long_name() {
    let long_name = "a".repeat(5000);
    let entry = FileEntry::new(&long_name, 0, [0; 32]);
    let bytes = entry.to_vec();
    let result = FileEntry::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_manifest_header_new() {
    let entries = make_entries();
    let header = ManifestHeader::new([0x42; 16], &entries, 15);
    assert_eq!(header.magic(), MANIFEST_MAGIC);
    assert_eq!(header.version(), MANIFEST_VERSION);
    assert_eq!(header.file_count(), 2);
    assert_eq!(header.total_size(), 15);
    assert_ne!(header.crc32c(), 0);
}

#[test]
fn test_manifest_header_to_vec_size() {
    let entries = make_entries();
    let header = ManifestHeader::new([0x42; 16], &entries, 15);
    let bytes = header.to_vec();
    assert_eq!(bytes.len(), 168);
}

#[test]
fn test_file_entry_truncated() {
    let entry = FileEntry::new("test.txt", 0, [0; 32]);
    let mut bytes = entry.to_vec();
    bytes.truncate(5);
    let result = FileEntry::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_file_entry_null_byte() {
    let entry = FileEntry::new("test\0.txt", 0, [0; 32]);
    let bytes = entry.to_vec();
    let result = FileEntry::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_manifest_header_from_bytes_round_trip() {
    let entries = make_entries();
    let header = ManifestHeader::new([0x55; 16], &entries, 15);
    let bytes = header.to_vec();
    let parsed = ManifestHeader::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.magic(), header.magic());
    assert_eq!(parsed.version(), header.version());
    assert_eq!(parsed.session_id(), header.session_id());
    assert_eq!(parsed.file_count(), header.file_count());
    assert_eq!(parsed.total_size(), header.total_size());
    assert_eq!(parsed.crc32c(), header.crc32c());
}

#[test]
fn test_manifest_header_invalid_magic() {
    let entries = make_entries();
    let header = ManifestHeader::new([0; 16], &entries, 15);
    let mut bytes = header.to_vec();
    bytes[0..4].copy_from_slice(b"XXXX");
    let result = ManifestHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_manifest_header_crc_mismatch() {
    let entries = make_entries();
    let header = ManifestHeader::new([0; 16], &entries, 15);
    let mut bytes = header.to_vec();
    // Corrupt CRC
    bytes[103] = bytes[103].wrapping_add(1);
    let result = ManifestHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_manifest_header_too_short() {
    let bytes = vec![0u8; 100];
    let result = ManifestHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_manifest_round_trip() {
    let entries = make_entries();
    let header = ManifestHeader::new([0x42; 16], &entries, 15);
    let signature = test_signature();
    let manifest = Manifest::build(&header, &entries, &signature);
    let bytes = manifest.to_vec();

    let parsed = Manifest::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.header().file_count(), 2);
    assert_eq!(parsed.entries().len(), 2);
    assert_eq!(parsed.entries()[0].name, "hello.txt");
    assert_eq!(parsed.entries()[1].name, "world.txt");
}

#[test]
fn test_manifest_empty_entries() {
    let header = ManifestHeader::new([0; 16], &[], 0);
    let manifest = Manifest::build(&header, &[], &test_signature());
    let bytes = manifest.to_vec();
    let parsed = Manifest::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.entries().len(), 0);
}

#[test]
fn test_manifest_header_accessors() {
    let entries = make_entries();
    let header = ManifestHeader::new([0xAA; 16], &entries, 100);
    assert_eq!(header.magic(), MANIFEST_MAGIC);
    assert_eq!(header.version(), MANIFEST_VERSION);
    assert_eq!(header.session_id(), [0xAA; 16]);
    assert_eq!(header.file_count(), 2);
    assert_eq!(header.total_size(), 100);
    assert_eq!(header.crc32c(), header.crc32c());
    assert_eq!(header.signature(), [0u8; 64]);
}

use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_manifest_round_trip(
        name in "[a-zA-Z0-9_]+"
    ) {
        let filename = format!("{}.txt", name);
        let entries = vec![FileEntry::new(&filename, 100, [0xAA; 32])];
        let header = ManifestHeader::new([0x42; 16], &entries, 100);
        let manifest = Manifest::build(&header, &entries, &[0xCD; 64]);
        let bytes = manifest.to_vec();
        let parsed = Manifest::from_bytes(&bytes).unwrap();
        prop_assert_eq!(parsed.entries().len(), 1);
        prop_assert_eq!(parsed.entries()[0].name.clone(), filename);
    }
}
