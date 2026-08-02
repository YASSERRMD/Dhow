//! Tests for the resume file wire format module.

use crate::resume::{
    BlockEntry, ResumeFile, ResumeHeader, RESUME_HEADER_SIZE, RESUME_MAGIC, RESUME_VERSION,
};

fn make_entries() -> Vec<BlockEntry> {
    let mut bitmap = vec![0u8; 1];
    bitmap[0] = 0b00000101;
    vec![
        BlockEntry::new(0, 8, 2, &bitmap),
        BlockEntry::new(1, 8, 1, &[0b00000001]),
    ]
}

#[test]
fn test_block_entry_round_trip() {
    let entry = BlockEntry::new(0, 8, 2, &[0b00000101]); // 8 symbols = 1 byte bitmap
    let bytes = entry.to_vec();
    let (parsed, consumed) = BlockEntry::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.block_index, 0);
    assert_eq!(parsed.symbol_count, 8);
    assert_eq!(parsed.symbols_held, 2);
    assert_eq!(parsed.symbol_bitmap, vec![0b00000101]);
}

#[test]
fn test_block_entry_truncated() {
    let bytes = vec![0u8; 5];
    let result = BlockEntry::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_block_entry_large_bitmap() {
    let bitmap = vec![0xFF; 16]; // 128 symbols
    let entry = BlockEntry::new(5, 128, 128, &bitmap);
    let bytes = entry.to_vec();
    let (parsed, _) = BlockEntry::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.symbol_count, 128);
    assert_eq!(parsed.symbol_bitmap.len(), 16);
}

#[test]
fn test_resume_header_new() {
    let entries = make_entries();
    let header = ResumeHeader::new([0x42; 16], &entries);
    assert_eq!(header.magic(), RESUME_MAGIC);
    assert_eq!(header.version(), RESUME_VERSION);
    assert_eq!(header.block_count(), 2);
    assert_ne!(header.crc32c(), 0);
    assert_ne!(header.integrity_digest(), [0u8; 32]);
}

#[test]
fn test_resume_header_to_vec_size() {
    let entries = make_entries();
    let header = ResumeHeader::new([0x42; 16], &entries);
    let bytes = header.to_vec();
    assert_eq!(bytes.len(), RESUME_HEADER_SIZE);
}

#[test]
fn test_resume_header_from_bytes_round_trip() {
    let entries = make_entries();
    let header = ResumeHeader::new([0x55; 16], &entries);
    let bytes = header.to_vec();
    let parsed = ResumeHeader::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.magic(), header.magic());
    assert_eq!(parsed.version(), header.version());
    assert_eq!(parsed.session_id(), header.session_id());
    assert_eq!(parsed.block_count(), header.block_count());
    assert_eq!(parsed.crc32c(), header.crc32c());
    assert_eq!(parsed.integrity_digest(), header.integrity_digest());
}

#[test]
fn test_resume_header_invalid_magic() {
    let mut bytes = vec![0u8; RESUME_HEADER_SIZE];
    bytes[0..4].copy_from_slice(b"XXXX");
    let result = ResumeHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_resume_header_unsupported_version() {
    let mut bytes = vec![0u8; RESUME_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&RESUME_MAGIC);
    bytes[4] = 99;
    let result = ResumeHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_resume_header_too_short() {
    let bytes = vec![0u8; RESUME_HEADER_SIZE - 1];
    let result = ResumeHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_resume_header_crc_mismatch() {
    let entries = make_entries();
    let header = ResumeHeader::new([0; 16], &entries);
    let mut bytes = header.to_vec();
    // Corrupt CRC (at offset 60..64)
    bytes[60] = bytes[60].wrapping_add(1);
    let result = ResumeHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_resume_header_integrity_digest_mismatch() {
    let entries = make_entries();
    let header = ResumeHeader::new([0; 16], &entries);
    let mut bytes = header.to_vec();
    // Corrupt integrity digest (at offset 64..96)
    bytes[64] = bytes[64].wrapping_add(1);
    let result = ResumeHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_resume_round_trip() {
    let session_id = [0xAA; 16];
    let entries = make_entries();
    let header = ResumeHeader::new(session_id, &entries);
    let resume = ResumeFile::build(&header, &entries);
    let bytes = resume.to_vec();

    let parsed = ResumeFile::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.header().session_id(), session_id);
    assert_eq!(parsed.entries().len(), 2);
    assert_eq!(parsed.entries()[0].block_index, 0);
    assert_eq!(parsed.entries()[1].block_index, 1);
}

#[test]
fn test_resume_empty_entries() {
    let header = ResumeHeader::new([0; 16], &[]);
    let resume = ResumeFile::build(&header, &[]);
    let bytes = resume.to_vec();
    let parsed = ResumeFile::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.entries().len(), 0);
}

#[test]
fn test_resume_truncated_block_entries() {
    let entries = make_entries();
    let header = ResumeHeader::new([0; 16], &entries);
    let resume = ResumeFile::build(&header, &entries);
    let mut bytes = resume.to_vec();
    // Truncate block entries
    bytes.truncate(RESUME_HEADER_SIZE + 5);
    let result = ResumeFile::from_bytes(&bytes);
    assert!(result.is_err());
}

    #[test]
    fn test_resume_header_accessors() {
        let entries = make_entries();
        let header = ResumeHeader::new([0x55; 16], &entries);
        assert_eq!(header.magic(), RESUME_MAGIC);
        assert_eq!(header.version(), RESUME_VERSION);
        assert_eq!(header.session_id(), [0x55; 16]);
        assert_eq!(header.block_count(), 2);
        assert_ne!(header.crc32c(), 0);
        assert_ne!(header.integrity_digest(), [0u8; 32]);
    }

    #[test]
    fn test_resume_file_accessors() {
        let entries = make_entries();
        let header = ResumeHeader::new([0xAA; 16], &entries);
        let resume = ResumeFile::build(&header, &entries);
        assert_eq!(resume.session_id(), [0xAA; 16]);
        assert_eq!(resume.block_count(), 2);
        assert_eq!(resume.entries().len(), 2);
    }

    #[test]
    fn test_block_entry_equality() {
        let e1 = BlockEntry::new(0, 8, 2, &[0b00000101]);
        let e2 = BlockEntry::new(0, 8, 2, &[0b00000101]);
        let e3 = BlockEntry::new(0, 8, 2, &[0b00000010]);
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }
