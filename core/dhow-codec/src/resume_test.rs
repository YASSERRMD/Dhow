//! Tests for the resume file wire format module.

use proptest::prelude::*;

use crate::ResumeError;
use crate::resume::{
    BLOCK_ENTRY_HEADER_SIZE, CRC_COVER_BYTES, INTEGRITY_COVER_BYTES, RESUME_HEADER_SIZE,
    RESUME_MAGIC, RESUME_VERSION, ResumeFile, ResumeHeader,
};

const JOURNAL_BYTES: u64 = 4096;
const JOURNAL_DIGEST: [u8; 32] = [0x9C; 32];

/// Builds a bitmap of `symbol_count` symbols with `held` listed as present.
fn bitmap_of(symbol_count: u32, held: &[u32]) -> Vec<u8> {
    let mut bitmap = vec![0u8; (symbol_count as usize).div_ceil(8)];
    for &symbol in held {
        bitmap[symbol as usize / 8] |= 1 << (symbol % 8);
    }
    bitmap
}

/// Builds a block entry whose declared count and bitmap agree.
fn entry(block_index: u32, symbol_count: u32, held: &[u32]) -> BlockEntry {
    BlockEntry::new(
        block_index,
        symbol_count,
        held.len() as u32,
        &bitmap_of(symbol_count, held),
    )
}

use crate::resume::BlockEntry;

fn make_entries() -> Vec<BlockEntry> {
    vec![entry(0, 8, &[0, 2]), entry(1, 8, &[0])]
}

fn make_file() -> ResumeFile {
    let entries = make_entries();
    ResumeFile::new([0xAA; 16], JOURNAL_BYTES, JOURNAL_DIGEST, &entries)
}

// --- Block entries ---

#[test]
fn test_block_entry_round_trip() {
    let e = entry(0, 8, &[0, 2]);
    let bytes = e.to_vec();
    let (parsed, consumed) = BlockEntry::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, e);
    assert_eq!(parsed.symbol_bitmap, vec![0b0000_0101]);
}

#[test]
fn test_block_entry_bitmap_length_follows_the_symbol_count() {
    // 100 symbols need 13 bytes, and the parser must size the bitmap from the
    // declared count rather than from whatever is left in the buffer.
    let e = entry(5, 100, &[0, 7, 8, 99]);
    let (parsed, consumed) = BlockEntry::from_bytes(&e.to_vec()).unwrap();
    assert_eq!(parsed.symbol_bitmap.len(), 13);
    assert_eq!(consumed, BLOCK_ENTRY_HEADER_SIZE + 13);
    assert_eq!(parsed.symbols_held, 4);
}

#[test]
fn test_block_entry_rejects_a_short_buffer() {
    let err = BlockEntry::from_bytes(&[0u8; 5]).unwrap_err();
    assert!(
        matches!(
            err,
            ResumeError::Truncated {
                expected: BLOCK_ENTRY_HEADER_SIZE,
                actual: 5
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn test_block_entry_rejects_a_bitmap_cut_short() {
    let mut bytes = entry(0, 64, &[0, 1, 2]).to_vec();
    bytes.truncate(bytes.len() - 1);
    let err = BlockEntry::from_bytes(&bytes).unwrap_err();
    assert!(
        matches!(err, ResumeError::Truncated { expected: 20, .. }),
        "got {err:?}"
    );
}

#[test]
fn test_block_entry_rejects_a_count_the_bitmap_contradicts() {
    // The declared count and the bitmap are two views of one fact. A file
    // where they disagree is wrong in a way no reader can reconcile.
    let mut bytes = entry(0, 8, &[0, 2]).to_vec();
    bytes[8] = 5; // claim five held, bitmap has two
    let err = BlockEntry::from_bytes(&bytes).unwrap_err();
    assert!(
        matches!(
            err,
            ResumeError::HeldCountMismatch {
                declared: 5,
                bitmap: 2
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn test_block_entry_rejects_more_held_than_exist() {
    let mut bytes = entry(0, 8, &[0, 2]).to_vec();
    bytes[8..12].copy_from_slice(&99u32.to_le_bytes());
    let err = BlockEntry::from_bytes(&bytes).unwrap_err();
    assert!(
        matches!(err, ResumeError::InvalidSymbolCount { count: 99 }),
        "got {err:?}"
    );
}

#[test]
fn test_block_entry_rejects_bits_past_the_symbol_count() {
    // 12 symbols occupy 12 of the 16 bits in two bytes. Bits 12..16 name
    // symbols the session does not have.
    let mut bytes = entry(0, 12, &[0, 1]).to_vec();
    bytes[BLOCK_ENTRY_HEADER_SIZE + 1] |= 0b1000_0000;
    bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
    let err = BlockEntry::from_bytes(&bytes).unwrap_err();
    assert!(
        matches!(err, ResumeError::InvalidSymbolCount { count: 12 }),
        "got {err:?}"
    );
}

#[test]
fn test_block_entry_equality() {
    assert_eq!(entry(0, 8, &[0, 2]), entry(0, 8, &[0, 2]));
    assert_ne!(entry(0, 8, &[0, 2]), entry(0, 8, &[1]));
}

// --- Header ---

#[test]
fn test_resume_header_round_trip_carries_every_field() {
    let entries = make_entries();
    let header = ResumeHeader::new([0x55; 16], JOURNAL_BYTES, JOURNAL_DIGEST, &entries);
    let bytes = header.to_vec();
    assert_eq!(bytes.len(), RESUME_HEADER_SIZE);

    let parsed = ResumeHeader::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.magic(), RESUME_MAGIC);
    assert_eq!(parsed.version(), RESUME_VERSION);
    assert_eq!(parsed.session_id(), [0x55; 16]);
    assert_eq!(parsed.block_count(), 2);
    assert_eq!(parsed.journal_bytes(), JOURNAL_BYTES);
    assert_eq!(parsed.journal_digest(), JOURNAL_DIGEST);
    assert_eq!(parsed.crc32c(), header.crc32c());
    assert_eq!(parsed.integrity_digest(), header.integrity_digest());
}

#[test]
fn test_resume_header_rejects_foreign_magic() {
    let mut bytes = make_file().to_vec();
    bytes[0..4].copy_from_slice(b"XXXX");
    let err = ResumeHeader::from_bytes(&bytes).unwrap_err();
    assert!(
        matches!(err, ResumeError::InvalidMagic { got } if got == *b"XXXX"),
        "got {err:?}"
    );
}

#[test]
fn test_resume_header_rejects_version_one() {
    // Version 1 had no journal binding, so its progress record cannot be
    // checked against anything. Reading one as if it were current would mean
    // trusting a journal on its own say-so.
    let mut bytes = make_file().to_vec();
    bytes[4] = 1;
    let err = ResumeHeader::from_bytes(&bytes).unwrap_err();
    assert!(
        matches!(err, ResumeError::UnsupportedVersion { version: 1 }),
        "got {err:?}"
    );
}

#[test]
fn test_resume_header_rejects_a_future_version() {
    let mut bytes = make_file().to_vec();
    bytes[4] = RESUME_VERSION + 1;
    let err = ResumeHeader::from_bytes(&bytes).unwrap_err();
    assert!(
        matches!(err, ResumeError::UnsupportedVersion { .. }),
        "got {err:?}"
    );
}

#[test]
fn test_resume_header_rejects_a_short_buffer() {
    for len in [0usize, 1, RESUME_HEADER_SIZE - 1] {
        let bytes = make_file().to_vec();
        let err = ResumeHeader::from_bytes(&bytes[..len]).unwrap_err();
        assert!(
            matches!(
                err,
                ResumeError::Truncated {
                    expected: RESUME_HEADER_SIZE,
                    ..
                }
            ),
            "len {len} got {err:?}"
        );
    }
}

#[test]
fn test_resume_header_rejects_a_filled_reserved_field() {
    for offset in [5usize, 68] {
        let mut bytes = make_file().to_vec();
        bytes[offset] = 1;
        // Keep the CRC and digest honest so the reserved check is what bites,
        // not the integrity check standing in for it.
        let err = ResumeHeader::from_bytes(&reseal(&mut bytes)).unwrap_err();
        assert!(
            matches!(err, ResumeError::ReservedNotZero { offset: o } if o == offset),
            "offset {offset} got {err:?}"
        );
    }
}

/// Recomputes the CRC and integrity digest over a mutated header.
///
/// Used to isolate a field check from the integrity check: without this every
/// mutation fails at the digest and the field check is never exercised.
fn reseal(bytes: &mut [u8]) -> Vec<u8> {
    let crc = crate::crc32c::crc32c_digest(&bytes[0..CRC_COVER_BYTES]);
    bytes[CRC_COVER_BYTES..CRC_COVER_BYTES + 4].copy_from_slice(&crc.to_le_bytes());
    let digest = crate::blake3::blake3_digest(&bytes[0..INTEGRITY_COVER_BYTES]);
    bytes[INTEGRITY_COVER_BYTES..INTEGRITY_COVER_BYTES + 32].copy_from_slice(&digest);
    bytes.to_vec()
}

#[test]
fn test_resume_header_notices_every_single_byte_flip_in_its_covered_range() {
    // A resume file that survives on disk through a crash is exactly the file
    // most likely to have been half-written. Every byte the digests cover must
    // be load-bearing.
    let good = make_file().to_vec();
    for offset in 0..RESUME_HEADER_SIZE {
        let mut bytes = good.clone();
        bytes[offset] ^= 0x01;

        let result = ResumeHeader::from_bytes(&bytes);
        assert!(
            result.is_err(),
            "flipping byte {offset} of the header was not noticed"
        );
    }
}

#[test]
fn test_resume_header_crc_and_digest_are_checked_separately() {
    let mut bytes = make_file().to_vec();
    bytes[CRC_COVER_BYTES] ^= 0x01;
    assert!(matches!(
        ResumeHeader::from_bytes(&bytes).unwrap_err(),
        ResumeError::IntegrityCheckFailed
    ));

    let mut bytes = make_file().to_vec();
    bytes[INTEGRITY_COVER_BYTES] ^= 0x01;
    assert!(matches!(
        ResumeHeader::from_bytes(&bytes).unwrap_err(),
        ResumeError::IntegrityCheckFailed
    ));
}

// --- Whole file ---

#[test]
fn test_resume_round_trip() {
    let parsed = ResumeFile::from_bytes(&make_file().to_vec()).unwrap();
    assert_eq!(parsed.session_id(), [0xAA; 16]);
    assert_eq!(parsed.block_count(), 2);
    assert_eq!(parsed.journal_bytes(), JOURNAL_BYTES);
    assert_eq!(parsed.journal_digest(), JOURNAL_DIGEST);
    assert_eq!(parsed.entries(), make_entries().as_slice());
}

#[test]
fn test_resume_with_no_blocks_round_trips() {
    let file = ResumeFile::new([0; 16], 0, [0; 32], &[]);
    let parsed = ResumeFile::from_bytes(&file.to_vec()).unwrap();
    assert_eq!(parsed.entries().len(), 0);
    assert_eq!(parsed.journal_bytes(), 0);
}

#[test]
fn test_resume_rejects_entries_out_of_block_order() {
    let entries = vec![entry(1, 8, &[0]), entry(0, 8, &[0, 2])];
    let file = ResumeFile::new([0; 16], JOURNAL_BYTES, JOURNAL_DIGEST, &entries);
    let err = ResumeFile::from_bytes(&file.to_vec()).unwrap_err();
    assert!(
        matches!(err, ResumeError::BlockIndexOutOfRange { index: 1 }),
        "got {err:?}"
    );
}

#[test]
fn test_resume_rejects_trailing_bytes() {
    let mut bytes = make_file().to_vec();
    bytes.extend_from_slice(b"appended");
    let err = ResumeFile::from_bytes(&bytes).unwrap_err();
    assert!(
        matches!(err, ResumeError::TrailingBytes { extra: 8 }),
        "got {err:?}"
    );
}

#[test]
fn test_resume_rejects_entries_cut_short() {
    let mut bytes = make_file().to_vec();
    bytes.truncate(RESUME_HEADER_SIZE + 5);
    let err = ResumeFile::from_bytes(&bytes).unwrap_err();
    assert!(matches!(err, ResumeError::Truncated { .. }), "got {err:?}");
}

#[test]
fn test_resume_rejects_a_block_count_larger_than_the_entries_present() {
    let entries = make_entries();
    let file = ResumeFile::new([0; 16], JOURNAL_BYTES, JOURNAL_DIGEST, &entries);
    let mut bytes = file.to_vec();
    bytes[24..28].copy_from_slice(&9u32.to_le_bytes());
    let err = ResumeFile::from_bytes(&reseal(&mut bytes)).unwrap_err();
    assert!(matches!(err, ResumeError::Truncated { .. }), "got {err:?}");
}

#[test]
fn test_resume_file_is_empty_bytes_safe() {
    assert!(ResumeFile::from_bytes(&[]).is_err());
    assert!(ResumeHeader::from_bytes(&[]).is_err());
}

#[test]
fn test_resume_constants() {
    assert_eq!(RESUME_MAGIC, *b"DHRS");
    assert_eq!(RESUME_VERSION, 2);
    assert_eq!(RESUME_HEADER_SIZE, 128);
    assert_eq!(CRC_COVER_BYTES, 92);
    assert_eq!(INTEGRITY_COVER_BYTES, 96);
}

proptest! {
    /// Any progress record survives a write and a read unchanged.
    #[test]
    fn prop_resume_round_trip(
        session_id in proptest::array::uniform16(proptest::arbitrary::any::<u8>()),
        journal_bytes in proptest::arbitrary::any::<u64>(),
        journal_digest in proptest::array::uniform32(proptest::arbitrary::any::<u8>()),
        symbol_counts in proptest::collection::vec(1u32..200, 1..10),
    ) {
        let entries: Vec<BlockEntry> = symbol_counts
            .iter()
            .enumerate()
            .map(|(i, &count)| {
                // Hold every third symbol so the bitmap is neither empty nor
                // full and its trailing bits stay inside the count.
                let held: Vec<u32> = (0..count).step_by(3).collect();
                entry(i as u32, count, &held)
            })
            .collect();

        let file = ResumeFile::new(session_id, journal_bytes, journal_digest, &entries);
        let parsed = ResumeFile::from_bytes(&file.to_vec()).unwrap();

        prop_assert_eq!(parsed.session_id(), session_id);
        prop_assert_eq!(parsed.journal_bytes(), journal_bytes);
        prop_assert_eq!(parsed.journal_digest(), journal_digest);
        prop_assert_eq!(parsed.entries(), entries.as_slice());
    }

    /// No byte sequence makes the parser panic.
    #[test]
    fn prop_arbitrary_bytes_never_panic(
        bytes in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..600),
    ) {
        let _ = ResumeFile::from_bytes(&bytes);
    }

    /// Corrupting any single byte of a valid file is always caught.
    #[test]
    fn prop_single_byte_corruption_is_rejected(
        offset in 0usize..RESUME_HEADER_SIZE,
        xor in 1u8..=255,
    ) {
        let mut bytes = make_file().to_vec();
        bytes[offset] ^= xor;
        prop_assert!(ResumeFile::from_bytes(&bytes).is_err());
    }
}
