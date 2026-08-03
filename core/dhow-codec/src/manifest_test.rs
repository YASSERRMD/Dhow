//! Tests for the manifest wire format module.

use crate::manifest::{
    CRC_OFFSET, FileEntry, MANIFEST_HEADER_SIZE, MANIFEST_MAGIC, MANIFEST_VERSION, Manifest,
    ManifestHeader,
};
use crate::session::{RaptorQParams, SessionParams};

fn test_signature() -> [u8; 64] {
    [0xCD; 64]
}

fn test_params() -> SessionParams {
    SessionParams {
        payload_size: 4096,
        block_count: 3,
        symbol_size: 256,
        source_symbols_per_block: 6,
        total_symbols_per_block: 9,
        raptorq: RaptorQParams {
            z: 3,
            n: 1,
            psi: 11,
        },
        payload_digest: [0x7E; 32],
    }
}

/// Builds a header with fixed session material, so a test that is about
/// something else does not have to restate six parameters to say so.
fn header(session_id: [u8; 16], entries: &[FileEntry], total_size: u64) -> ManifestHeader {
    ManifestHeader::new(
        session_id,
        entries,
        total_size,
        [0x5A; 32],
        [0x3C; 24],
        test_params(),
    )
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
    let hdr = header([0x42; 16], &entries, 15);
    assert_eq!(hdr.magic(), MANIFEST_MAGIC);
    assert_eq!(hdr.version(), MANIFEST_VERSION);
    assert_eq!(hdr.file_count(), 2);
    assert_eq!(hdr.total_size(), 15);
    assert_ne!(hdr.crc32c(), 0);
}

#[test]
fn test_manifest_header_to_vec_size() {
    let entries = make_entries();
    let hdr = header([0x42; 16], &entries, 15);
    let bytes = hdr.to_vec();
    assert_eq!(bytes.len(), MANIFEST_HEADER_SIZE);
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
fn test_file_entry_leading_slash() {
    let entry = FileEntry::new("/etc/passwd", 0, [0; 32]);
    let bytes = entry.to_vec();
    let result = FileEntry::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_file_entry_empty_name() {
    // An empty name names no file and cannot be extracted to anything, so it
    // is a malformed entry rather than a harmless one. This previously parsed
    // successfully; the name policy now rejects it.
    let entry = FileEntry::new("", 0, [0; 32]);
    let bytes = entry.to_vec();
    assert!(FileEntry::from_bytes(&bytes).is_err());
}

#[test]
fn test_file_entry_rejects_traversal_in_any_component() {
    // A name whose first component is harmless still escapes if a later
    // component is `..`. Checking only the start of the string missed these.
    for name in [
        "a/../../etc/passwd",
        "docs/../../../root/.ssh/id_ed25519",
        "a/b/..",
        "a/../b",
        "./../x",
    ] {
        let bytes = FileEntry::new(name, 0, [0; 32]).to_vec();
        assert!(
            FileEntry::from_bytes(&bytes).is_err(),
            "traversal name {name:?} was accepted"
        );
    }
}

#[test]
fn test_file_entry_rejects_absolute_and_drive_paths() {
    for name in ["/etc/passwd", "/", "C:/Windows/System32", "C:evil"] {
        let bytes = FileEntry::new(name, 0, [0; 32]).to_vec();
        assert!(
            FileEntry::from_bytes(&bytes).is_err(),
            "absolute name {name:?} was accepted"
        );
    }
}

#[test]
fn test_file_entry_accepts_ordinary_relative_names() {
    for name in ["a.txt", "dir/a.txt", "a/b/c/d.bin", "..hidden", "a..b"] {
        let bytes = FileEntry::new(name, 7, [1; 32]).to_vec();
        assert!(
            FileEntry::from_bytes(&bytes).is_ok(),
            "legitimate name {name:?} was rejected"
        );
    }
}

#[test]
fn test_file_entry_parent_dir() {
    let entry = FileEntry::new("../secret", 0, [0; 32]);
    let bytes = entry.to_vec();
    let result = FileEntry::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_file_entry_backslash() {
    let entry = FileEntry::new("..\\secret", 0, [0; 32]);
    let bytes = entry.to_vec();
    let result = FileEntry::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_manifest_many_entries() {
    let entries: Vec<FileEntry> = (0..10)
        .map(|i| FileEntry::new(&format!("file{}.txt", i), i as u64, [i as u8; 32]))
        .collect();
    let hdr = header([0; 16], &entries, 45);
    let manifest = Manifest::build(&hdr, &entries, &[0u8; 64]);
    let bytes = manifest.to_vec();
    let parsed = Manifest::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.entries().len(), 10);
    assert_eq!(parsed.entries()[0].name, "file0.txt");
    assert_eq!(parsed.entries()[9].name, "file9.txt");
}

#[test]
fn test_manifest_header_unsupported_version() {
    let entries = make_entries();
    let hdr = header([0; 16], &entries, 15);
    let mut bytes = hdr.to_vec();
    bytes[4] = 99;
    let result = ManifestHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_manifest_header_from_bytes_round_trip() {
    let entries = make_entries();
    let hdr = header([0x55; 16], &entries, 15);
    let bytes = hdr.to_vec();
    let parsed = ManifestHeader::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.magic(), hdr.magic());
    assert_eq!(parsed.version(), hdr.version());
    assert_eq!(parsed.session_id(), hdr.session_id());
    assert_eq!(parsed.file_count(), hdr.file_count());
    assert_eq!(parsed.total_size(), hdr.total_size());
    assert_eq!(parsed.crc32c(), hdr.crc32c());
}

#[test]
fn test_manifest_header_invalid_magic() {
    let entries = make_entries();
    let hdr = header([0; 16], &entries, 15);
    let mut bytes = hdr.to_vec();
    bytes[0..4].copy_from_slice(b"XXXX");
    let result = ManifestHeader::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_manifest_header_crc_mismatch() {
    let entries = make_entries();
    let hdr = header([0; 16], &entries, 15);
    let mut bytes = hdr.to_vec();
    // Corrupt the last byte of the CRC field.
    bytes[CRC_OFFSET + 3] = bytes[CRC_OFFSET + 3].wrapping_add(1);
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
    let hdr = header([0x42; 16], &entries, 15);
    let signature = test_signature();
    let manifest = Manifest::build(&hdr, &entries, &signature);
    let bytes = manifest.to_vec();

    let parsed = Manifest::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.header().file_count(), 2);
    assert_eq!(parsed.entries().len(), 2);
    assert_eq!(parsed.entries()[0].name, "hello.txt");
    assert_eq!(parsed.entries()[1].name, "world.txt");
}

#[test]
fn test_manifest_empty_entries() {
    let hdr = header([0; 16], &[], 0);
    let manifest = Manifest::build(&hdr, &[], &test_signature());
    let bytes = manifest.to_vec();
    let parsed = Manifest::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.entries().len(), 0);
}

#[test]
fn test_manifest_header_accessors() {
    let entries = make_entries();
    let hdr = header([0xAA; 16], &entries, 100);
    assert_eq!(hdr.magic(), MANIFEST_MAGIC);
    assert_eq!(hdr.version(), MANIFEST_VERSION);
    assert_eq!(hdr.session_id(), [0xAA; 16]);
    assert_eq!(hdr.file_count(), 2);
    assert_eq!(hdr.total_size(), 100);
    assert_eq!(hdr.crc32c(), hdr.crc32c());
    assert_eq!(hdr.signature(), [0u8; 64]);
}

#[test]
fn test_manifest_single_entry() {
    let entries = vec![FileEntry::new("single.txt", 42, [0x99; 32])];
    let hdr = header([0; 16], &entries, 42);
    let manifest = Manifest::build(&hdr, &entries, &[0x11; 64]);
    let bytes = manifest.to_vec();
    let parsed = Manifest::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.entries().len(), 1);
    assert_eq!(parsed.entries()[0].name, "single.txt");
    assert_eq!(parsed.entries()[0].size, 42);
    assert_eq!(parsed.entries()[0].digest, [0x99; 32]);
}

#[test]
fn test_manifest_header_set_signature() {
    let entries = make_entries();
    let hdr = header([0; 16], &entries, 15);
    let mut hdr = hdr;
    let sig = [0xDE; 64];
    hdr.set_signature(sig);
    assert_eq!(hdr.signature(), sig);
}

use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_manifest_round_trip(
        name in "[a-zA-Z0-9_]+"
    ) {
        let filename = format!("{}.txt", name);
        let entries = vec![FileEntry::new(&filename, 100, [0xAA; 32])];
        let hdr = header([0x42; 16], &entries, 100);
        let manifest = Manifest::build(&hdr, &entries, &[0xCD; 64]);
        let bytes = manifest.to_vec();
        let parsed = Manifest::from_bytes(&bytes).unwrap();
        prop_assert_eq!(parsed.entries().len(), 1);
        prop_assert_eq!(parsed.entries()[0].name.clone(), filename);
    }
}

// --- v2: the executable flag ---

#[test]
fn executable_flag_round_trips() {
    for executable in [false, true] {
        let entry = FileEntry::with_mode("run.sh", 12, [0x33; 32], executable);
        let bytes = entry.to_vec();
        let (parsed, consumed) = FileEntry::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(
            parsed.executable, executable,
            "executable={executable} did not survive the round trip"
        );
    }
}

#[test]
fn entry_length_is_43_plus_name() {
    for name in ["a", "dir/file.bin", &"x".repeat(300)] {
        let bytes = FileEntry::with_mode(name, 0, [0; 32], false).to_vec();
        assert_eq!(
            bytes.len(),
            43 + name.len(),
            "entry for a {}-byte name was {} bytes",
            name.len(),
            bytes.len()
        );
    }
}

#[test]
fn undefined_flag_bits_are_rejected_not_masked() {
    // Masking an unknown bit off would let a receiver act on a signed manifest
    // it did not fully understand while believing it had checked all of it.
    let entry = FileEntry::with_mode("a.txt", 1, [0; 32], false);
    let mut bytes = entry.to_vec();
    let flags_at = bytes.len() - 1;
    for bit in 1..8u8 {
        bytes[flags_at] = 1 << bit;
        let err = FileEntry::from_bytes(&bytes)
            .expect_err(&format!("flag bit {bit} was accepted"))
            .to_string();
        assert!(
            err.contains("undefined flag bits"),
            "bit {bit} rejected with the wrong error: {err}"
        );
    }
}

// --- v2: the session fields ---

#[test]
fn session_fields_round_trip() {
    let entries = make_entries();
    let params = test_params();
    let hdr = ManifestHeader::new([0x11; 16], &entries, 15, [0xA1; 32], [0xB2; 24], params);
    let parsed = ManifestHeader::from_bytes(&hdr.to_vec()).unwrap();

    assert_eq!(parsed.salt(), [0xA1; 32]);
    assert_eq!(parsed.nonce(), [0xB2; 24]);
    assert_eq!(parsed.params(), params);
    // The payload digest is the session's, not a digest of the file digests.
    assert_eq!(parsed.payload_digest(), params.payload_digest);
}

#[test]
fn every_session_field_is_covered_by_the_crc() {
    // A field the CRC does not cover can be changed without the parser
    // noticing, which for salt, nonce, and coding parameters means a receiver
    // decoding a transfer nobody described. Walk the whole covered range.
    let entries = make_entries();
    let good = header([0x11; 16], &entries, 15).to_vec();

    for offset in 8..CRC_OFFSET {
        let mut bytes = good.clone();
        bytes[offset] = bytes[offset].wrapping_add(1);
        assert!(
            ManifestHeader::from_bytes(&bytes).is_err(),
            "a flipped byte at offset {offset} parsed cleanly"
        );
    }
}

#[test]
fn reserved_bytes_at_158_must_be_zero() {
    let entries = make_entries();
    let mut bytes = header([0; 16], &entries, 15).to_vec();
    bytes[158] = 1;
    // Fix the CRC so the reserved check is what rejects it, not the CRC.
    let crc = crate::crc32c::crc32c_digest(&bytes[0..CRC_OFFSET]);
    bytes[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());

    let err = ManifestHeader::from_bytes(&bytes).unwrap_err().to_string();
    assert!(err.contains("offset 158"), "rejected with: {err}");
}

#[test]
fn a_v1_manifest_is_rejected() {
    // v1 headers were 168 bytes with the version byte set to 1. Neither the
    // length nor the version is acceptable now, and the version is what should
    // be reported: it is the one an operator can act on.
    let mut v1 = vec![0u8; 168];
    v1[0..4].copy_from_slice(&MANIFEST_MAGIC);
    v1[4] = 1;
    let err = Manifest::from_bytes(&v1).unwrap_err().to_string();
    assert!(
        err.contains("unsupported manifest version: 1"),
        "a v1 manifest was rejected with: {err}"
    );
}

#[test]
fn signing_bytes_zero_the_signature_and_nothing_else() {
    let entries = make_entries();
    let hdr = header([0x42; 16], &entries, 15);
    let manifest = Manifest::build(&hdr, &entries, &test_signature());

    let full = manifest.to_vec();
    let signing = manifest.signing_bytes();

    assert_eq!(signing.len(), full.len());
    for (i, (a, b)) in full.iter().zip(signing.iter()).enumerate() {
        if (164..228).contains(&i) {
            assert_eq!(*b, 0, "signature byte {i} was not zeroed");
            assert_eq!(*a, 0xCD, "the manifest lost its signature at byte {i}");
        } else {
            assert_eq!(a, b, "byte {i} changed outside the signature field");
        }
    }
}

#[test]
fn signing_bytes_of_matches_signing_bytes() {
    // The signer holds a parsed manifest and the verifier holds bytes off the
    // wire. If the two build different signing inputs, every signature fails.
    let entries = make_entries();
    let hdr = header([0x42; 16], &entries, 15);
    let manifest = Manifest::build(&hdr, &entries, &test_signature());

    assert_eq!(
        Manifest::signing_bytes_of(&manifest.to_vec()).unwrap(),
        manifest.signing_bytes()
    );
}

#[test]
fn trailing_bytes_after_the_last_entry_are_rejected() {
    // Found while writing the manifest fuzz target in Phase 29. Nothing this
    // code writes has a tail, so anything after the last entry is corruption
    // or a forgery, and a parser whose output does not describe its input is a
    // trap for the next caller who parses without verifying.
    let entries = make_entries();
    let hdr = header([0x42; 16], &entries, 15);
    let manifest = Manifest::build(&hdr, &entries, &test_signature());

    let clean = manifest.to_vec();
    assert!(
        Manifest::from_bytes(&clean).is_ok(),
        "a manifest with no tail was rejected"
    );

    let mut with_tail = clean.clone();
    with_tail.extend_from_slice(b"TRAILING");
    let err = Manifest::from_bytes(&with_tail).unwrap_err().to_string();
    assert!(
        err.contains("trailing bytes"),
        "a manifest with a tail was rejected with: {err}"
    );

    // A single byte counts. The check is exact, not a tolerance.
    let mut one_extra = clean.clone();
    one_extra.push(0);
    assert!(
        Manifest::from_bytes(&one_extra).is_err(),
        "a manifest with one trailing byte was accepted"
    );
}

#[test]
fn a_manifest_that_parses_re_serializes_to_its_own_input() {
    // The property the trailing-byte check exists to make true, stated as the
    // property rather than as the mechanism.
    let entries = make_entries();
    let hdr = header([0x42; 16], &entries, 15);
    let bytes = Manifest::build(&hdr, &entries, &test_signature()).to_vec();

    let parsed = Manifest::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.to_vec(), bytes);
}
