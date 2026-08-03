//! Replays the committed fuzz regression inputs on stable.
//!
//! The fuzz targets in `fuzz/` need a nightly toolchain and `cargo-fuzz`, and
//! `scripts/gate.sh` skips them when either is missing. That is the right
//! behaviour for a search, and the wrong behaviour for a *regression*: an input
//! that once crashed a parser must be checked on every run, by everyone, with
//! the toolchain everyone has.
//!
//! So the invariants the fuzz targets assert are asserted here too, over the
//! inputs in `fuzz/regressions/`. The two are deliberately duplicated rather
//! than shared: the fuzz crate cannot be a dependency of this one, and a
//! regression check that only runs where the fuzzer runs is a regression check
//! that was not needed.
//!
//! # Adding to this
//!
//! When a fuzz target finds something, copy the artifact into
//! `fuzz/regressions/<target>/` and fix the parser in the same change. The
//! input is then replayed here forever, on stable, in the default gate.

use crate::frame::{FRAME_HEADER_SIZE, FrameHeader};
use crate::manifest::{FileEntry, MANIFEST_HEADER_SIZE, MANIFEST_MAGIC, Manifest};
use crate::resume::{RESUME_HEADER_SIZE, ResumeFile};
use crate::session::{SESSION_HEADER_SIZE, SessionHeader};
use std::fs;
use std::path::PathBuf;

/// Returns the inputs committed for one target.
///
/// A missing directory is a failure rather than an empty iteration. A replay
/// test that silently checks nothing is the failure mode this file exists to
/// avoid, and it is one this repository has shipped before.
fn regressions(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/regressions")
        .join(target);

    let entries = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|entry| entry.expect("reading a regression directory entry"))
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "bin"))
        .map(|entry| {
            let path = entry.path();
            let bytes = fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                bytes,
            )
        })
        .collect::<Vec<_>>();

    assert!(
        !entries.is_empty(),
        "no regression inputs in {}; this test would pass without checking anything",
        dir.display()
    );
    entries
}

#[test]
fn frame_header_regressions_round_trip() {
    for (name, data) in regressions("frame_decode") {
        let Ok(header) = FrameHeader::from_bytes(&data) else {
            continue;
        };
        let round_tripped = header.to_vec();
        assert_eq!(round_tripped.len(), FRAME_HEADER_SIZE, "{name}");
        assert_eq!(
            &round_tripped[..],
            &data[..FRAME_HEADER_SIZE],
            "{name}: a parsed frame header did not re-serialize to its own bytes"
        );
    }
}

#[test]
fn session_header_regressions_round_trip() {
    for (name, data) in regressions("session_header") {
        let Ok(header) = SessionHeader::from_bytes(&data) else {
            continue;
        };
        let round_tripped = header.to_vec();
        assert_eq!(round_tripped.len(), SESSION_HEADER_SIZE, "{name}");
        assert_eq!(
            &round_tripped[..],
            &data[..SESSION_HEADER_SIZE],
            "{name}: a parsed session header did not re-serialize to its own bytes"
        );

        // The parser's bounds and the validator's must agree, or every caller
        // is one forgotten validate() away from a zero block count.
        let params = header.params();
        if params.validate().is_ok() {
            assert!(params.block_count > 0, "{name}");
            assert!(params.symbol_size > 0, "{name}");
            assert!(
                params.total_symbols_per_block >= params.source_symbols_per_block,
                "{name}"
            );
        }
    }
}

#[test]
fn manifest_entry_regressions_are_safe_to_extract() {
    for (name, data) in regressions("manifest_entry") {
        let Ok((entry, consumed)) = FileEntry::from_bytes(&data) else {
            continue;
        };

        assert!(consumed <= data.len(), "{name}: over-reported consumption");
        assert_eq!(consumed, 43 + entry.name.len(), "{name}");

        // The traversal rules restated rather than delegated to validate_name,
        // so the parser and the validator drifting apart is visible.
        assert!(!entry.name.is_empty(), "{name}: empty name parsed");
        assert!(!entry.name.starts_with('/'), "{name}: {:?}", entry.name);
        assert!(!entry.name.contains('\\'), "{name}: {:?}", entry.name);
        assert!(!entry.name.contains('\0'), "{name}: {:?}", entry.name);
        assert!(
            entry.name.chars().nth(1) != Some(':'),
            "{name}: {:?}",
            entry.name
        );
        assert!(
            !entry.name.split('/').any(|part| part == ".."),
            "{name}: traversal name {:?} parsed",
            entry.name
        );

        assert_eq!(
            &entry.to_vec()[..],
            &data[..consumed],
            "{name}: an entry did not re-serialize to its own bytes"
        );
        assert_eq!(entry.flags() & !1, 0, "{name}: undefined flag bits parsed");
    }
}

#[test]
fn manifest_regressions_describe_themselves() {
    for (name, data) in regressions("manifest_verify") {
        let Ok(manifest) = Manifest::from_bytes(&data) else {
            continue;
        };

        assert_eq!(
            manifest.entries().len(),
            manifest.header().file_count() as usize,
            "{name}: entry count disagrees with the declared file count"
        );
        assert_eq!(manifest.header().magic(), MANIFEST_MAGIC, "{name}");

        let serialized = manifest.to_vec();
        assert!(serialized.len() >= MANIFEST_HEADER_SIZE, "{name}");
        assert_eq!(
            serialized.len(),
            data.len(),
            "{name}: a parsed manifest left bytes unaccounted for"
        );
        assert_eq!(
            &serialized[..],
            &data[..],
            "{name}: a parsed manifest did not re-serialize to its own bytes"
        );
        assert_eq!(
            manifest.signing_bytes().len(),
            serialized.len(),
            "{name}: signing bytes and manifest bytes are different lengths"
        );
    }
}

#[test]
fn resume_regressions_account_for_every_byte() {
    for (name, data) in regressions("resume_load") {
        let Ok(file) = ResumeFile::from_bytes(&data) else {
            continue;
        };

        assert_eq!(
            file.entries().len(),
            file.header().block_count() as usize,
            "{name}: entry count disagrees with the declared block count"
        );

        for (index, entry) in file.entries().iter().enumerate() {
            assert_eq!(entry.block_index as usize, index, "{name}: out of order");
            assert_eq!(
                entry.symbol_bitmap.len(),
                entry.symbol_count.div_ceil(8) as usize,
                "{name}: block {index} bitmap length does not match its symbol count"
            );
        }

        let serialized = file.to_vec();
        assert!(serialized.len() >= RESUME_HEADER_SIZE, "{name}");
        assert_eq!(
            serialized.len(),
            data.len(),
            "{name}: a parsed resume file left bytes unaccounted for"
        );
        assert_eq!(&serialized[..], &data[..], "{name}");
    }
}
