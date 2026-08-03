//! Fuzz the resume file parser.
//!
//! A resume file is read from local storage the tool does not own. The threat
//! model treats a compromised receiver as in scope, so this parser is handed
//! attacker-controlled bytes on a machine where the attacker also controls
//! where they land.
//!
//! # Invariants asserted
//!
//! - The parser never panics.
//! - A file that parses carries exactly the number of entries its header
//!   declares, in block order with no gaps.
//! - Every entry's bitmap is exactly as long as its symbol count requires. The
//!   bitmap length is derived from a declared count, so a mismatch is where an
//!   out-of-range read would come from.
//! - A parsed file re-serializes to the bytes it came from, which is what
//!   rules out a trailing region the parser ignored and something else later
//!   trusts.

#![no_main]

use dhow_codec::resume::{RESUME_HEADER_SIZE, ResumeFile};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(file) = ResumeFile::from_bytes(data) else {
        return;
    };

    let header = file.header();
    assert_eq!(
        file.entries().len(),
        header.block_count() as usize,
        "a parsed resume file carries a different number of entries than it declares"
    );

    for (index, entry) in file.entries().iter().enumerate() {
        assert_eq!(
            entry.block_index as usize, index,
            "resume entries are out of block order at position {index}"
        );

        let required = entry.symbol_count.div_ceil(8) as usize;
        assert_eq!(
            entry.symbol_bitmap.len(),
            required,
            "block {index} declares {} symbols and carries a {}-byte bitmap",
            entry.symbol_count,
            entry.symbol_bitmap.len()
        );
    }

    // Exact round trip. The parser documents that a file must end at its last
    // entry; anything left over would be a region it ignored, and an ignored
    // region is one something else can be talked into reading.
    let serialized = file.to_vec();
    assert!(
        serialized.len() >= RESUME_HEADER_SIZE,
        "a parsed resume file serialized to {} bytes",
        serialized.len()
    );
    assert_eq!(
        serialized.len(),
        data.len(),
        "a parsed resume file re-serialized to a different length than it was parsed from"
    );
    assert_eq!(
        &serialized[..],
        data,
        "a parsed resume file did not re-serialize to the bytes it came from"
    );
});
