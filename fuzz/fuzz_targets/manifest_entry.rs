//! Fuzz a single manifest file entry.
//!
//! This is the path-traversal surface, and it is reached with an
//! attacker-chosen 16-bit length prefix in front of an attacker-chosen name.
//! It gets its own target rather than only being covered through the whole
//! manifest, because reaching it that way requires a valid header and a valid
//! CRC first, and a fuzzer spends its whole budget on those instead.
//!
//! # Invariants asserted
//!
//! - The parser never panics, at any length prefix.
//! - An entry that parses reports consuming exactly the bytes it occupies, and
//!   never more than were supplied. An over-report walks the next entry's
//!   parse off the end of the buffer.
//! - No name that escapes an extraction directory is ever returned. This is
//!   asserted independently rather than trusting `validate_name`, because a
//!   parser that returns the name and a validator that checks it are two
//!   things that can drift.
//! - No entry sets an undefined flag bit.

#![no_main]

use dhow_codec::manifest::{FileEntry, MAX_NAME_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((entry, consumed)) = FileEntry::from_bytes(data) else {
        return;
    };

    assert!(
        consumed <= data.len(),
        "an entry reported consuming {consumed} of {} available bytes",
        data.len()
    );
    assert_eq!(
        consumed,
        43 + entry.name.len(),
        "an entry of name length {} reported consuming {consumed} bytes",
        entry.name.len()
    );

    // The traversal rules, restated. Deliberately not a call to validate_name:
    // the point is to catch the parser and the validator drifting apart, and
    // reusing the validator would make that impossible to see.
    assert!(!entry.name.is_empty(), "an entry parsed with an empty name");
    assert!(
        entry.name.len() <= MAX_NAME_LEN,
        "an entry parsed with a {}-byte name",
        entry.name.len()
    );
    assert!(
        !entry.name.starts_with('/'),
        "an absolute name parsed: {:?}",
        entry.name
    );
    assert!(
        !entry.name.contains('\\'),
        "a name with a backslash parsed: {:?}",
        entry.name
    );
    assert!(
        !entry.name.contains('\0'),
        "a name with a NUL parsed: {:?}",
        entry.name
    );
    assert!(
        entry.name.chars().nth(1) != Some(':'),
        "a drive-relative name parsed: {:?}",
        entry.name
    );
    assert!(
        !entry.name.split('/').any(|part| part == ".."),
        "a traversal name parsed: {:?}",
        entry.name
    );

    // Round trip. The flag byte is the newest field and the one most likely to
    // be read at the wrong offset, and this is what would catch that.
    let round_tripped = entry.to_vec();
    assert_eq!(
        &round_tripped[..],
        &data[..consumed],
        "an entry did not re-serialize to the bytes it came from"
    );
    assert!(
        entry.flags() & !1 == 0,
        "an entry parsed with undefined flag bits set: {:#04x}",
        entry.flags()
    );
});
