//! Fuzz the session header parser.
//!
//! The session header is unsigned framing that configures the decoder: block
//! count, symbol size, and the RaptorQ parameters. It is read before any
//! signature is checked, so a value it accepts is a value an attacker on the
//! optical channel chose.
//!
//! # Invariants asserted
//!
//! - The parser never panics.
//! - A header that parses re-serializes to the same 126 bytes.
//! - Parameters that parse are ones `validate()` accepts. If the parser can
//!   produce a header the validator rejects, then every caller is one
//!   forgotten `validate()` away from handing RaptorQ a zero block count.

#![no_main]

use dhow_codec::session::{SESSION_HEADER_SIZE, SessionHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(header) = SessionHeader::from_bytes(data) else {
        return;
    };

    let round_tripped = header.to_vec();
    assert_eq!(
        round_tripped.len(),
        SESSION_HEADER_SIZE,
        "a parsed session header serialized to {} bytes",
        round_tripped.len()
    );
    assert_eq!(
        &round_tripped[..],
        &data[..SESSION_HEADER_SIZE],
        "a parsed session header did not re-serialize to the bytes it came from"
    );

    // The parser's own bounds and the validator's must not disagree. A header
    // the parser accepts and the validator rejects is a trap: it puts the
    // safety of every decoder on the caller remembering an extra call.
    let params = header.params();
    if params.validate().is_ok() {
        assert!(params.block_count > 0, "validate accepted zero blocks");
        assert!(params.symbol_size > 0, "validate accepted a zero symbol size");
        assert!(
            params.total_symbols_per_block >= params.source_symbols_per_block,
            "validate accepted fewer total symbols than source symbols"
        );
    }
});
