//! Fuzz the frame parser.
//!
//! Every frame that reaches this code came off a camera pointed at a screen
//! anyone can stand in front of, so the parser is the first thing an attacker
//! reaches and the only thing between them and the decoder.
//!
//! # Invariants asserted
//!
//! - The parser never panics.
//! - A header that parses re-serializes to the same 46 bytes it was parsed
//!   from. A parser that accepts a header it cannot reproduce is discarding
//!   something, and what it discards is what an attacker gets to choose.
//! - A frame that parses declares a payload length that matches the payload it
//!   actually carries, so the length field cannot describe one thing while the
//!   decoder is handed another.
//! - Parsing is deterministic: the same bytes give the same answer twice.

#![no_main]

use dhow_codec::frame::{FRAME_HEADER_SIZE, Frame, FrameHeader};
use libfuzzer_sys::fuzz_target;

/// The session key the parser authenticates against.
///
/// Fixed rather than drawn from the input: the fuzzer's job here is to explore
/// frame *structure*, and a key that changed with the input would send almost
/// every case down the MAC-rejection path before the parser ran.
const SESSION_KEY: [u8; 32] = [0x5A; 32];

fuzz_target!(|data: &[u8]| {
    // The header, on its own. It is reachable before any authentication, so it
    // is the part of the surface an unauthenticated attacker actually has.
    if let Ok(header) = FrameHeader::from_bytes(data) {
        let round_tripped = header.to_vec();
        assert_eq!(
            round_tripped.len(),
            FRAME_HEADER_SIZE,
            "a parsed header serialized to {} bytes",
            round_tripped.len()
        );
        assert_eq!(
            &round_tripped[..],
            &data[..FRAME_HEADER_SIZE],
            "a parsed header did not re-serialize to the bytes it came from"
        );

        // Parsing twice must agree. A parser that depends on anything but its
        // input cannot be reasoned about from its input.
        let again = FrameHeader::from_bytes(data).expect("a header parsed once and not twice");
        assert_eq!(again.to_vec(), round_tripped);
    }

    // The whole frame, including MAC and CRC. Reaching this needs a correct
    // MAC, which the fuzzer will not guess; the corpus seeds it with real
    // frames so the path is exercised rather than merely present.
    if let Ok(frame) = Frame::from_bytes(data, &SESSION_KEY) {
        assert_eq!(
            frame.payload().len(),
            frame.header().payload_length() as usize,
            "a frame's declared payload length disagrees with its payload"
        );
        assert_eq!(
            frame.to_vec().len(),
            FRAME_HEADER_SIZE + frame.payload().len(),
            "a frame serialized to a length its parts do not account for"
        );
    }
});
