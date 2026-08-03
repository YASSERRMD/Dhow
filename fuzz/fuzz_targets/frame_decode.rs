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
//! - A frame whose MAC and CRC have been repaired carries back exactly the
//!   payload it was given. See the comment on the repair below for why this
//!   path exists at all.

#![no_main]

use dhow_codec::frame::{FRAME_HEADER_SIZE, Frame, FrameHeader, MAX_PAYLOAD_LEN};
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

    // The whole frame, unaltered. Almost always rejected at the MAC, which is
    // the path a real attacker without the key gets, and worth exercising.
    if let Ok(frame) = Frame::from_bytes(data, &SESSION_KEY) {
        check_frame(&frame);
    }

    // The whole frame, with the MAC and CRC fixed up so it authenticates.
    //
    // Without this the target only ever tests the rejection path: a fuzzer will
    // not produce eight bytes of keyed MAC by mutation, so every input dies at
    // the first check and the code that reads a length and slices a payload is
    // never reached. Repairing the two integrity fields is the standard way
    // past a checksum gate, and it is sound here because the fields being
    // repaired are exactly the ones a sender computes: everything the fuzzer
    // still controls - the block and symbol indices, the declared length, the
    // payload, and the version and type bytes - is what a *legitimate but
    // malicious* sender controls, which is the threat this side of the MAC.
    if data.len() >= FRAME_HEADER_SIZE {
        let (head, body) = data.split_at(FRAME_HEADER_SIZE);

        if let Ok(header) = FrameHeader::from_bytes(head) {
            // FrameHeader::new panics above MAX_PAYLOAD_LEN, which is a
            // contract on the sender rather than on parsed input, so the
            // length is bounded here rather than being handed straight over.
            let body = &body[..body.len().min(MAX_PAYLOAD_LEN as usize)];

            let mut repaired = FrameHeader::new(
                header.frame_type(),
                header.session_id(),
                header.block_index(),
                header.symbol_index(),
                body,
            );
            repaired.set_mac(repaired.compute_mac(&SESSION_KEY));

            let mut whole = repaired.to_vec();
            whole.extend_from_slice(body);

            let frame = Frame::from_bytes(&whole, &SESSION_KEY)
                .expect("a frame with a repaired MAC and CRC did not authenticate");
            check_frame(&frame);
            assert_eq!(
                frame.payload(),
                body,
                "a repaired frame did not carry back the payload it was given"
            );
        }
    }
});

/// Asserts what a parsed frame promises about itself.
fn check_frame(frame: &Frame) {
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
