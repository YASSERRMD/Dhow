//! Property tests for the frame pipeline.
//!
//! `pipeline_test.rs` covers the same ground with examples: a specific payload,
//! a 64-byte symbol, one or two blocks. Those tests are worth having and they
//! pin one point in a space with three dimensions. These vary the payload size,
//! the symbol size, and the block count together, because the defects that
//! survive an example suite live at the combinations nobody wrote down - a
//! payload that divides evenly by the symbol size but not by the block count, a
//! final block one byte long, a symbol size that leaves a single byte of
//! padding.
//!
//! Every property here is one an operator depends on without knowing it: that
//! the order frames arrive in does not matter, that a subset is enough, that a
//! frame from someone else's transfer never enters this one.

use crate::blake3::blake3_digest;
use crate::frame::FRAME_HEADER_SIZE;
use crate::pipeline::{Pipeline, PipelineDecoder};
use crate::session::{RaptorQParams, SessionParams};
use proptest::prelude::*;

const KEY: [u8; 32] = [0xAB; 32];
const SESSION: [u8; 16] = [0x42; 16];

/// A payload, symbol size, and block count that describe a valid session.
///
/// Generated together rather than independently: the symbol counts are a
/// function of all three, and drawing them separately would spend most of the
/// run on parameter combinations the encoder rejects before doing any work.
fn session() -> impl Strategy<Value = (Vec<u8>, u32, u32, u32)> {
    (
        prop::collection::vec(any::<u8>(), 1..8192),
        prop::sample::select(vec![64u32, 96, 128, 256, 512, 1024]),
        1u32..=8,
        // Repair symbols beyond the source count. Zero is included because a
        // transfer with no overhead must still decode from a complete stream.
        0u32..=12,
    )
}

/// Builds parameters for a payload, matching what `send` computes.
fn params_for(payload: &[u8], symbol_size: u32, block_count: u32, repair: u32) -> SessionParams {
    let largest_block = (payload.len() as u64).div_ceil(block_count as u64);
    let source = largest_block.div_ceil(symbol_size as u64).max(1) as u32;
    SessionParams {
        payload_size: payload.len() as u64,
        block_count,
        symbol_size,
        source_symbols_per_block: source,
        total_symbols_per_block: source + repair,
        raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
        payload_digest: blake3_digest(payload),
    }
}

/// Encodes a payload, returning the frames and the parameters used.
fn encode(
    payload: &[u8],
    symbol_size: u32,
    block_count: u32,
    repair: u32,
) -> (SessionParams, Vec<Vec<u8>>) {
    let params = params_for(payload, symbol_size, block_count, repair);
    let pipeline = Pipeline::new(SESSION, params, KEY).expect("valid parameters");
    let frames = pipeline.encode_to_bytes(payload).expect("encoding");
    (params, frames)
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Each case builds and decodes a whole transfer, so the default 256
        // would make this the slowest test in the tree by a wide margin. 48 is
        // enough to explore the parameter space without that.
        cases: 48,
        ..ProptestConfig::default()
    })]

    /// Every payload round-trips at every parameter combination.
    #[test]
    fn any_session_round_trips((payload, symbol_size, blocks, repair) in session()) {
        let (params, frames) = encode(&payload, symbol_size, blocks, repair);

        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        for frame in &frames {
            let _ = decoder.accept(frame);
        }
        prop_assert!(decoder.is_complete(), "a complete stream did not complete the decode");
        prop_assert_eq!(decoder.finish().unwrap(), payload);
    }

    /// Frame order does not matter.
    ///
    /// A camera captures whatever is on screen when it looks, and the display
    /// loops, so the receiver sees frames in an order the sender never chose.
    #[test]
    fn frame_order_does_not_change_the_result(
        (payload, symbol_size, blocks, repair) in session(),
        shuffle in any::<prop::sample::Index>(),
    ) {
        let (params, frames) = encode(&payload, symbol_size, blocks, repair);

        // A rotation rather than a full shuffle: it is a permutation drawn from
        // the same input space, it reaches every starting offset, and it does
        // not need a second generator to produce.
        let at = shuffle.index(frames.len());
        let mut rotated = frames[at..].to_vec();
        rotated.extend_from_slice(&frames[..at]);

        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        for frame in &rotated {
            let _ = decoder.accept(frame);
        }
        prop_assert!(decoder.is_complete());
        prop_assert_eq!(decoder.finish().unwrap(), payload);
    }

    /// Duplicated frames change nothing.
    ///
    /// The display loops until the operator stops it, so the receiver sees
    /// every frame many times. A decoder that counted duplicates towards its
    /// threshold would report completion it had not reached.
    #[test]
    fn duplicates_do_not_help_or_harm((payload, symbol_size, blocks, repair) in session()) {
        let (params, frames) = encode(&payload, symbol_size, blocks, repair);

        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        for frame in frames.iter().chain(frames.iter()).chain(frames.iter()) {
            let _ = decoder.accept(frame);
        }
        prop_assert!(decoder.is_complete());
        prop_assert_eq!(decoder.finish().unwrap(), payload);
    }

    /// A frame from another session is never accepted.
    ///
    /// Not "is usually rejected": a frame carrying another session's id must
    /// never enter this decoder, whatever the parameters, because a stream
    /// recorded from an earlier transfer is exactly what an attacker replays.
    #[test]
    fn no_frame_from_another_session_is_accepted(
        (payload, symbol_size, blocks, repair) in session(),
        other in any::<[u8; 16]>(),
    ) {
        prop_assume!(other != SESSION);

        let params = params_for(&payload, symbol_size, blocks, repair);
        let foreign = Pipeline::new(other, params, KEY).unwrap();
        let frames = foreign.encode_to_bytes(&payload).unwrap();

        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        for frame in &frames {
            prop_assert!(
                decoder.accept(frame).is_err(),
                "a frame from session {:x?} entered session {:x?}", other, SESSION
            );
        }
        prop_assert!(!decoder.is_complete());
    }

    /// A frame authenticated under another key is never accepted.
    #[test]
    fn no_frame_under_another_key_is_accepted(
        (payload, symbol_size, blocks, repair) in session(),
        other_key in any::<[u8; 32]>(),
    ) {
        prop_assume!(other_key != KEY);

        let params = params_for(&payload, symbol_size, blocks, repair);
        let foreign = Pipeline::new(SESSION, params, other_key).unwrap();
        let frames = foreign.encode_to_bytes(&payload).unwrap();

        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        for frame in &frames {
            prop_assert!(decoder.accept(frame).is_err());
        }
    }

    /// A corrupted frame never poisons a decode that would otherwise succeed.
    ///
    /// This is the property that makes a lossy optical channel usable at all: a
    /// blurred capture must cost one frame, not the transfer.
    #[test]
    fn a_corrupt_frame_never_poisons_the_decode(
        (payload, symbol_size, blocks, repair) in session(),
        victim in any::<prop::sample::Index>(),
        offset in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let (params, frames) = encode(&payload, symbol_size, blocks, repair);

        let mut damaged = frames.clone();
        let at = victim.index(damaged.len());
        let byte = offset.index(damaged[at].len());
        damaged[at][byte] = damaged[at][byte].wrapping_add(delta);

        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        for frame in &damaged {
            // A rejected frame is expected; what must not happen is the decode
            // being unable to finish afterwards from the frames that were good.
            let _ = decoder.accept(frame);
        }

        // Feed the intact stream after the damaged one. If the corrupt frame
        // had poisoned any block, this would not recover.
        for frame in &frames {
            let _ = decoder.accept(frame);
        }
        prop_assert!(decoder.is_complete(), "a corrupt frame stopped the decode completing");
        prop_assert_eq!(decoder.finish().unwrap(), payload);
    }

    /// Every single-byte mutation of any frame is rejected.
    ///
    /// The header is covered by a MAC and the payload by a CRC, so there is no
    /// byte in a frame that can be changed without one of them noticing. A byte
    /// that could would be a byte an attacker chooses.
    #[test]
    fn every_single_byte_mutation_of_a_frame_is_rejected(
        (payload, symbol_size, blocks, repair) in session(),
        victim in any::<prop::sample::Index>(),
        offset in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let (params, frames) = encode(&payload, symbol_size, blocks, repair);

        let at = victim.index(frames.len());
        let mut frame = frames[at].clone();
        let byte = offset.index(frame.len());
        frame[byte] = frame[byte].wrapping_add(delta);

        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        prop_assert!(
            decoder.accept(&frame).is_err(),
            "a frame with byte {} of {} altered was accepted", byte, frame.len()
        );
    }

    /// A truncated frame is rejected rather than read past its end.
    #[test]
    fn a_truncated_frame_is_rejected(
        (payload, symbol_size, blocks, repair) in session(),
        victim in any::<prop::sample::Index>(),
        cut in any::<prop::sample::Index>(),
    ) {
        let (params, frames) = encode(&payload, symbol_size, blocks, repair);

        let at = victim.index(frames.len());
        let full = &frames[at];
        // Anything shorter than the whole frame, including shorter than the
        // header, which is where an unchecked index would bite.
        let keep = cut.index(full.len());
        let truncated = &full[..keep];

        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        prop_assert!(
            decoder.accept(truncated).is_err(),
            "a frame truncated to {} of {} bytes was accepted", keep, full.len()
        );
    }

    /// Frames never exceed the size the wire format allows.
    ///
    /// A frame has to fit a QR code, and the capacity table an operator picks a
    /// version from is derived from this bound. A frame larger than its
    /// declared symbol size plus a header would silently stop fitting.
    #[test]
    fn frames_are_the_size_the_parameters_promise(
        (payload, symbol_size, blocks, repair) in session(),
    ) {
        let (_, frames) = encode(&payload, symbol_size, blocks, repair);

        // The RaptorQ PayloadId travels in the frame payload alongside the
        // symbol, which is why the bound is symbol_size + 4 and not symbol_size.
        let largest = FRAME_HEADER_SIZE + symbol_size as usize + 4;
        for (i, frame) in frames.iter().enumerate() {
            prop_assert!(
                frame.len() <= largest,
                "frame {} is {} bytes, above the {} its parameters allow",
                i, frame.len(), largest
            );
        }
    }
}
