//! Tests for the frame assembly and reassembly pipeline.

use crate::blake3::blake3_digest;
use crate::frame::{FRAME_HEADER_SIZE, FrameType};
use crate::pipeline::{FrameOutcome, Pipeline, PipelineDecoder};
use crate::session::{RaptorQParams, SessionParams};
use crate::{CodecError, FrameError, ResumeError, SessionError};

const KEY: [u8; 32] = [0xAB; 32];
const SESSION: [u8; 16] = [0x42; 16];

/// Builds session parameters matching `payload`, with the given block count
/// and repair overhead.
fn params_for(payload: &[u8], block_count: u32, repair: u32) -> SessionParams {
    let symbol_size = 64u32;
    // Symbols in the largest block, which is what the repair budget is sized against.
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

fn payload_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Drives a full send -> receive cycle, feeding `frames` in the given order.
fn round_trip(payload: &[u8], params: SessionParams, frames: Vec<Vec<u8>>) -> Vec<u8> {
    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    for frame in &frames {
        decoder.accept(frame).unwrap();
    }
    assert!(decoder.is_complete(), "decoder did not complete");
    let out = decoder.finish().unwrap();
    assert_eq!(out, payload);
    out
}

#[test]
fn test_round_trip_single_block() {
    let payload = b"Hello, Dhow!".to_vec();
    let params = params_for(&payload, 1, 4);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    round_trip(&payload, params, frames);
}

#[test]
fn test_round_trip_multiple_blocks() {
    let payload = payload_of(4096);
    let params = params_for(&payload, 4, 8);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    round_trip(&payload, params, frames);
}

#[test]
fn test_round_trip_payload_smaller_than_one_symbol() {
    let payload = b"x".to_vec();
    let params = params_for(&payload, 1, 2);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    round_trip(&payload, params, frames);
}

#[test]
fn test_round_trip_payload_exact_symbol_multiple() {
    let payload = payload_of(64 * 8);
    let params = params_for(&payload, 1, 4);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    round_trip(&payload, params, frames);
}

#[test]
fn test_round_trip_frames_reversed() {
    let payload = payload_of(2048);
    let params = params_for(&payload, 2, 6);
    let mut frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    frames.reverse();
    round_trip(&payload, params, frames);
}

#[test]
fn test_round_trip_with_duplicated_frames() {
    let payload = payload_of(1024);
    let params = params_for(&payload, 1, 4);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    let doubled: Vec<Vec<u8>> = frames.iter().flat_map(|f| [f.clone(), f.clone()]).collect();
    round_trip(&payload, params, doubled);
}

#[test]
fn test_decode_recovers_from_dropped_source_symbols() {
    let payload = payload_of(2048);
    // Generous repair budget so dropping source symbols is still recoverable.
    let params = params_for(&payload, 1, 32);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    // Drop every third frame, simulating missed captures.
    let surviving: Vec<Vec<u8>> = frames
        .into_iter()
        .enumerate()
        .filter(|(i, _)| i % 3 != 0)
        .map(|(_, f)| f)
        .collect();

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    for frame in &surviving {
        decoder.accept(frame).unwrap();
    }
    assert!(decoder.is_complete());
    assert_eq!(decoder.finish().unwrap(), payload);
}

#[test]
fn test_encode_emits_each_symbol_index_once_per_block() {
    let payload = payload_of(512);
    let params = params_for(&payload, 2, 3);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode(&payload)
        .unwrap();

    let mut seen = std::collections::HashSet::new();
    for prepared in &frames {
        let h = prepared.frame.header();
        assert!(
            seen.insert((h.block_index(), h.symbol_index())),
            "duplicate (block, symbol) pair emitted: ({}, {})",
            h.block_index(),
            h.symbol_index()
        );
    }
}

#[test]
fn test_encode_frames_carry_payload_id_and_symbol() {
    let payload = payload_of(256);
    let params = params_for(&payload, 1, 1);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode(&payload)
        .unwrap();

    for prepared in &frames {
        // 4-byte PayloadId plus at least one byte of symbol data.
        assert!(prepared.frame.payload().len() > 4);
        assert_eq!(prepared.frame.header().frame_type(), FrameType::Repair);
        assert_eq!(prepared.frame.header().session_id(), SESSION);
    }
}

#[test]
fn test_encode_is_deterministic() {
    let payload = payload_of(1024);
    let params = params_for(&payload, 2, 4);
    let pipeline = Pipeline::new(SESSION, params, KEY).unwrap();
    assert_eq!(
        pipeline.encode_to_bytes(&payload).unwrap(),
        pipeline.encode_to_bytes(&payload).unwrap()
    );
}

#[test]
fn test_encode_rejects_payload_size_mismatch() {
    let payload = payload_of(100);
    let params = params_for(&payload, 1, 2);
    let pipeline = Pipeline::new(SESSION, params, KEY).unwrap();
    assert!(matches!(
        pipeline.encode(b"short"),
        Err(CodecError::Session(SessionError::InvalidParameters { .. }))
    ));
}

#[test]
fn test_new_rejects_symbol_size_below_fec_minimum() {
    let payload = payload_of(128);
    let mut params = params_for(&payload, 1, 2);
    params.symbol_size = 32;
    // Must be a typed error, not a panic from inside RaptorQ.
    assert!(Pipeline::new(SESSION, params, KEY).is_err());
    assert!(PipelineDecoder::new(SESSION, params, KEY).is_err());
}

#[test]
fn test_new_rejects_symbol_size_that_overflows_a_frame() {
    let payload = payload_of(128);
    let mut params = params_for(&payload, 1, 2);
    params.symbol_size = 65535;
    assert!(Pipeline::new(SESSION, params, KEY).is_err());
    assert!(PipelineDecoder::new(SESSION, params, KEY).is_err());
}

#[test]
fn test_new_rejects_zero_block_count() {
    let payload = payload_of(128);
    let mut params = params_for(&payload, 1, 2);
    params.block_count = 0;
    assert!(Pipeline::new(SESSION, params, KEY).is_err());
}

#[test]
fn test_decoder_rejects_frame_from_another_session() {
    let payload = payload_of(256);
    let params = params_for(&payload, 1, 2);
    let frames = Pipeline::new([0x01; 16], params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let mut decoder = PipelineDecoder::new([0x02; 16], params, KEY).unwrap();
    // The MAC binds the session id, so a foreign frame fails before its
    // contents are ever used.
    assert!(decoder.accept(&frames[0]).is_err());
    assert!(!decoder.is_complete());
}

#[test]
fn test_decoder_rejects_frame_signed_with_another_key() {
    let payload = payload_of(256);
    let params = params_for(&payload, 1, 2);
    let frames = Pipeline::new(SESSION, params, [0x11; 32])
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let mut decoder = PipelineDecoder::new(SESSION, params, [0x22; 32]).unwrap();
    assert!(matches!(
        decoder.accept(&frames[0]),
        Err(CodecError::Frame(FrameError::MacVerificationFailed))
    ));
}

#[test]
fn test_decoder_rejects_corrupted_payload() {
    let payload = payload_of(512);
    let params = params_for(&payload, 1, 4);
    let mut frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    // Flip a bit in the symbol data; the CRC must catch it.
    let last = frames[0].len() - 1;
    frames[0][last] ^= 0xFF;

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    assert!(matches!(
        decoder.accept(&frames[0]),
        Err(CodecError::Frame(FrameError::CrcMismatch { .. }))
    ));
}

#[test]
fn test_corrupt_frame_does_not_poison_decode() {
    let payload = payload_of(1024);
    let params = params_for(&payload, 1, 16);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();

    // Interleave a corrupted copy of each frame with the good one.
    for frame in &frames {
        let mut bad = frame.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        let _ = decoder.accept(&bad);
        decoder.accept(frame).unwrap();
    }

    assert!(decoder.is_complete());
    assert_eq!(decoder.finish().unwrap(), payload);
}

#[test]
fn test_decoder_rejects_truncated_frame() {
    let payload = payload_of(256);
    let params = params_for(&payload, 1, 2);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    for cut in [0, 1, FRAME_HEADER_SIZE - 1, FRAME_HEADER_SIZE + 1] {
        assert!(
            decoder.accept(&frames[0][..cut]).is_err(),
            "truncation to {cut} bytes was accepted"
        );
    }
}

#[test]
fn test_decoder_rejects_every_single_byte_mutation_of_a_frame() {
    let payload = payload_of(128);
    let params = params_for(&payload, 1, 1);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    let good = &frames[0];

    for i in 0..good.len() {
        let mut mutated = good.clone();
        mutated[i] ^= 0x01;
        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        assert!(
            decoder.accept(&mutated).is_err(),
            "mutation at byte {i} was accepted"
        );
    }
}

#[test]
fn test_decoder_rejects_short_symbol_payload_without_panicking() {
    // A frame whose payload is shorter than a RaptorQ PayloadId would make the
    // library index out of bounds; the decoder must reject it first.
    use crate::frame::{Frame, FrameHeader};

    let payload = payload_of(256);
    let params = params_for(&payload, 1, 2);

    for len in 0..=4usize {
        let symbol = vec![0u8; len];
        let header = FrameHeader::new(FrameType::Repair, SESSION, 0, 0, &symbol);
        let frame = Frame::build(&header, &symbol, &KEY).to_vec();

        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        assert!(
            decoder.accept(&frame).is_err(),
            "a {len}-byte symbol payload was accepted"
        );
    }
}

#[test]
fn test_decoder_rejects_out_of_range_block_index() {
    use crate::frame::{Frame, FrameHeader};

    let payload = payload_of(256);
    let params = params_for(&payload, 1, 2);

    let symbol = vec![7u8; 32];
    let header = FrameHeader::new(FrameType::Repair, SESSION, 999, 0, &symbol);
    let frame = Frame::build(&header, &symbol, &KEY).to_vec();

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    assert!(decoder.accept(&frame).is_err());
}

#[test]
fn test_redundant_frames_after_block_completes() {
    let payload = payload_of(256);
    let params = params_for(&payload, 1, 8);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    let mut saw_redundant = false;
    for frame in &frames {
        if decoder.accept(frame).unwrap() == FrameOutcome::Redundant {
            saw_redundant = true;
        }
    }
    assert!(
        saw_redundant,
        "expected surplus repair symbols to report as redundant"
    );
    assert_eq!(decoder.finish().unwrap(), payload);
}

#[test]
fn test_finish_refuses_before_all_blocks_decode() {
    let payload = payload_of(4096);
    let params = params_for(&payload, 4, 2);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    // Feed only the first block's frames.
    for frame in frames.iter().take(2) {
        let _ = decoder.accept(frame);
    }
    assert!(!decoder.is_complete());
    assert!(decoder.finish().is_err());
}

#[test]
fn test_finish_rejects_payload_that_fails_its_digest() {
    let payload = payload_of(512);
    let mut params = params_for(&payload, 1, 4);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    // The receiver is told to expect a different payload than what arrives.
    params.payload_digest = [0xFF; 32];

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    for frame in &frames {
        decoder.accept(frame).unwrap();
    }
    assert!(decoder.is_complete());
    assert!(matches!(
        decoder.finish(),
        Err(CodecError::Session(SessionError::DigestMismatch))
    ));
}

#[test]
fn test_blocks_complete_counts_up() {
    let payload = payload_of(4096);
    let params = params_for(&payload, 4, 8);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    assert_eq!(decoder.blocks_complete(), 0);
    for frame in &frames {
        decoder.accept(frame).unwrap();
    }
    assert_eq!(decoder.blocks_complete(), 4);
}

#[test]
fn test_accessors_return_construction_values() {
    let payload = payload_of(128);
    let params = params_for(&payload, 1, 2);
    let pipeline = Pipeline::new(SESSION, params, KEY).unwrap();
    assert_eq!(pipeline.session_id(), SESSION);
    assert_eq!(pipeline.params().payload_size, 128);
    assert_eq!(pipeline.chunk_map().block_count(), 1);

    let decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    assert_eq!(decoder.session_id(), SESSION);
    assert_eq!(decoder.params().payload_size, 128);
}

#[test]
fn test_frames_are_interleaved_across_blocks() {
    // Emitting block by block would put every frame of block 0 at the front of
    // the stream. Interleaving means consecutive frames come from different
    // blocks.
    let payload = payload_of(8192);
    let params = params_for(&payload, 4, 4);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode(&payload)
        .unwrap();

    let first_four: Vec<u32> = frames
        .iter()
        .take(4)
        .map(|f| f.frame.header().block_index())
        .collect();
    assert_eq!(
        first_four,
        vec![0, 1, 2, 3],
        "the stream opens with consecutive frames from the same block"
    );
}

#[test]
fn test_decode_survives_a_contiguous_outage() {
    // A camera refocusing, or an operator stepping in front of the screen,
    // drops a run of consecutive frames. RaptorQ repairs within a block and
    // never across blocks, so if that run fell entirely inside one block no
    // repair overhead could recover it. Interleaving is what makes this
    // survivable.
    let payload = payload_of(16384);
    let params = params_for(&payload, 4, 24);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let outage = frames.len() / 5;
    let start = frames.len() / 3;
    let surviving: Vec<Vec<u8>> = frames
        .into_iter()
        .enumerate()
        .filter(|(i, _)| *i < start || *i >= start + outage)
        .map(|(_, f)| f)
        .collect();

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    for frame in &surviving {
        decoder.accept(frame).unwrap();
    }
    assert!(
        decoder.is_complete(),
        "a contiguous outage of {outage} frames was not recoverable"
    );
    assert_eq!(decoder.finish().unwrap(), payload);
}

#[test]
fn test_interleaving_preserves_every_frame() {
    // Blocks differ in length when the payload does not divide evenly, so the
    // interleave must not stop at the shortest block and drop the remainder.
    let payload = payload_of(5000);
    let params = params_for(&payload, 3, 5);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode(&payload)
        .unwrap();

    let mut per_block = std::collections::HashMap::new();
    for f in &frames {
        *per_block.entry(f.frame.header().block_index()).or_insert(0) += 1;
    }
    assert_eq!(per_block.len(), 3, "not every block produced frames");
    for (block, count) in &per_block {
        assert!(*count > 0, "block {block} produced no frames");
    }
}

// --- Held-symbol record and journal digest ---

/// Reads bit `index` of a bitmap laid out LSB-first.
fn bit_set(bitmap: &[u8], index: u32) -> bool {
    bitmap[index as usize / 8] & (1u8 << (index % 8)) != 0
}

/// Counts the set bits in a bitmap.
fn popcount(bitmap: &[u8]) -> u32 {
    bitmap.iter().map(|b| b.count_ones()).sum()
}

#[test]
fn test_held_bitmap_names_the_symbols_that_arrived() {
    let payload = payload_of(2048);
    let params = params_for(&payload, 2, 6);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode(&payload)
        .unwrap();

    // Feed every third frame so the bitmap has a shape worth checking rather
    // than being uniformly full.
    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    let mut expected: Vec<Vec<u32>> = vec![Vec::new(); params.block_count as usize];
    for frame in frames.iter().step_by(3) {
        let header = frame.frame.header();
        decoder.accept(&frame.frame.to_vec()).unwrap();
        expected[header.block_index() as usize].push(header.symbol_index());
    }

    for block in 0..params.block_count {
        let bitmap = decoder.symbol_bitmap(block).expect("block in range");
        let want = &expected[block as usize];

        assert_eq!(
            decoder.symbols_held(block),
            Some(want.len() as u32),
            "block {block} held count"
        );
        assert_eq!(popcount(bitmap), want.len() as u32, "block {block} bit count");

        for symbol in 0..params.total_symbols_per_block {
            assert_eq!(
                bit_set(bitmap, symbol),
                want.contains(&symbol),
                "block {block} symbol {symbol}"
            );
        }
    }
}

#[test]
fn test_held_count_ignores_a_repeated_symbol() {
    let payload = payload_of(512);
    let params = params_for(&payload, 1, 4);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    decoder.accept(&frames[0]).unwrap();
    let after_first = decoder.symbols_held(0).unwrap();

    // A camera reads the same frame on consecutive passes all the time. That
    // must not inflate the record of what the receiver actually holds.
    for _ in 0..5 {
        decoder.accept(&frames[0]).unwrap();
    }
    assert_eq!(decoder.symbols_held(0), Some(after_first));
    assert_eq!(popcount(decoder.symbol_bitmap(0).unwrap()), after_first);
}

#[test]
fn test_bitmap_is_empty_before_any_frame_and_out_of_range_is_none() {
    let payload = payload_of(256);
    let params = params_for(&payload, 2, 4);
    let decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();

    for block in 0..params.block_count {
        assert_eq!(decoder.symbols_held(block), Some(0));
        assert_eq!(popcount(decoder.symbol_bitmap(block).unwrap()), 0);
    }
    assert_eq!(decoder.block_count(), params.block_count);
    assert_eq!(decoder.symbol_bitmap(params.block_count), None);
    assert_eq!(decoder.symbols_held(params.block_count), None);
}

#[test]
fn test_rejected_frame_leaves_no_trace_in_the_record() {
    let payload = payload_of(512);
    let params = params_for(&payload, 1, 4);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    decoder.accept(&frames[0]).unwrap();
    let held = decoder.symbols_held(0).unwrap();
    let digest = decoder.journal_digest();

    // A frame from another session, a frame with a broken MAC, and a truncated
    // frame are the three ways capture noise reaches the decoder. None of them
    // may enter the record, or a replay would be asked to reproduce a frame
    // the receiver never wrote down.
    let foreign = Pipeline::new([0x99; 16], params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    assert!(decoder.accept(&foreign[0]).is_err());

    let mut tampered = frames[1].clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    assert!(decoder.accept(&tampered).is_err());

    assert!(decoder.accept(&frames[1][..FRAME_HEADER_SIZE - 1]).is_err());

    assert_eq!(decoder.symbols_held(0), Some(held));
    assert_eq!(decoder.journal_digest(), digest);
}

#[test]
fn test_journal_digest_reproduces_on_replay_and_notices_any_change() {
    let payload = payload_of(4096);
    let params = params_for(&payload, 3, 6);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let taken: Vec<Vec<u8>> = frames.iter().take(20).cloned().collect();

    let digest_of = |stream: &[Vec<u8>]| {
        let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
        for frame in stream {
            decoder.accept(frame).unwrap();
        }
        decoder.journal_digest()
    };

    let original = digest_of(&taken);

    // Replaying the same frames in the same order is the whole point: this is
    // what a restarted receiver does.
    assert_eq!(digest_of(&taken), original);

    // Every way a journal can be doctored has to move the digest.
    let mut reordered = taken.clone();
    reordered.swap(0, 1);
    assert_ne!(digest_of(&reordered), original, "reordering went unnoticed");

    assert_ne!(
        digest_of(&taken[..taken.len() - 1]),
        original,
        "truncation went unnoticed"
    );

    let mut extended = taken.clone();
    extended.push(frames[20].clone());
    assert_ne!(digest_of(&extended), original, "insertion went unnoticed");

    let mut substituted = taken.clone();
    substituted[5] = frames[25].clone();
    assert_ne!(
        digest_of(&substituted),
        original,
        "substitution went unnoticed"
    );
}

#[test]
fn test_journal_digest_of_an_untouched_decoder_is_the_empty_digest() {
    let payload = payload_of(256);
    let params = params_for(&payload, 1, 4);
    let decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    assert_eq!(decoder.journal_digest(), blake3_digest(b""));
}

// --- Resume state ---

/// Replays `stream` into a fresh decoder for `params`.
fn replay(params: SessionParams, stream: &[Vec<u8>]) -> PipelineDecoder {
    let mut decoder = PipelineDecoder::new(SESSION, params, KEY).unwrap();
    for frame in stream {
        decoder.accept(frame).unwrap();
    }
    decoder
}

#[test]
fn test_resume_state_survives_a_write_read_and_replay() {
    let payload = payload_of(8192);
    let params = params_for(&payload, 4, 8);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    // Stop partway, as a killed receiver would.
    let taken: Vec<Vec<u8>> = frames.iter().take(frames.len() / 3).cloned().collect();
    let journal_bytes: u64 = taken.iter().map(|f| f.len() as u64).sum();

    let before = replay(params, &taken);
    assert!(!before.is_complete(), "the test needs an unfinished transfer");

    // Round-trip the state through bytes, which is what a restart really does.
    let saved = before.resume_state(journal_bytes).to_vec();
    let loaded = crate::resume::ResumeFile::from_bytes(&saved).unwrap();
    assert_eq!(loaded.journal_bytes(), journal_bytes);
    assert_eq!(loaded.session_id(), SESSION);

    let after = replay(params, &taken);
    after
        .verify_resume(&loaded)
        .expect("a faithful replay must verify");

    // The point of resuming: the rest of the stream finishes the transfer.
    let mut after = after;
    for frame in &frames[taken.len()..] {
        after.accept(frame).unwrap();
    }
    assert!(after.is_complete());
    assert_eq!(after.finish().unwrap(), payload);
}

#[test]
fn test_resume_state_counts_match_the_decoder() {
    let payload = payload_of(4096);
    let params = params_for(&payload, 3, 6);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let taken: Vec<Vec<u8>> = frames.iter().take(11).cloned().collect();
    let decoder = replay(params, &taken);
    let state = decoder.resume_state(1234);

    assert_eq!(state.entries().len(), params.block_count as usize);
    let total: u32 = state.entries().iter().map(|e| e.symbols_held).sum();
    assert_eq!(total, taken.len() as u32, "every frame must be accounted for");

    for entry in state.entries() {
        assert_eq!(entry.symbol_count, params.total_symbols_per_block);
        assert_eq!(
            entry.symbols_held,
            decoder.symbols_held(entry.block_index).unwrap()
        );
        assert_eq!(
            entry.symbol_bitmap.as_slice(),
            decoder.symbol_bitmap(entry.block_index).unwrap()
        );
    }
}

#[test]
fn test_resume_rejects_a_replay_that_lost_a_frame() {
    let payload = payload_of(4096);
    let params = params_for(&payload, 2, 6);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let taken: Vec<Vec<u8>> = frames.iter().take(12).cloned().collect();
    let state = replay(params, &taken).resume_state(999);

    // A journal truncated by a crash mid-append, replayed against an index
    // that expected more.
    let short = replay(params, &taken[..taken.len() - 1]);
    let err = short.verify_resume(&state).unwrap_err();
    assert!(
        matches!(err, CodecError::Resume(ResumeError::JournalMismatch { .. })),
        "got {err:?}"
    );
}

#[test]
fn test_resume_rejects_a_replay_in_a_different_order() {
    let payload = payload_of(4096);
    let params = params_for(&payload, 2, 6);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    let taken: Vec<Vec<u8>> = frames.iter().take(12).cloned().collect();
    let state = replay(params, &taken).resume_state(999);

    let mut shuffled = taken.clone();
    shuffled.swap(3, 9);
    // The same symbols in a different order leave the bitmaps identical, so
    // only the journal digest can tell these apart.
    let out_of_order = replay(params, &shuffled);
    assert_eq!(
        out_of_order.symbol_bitmap(0),
        replay(params, &taken).symbol_bitmap(0)
    );
    let err = out_of_order.verify_resume(&state).unwrap_err();
    assert!(
        matches!(err, CodecError::Resume(ResumeError::JournalMismatch { .. })),
        "got {err:?}"
    );
}

#[test]
fn test_resume_rejects_state_from_another_session() {
    let payload = payload_of(2048);
    let params = params_for(&payload, 2, 6);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    let taken: Vec<Vec<u8>> = frames.iter().take(8).cloned().collect();

    let foreign_session = [0x11; 16];
    let foreign_frames = Pipeline::new(foreign_session, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    let mut foreign = PipelineDecoder::new(foreign_session, params, KEY).unwrap();
    for frame in foreign_frames.iter().take(8) {
        foreign.accept(frame).unwrap();
    }

    // Two directories, two transfers, one operator pointing at the wrong one.
    let err = replay(params, &taken)
        .verify_resume(&foreign.resume_state(500))
        .unwrap_err();
    assert!(
        matches!(err, CodecError::Resume(ResumeError::SessionMismatch)),
        "got {err:?}"
    );
}

#[test]
fn test_resume_rejects_state_for_a_different_block_layout() {
    let payload = payload_of(4096);
    let two_blocks = params_for(&payload, 2, 6);
    let four_blocks = params_for(&payload, 4, 6);

    let frames = Pipeline::new(SESSION, two_blocks, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();
    let taken: Vec<Vec<u8>> = frames.iter().take(8).cloned().collect();
    let state = replay(two_blocks, &taken).resume_state(700);

    let other = PipelineDecoder::new(SESSION, four_blocks, KEY).unwrap();
    let err = other.verify_resume(&state).unwrap_err();
    assert!(
        matches!(err, CodecError::Resume(ResumeError::JournalMismatch { .. })),
        "got {err:?}"
    );
}

#[test]
fn test_resume_state_of_a_finished_transfer_still_verifies() {
    let payload = payload_of(1024);
    let params = params_for(&payload, 2, 6);
    let frames = Pipeline::new(SESSION, params, KEY)
        .unwrap()
        .encode_to_bytes(&payload)
        .unwrap();

    // Saving on the last frame is an ordinary race, not an edge case.
    let done = replay(params, &frames);
    assert!(done.is_complete());
    let state = done.resume_state(4242);
    replay(params, &frames).verify_resume(&state).unwrap();
}
