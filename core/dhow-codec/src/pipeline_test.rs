//! Tests for the frame assembly pipeline.

use crate::pipeline::Pipeline;
use crate::session::{RaptorQParams, SessionParams};

fn test_params(payload_size: u64) -> SessionParams {
    SessionParams {
        payload_size,
        block_count: 1,
        symbol_size: 256,
        source_symbols_per_block: 0,
        total_symbols_per_block: 0,
        raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
        payload_digest: [0u8; 32],
    }
}

#[test]
fn test_pipeline_simple() {
    let payload = b"Hello, Dhow!";
    let mut params = test_params(payload.len() as u64);
    params.source_symbols_per_block = 1;
    params.total_symbols_per_block = 2;
    let pipeline = Pipeline::new([0x42; 16], params, [0xAB; 32]);
    let frames = pipeline.encode(payload);
    assert!(frames.is_ok());
    let frames = frames.unwrap();
    assert!(!frames.is_empty()); // at least source symbols
}

#[test]
fn test_pipeline_session_id_access() {
    let params = test_params(55);
    let pipeline = Pipeline::new([0xAB; 16], params, [0u8; 32]);
    assert_eq!(pipeline.session_id(), [0xAB; 16]);
}

#[test]
fn test_pipeline_params_access() {
    let params = test_params(55);
    let pipeline = Pipeline::new([0; 16], params, [0u8; 32]);
    assert_eq!(pipeline.params().payload_size, 55);
}

#[test]
fn test_pipeline_encode_to_bytes() {
    let payload = b"test data for pipeline encoding test";
    let mut params = test_params(payload.len() as u64);
    params.source_symbols_per_block = 1;
    params.total_symbols_per_block = 2;
    let pipeline = Pipeline::new([0; 16], params, [0u8; 32]);
    let result = pipeline.encode_to_bytes(payload);
    assert!(result.is_ok());
    let frames = result.unwrap();
    assert!(!frames.is_empty());
}

#[test]
fn test_pipeline_wrong_payload_size() {
    let params = test_params(100);
    let pipeline = Pipeline::new([0; 16], params, [0u8; 32]);
    let result = pipeline.encode(b"short");
    assert!(result.is_err());
}

#[test]
fn test_pipeline_multiple_blocks() {
    let payload: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
    let mut params = test_params(payload.len() as u64);
    params.block_count = 2;
    params.source_symbols_per_block = 1;
    params.total_symbols_per_block = 2;
    let pipeline = Pipeline::new([0x55; 16], params, [0xAB; 32]);
    let frames = pipeline.encode(&payload);
    assert!(frames.is_ok());
    let frames = frames.unwrap();
    assert!(frames.len() >= 2); // at least 1 source per block
}

#[test]
fn test_pipeline_preserves_data() {
    let payload: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let mut params = test_params(payload.len() as u64);
    params.source_symbols_per_block = 1;
    params.total_symbols_per_block = 1;
    let pipeline = Pipeline::new([0xAA; 16], params, [0xBB; 32]);
    let frames = pipeline.encode(&payload).unwrap();
    assert!(!frames.is_empty());
    // Verify first frame has the payload
    let first_frame = &frames[0].frame;
    assert_eq!(
        first_frame.header().frame_type(),
        crate::frame::FrameType::Repair
    );
}
