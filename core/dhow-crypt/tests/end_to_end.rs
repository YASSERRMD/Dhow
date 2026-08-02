//! End-to-end transfer tests across `dhow-crypt` and `dhow-codec`.
//!
//! These exercise the path a real transfer takes: a payload is encrypted with
//! keys derived from the operator key, chunked and fountain-coded into frames,
//! carried across a simulated optical channel, then decoded, verified, and
//! decrypted. Nothing here mocks a layer; the only thing standing in for the
//! screen and camera is a vector of frame bytes.
//!
//! Faults are injected at each layer to confirm each is caught where it should
//! be, rather than surfacing as corrupt output.

use dhow_codec::blake3::blake3_digest;
use dhow_codec::pipeline::{Pipeline, PipelineDecoder};
use dhow_codec::session::{RaptorQParams, SessionParams};
use dhow_crypt::aead::{TransferKeys, TransferSecrets, decrypt_payload, encrypt_payload};
use dhow_crypt::key::OperatorKey;

const SESSION_ID: [u8; 16] = [0x5A; 16];
const SYMBOL_SIZE: u32 = 256;

/// Everything the sender produces for one transfer.
struct Transmission {
    frames: Vec<Vec<u8>>,
    params: SessionParams,
    secrets: TransferSecrets,
}

/// Runs the sending half: derive keys, encrypt, chunk, and frame.
fn send(operator: &OperatorKey, plaintext: &[u8], block_count: u32) -> Transmission {
    let secrets = TransferSecrets::generate().expect("draw transfer secrets");
    let keys = TransferKeys::derive(operator, &secrets.salt).expect("derive transfer keys");

    // Encryption happens before chunking, so the codec only ever sees ciphertext.
    let ciphertext =
        encrypt_payload(&keys, &secrets.nonce, &SESSION_ID, plaintext).expect("encrypt payload");

    let largest_block = (ciphertext.len() as u64).div_ceil(block_count as u64);
    let source_symbols = largest_block.div_ceil(SYMBOL_SIZE as u64).max(1) as u32;

    let params = SessionParams {
        payload_size: ciphertext.len() as u64,
        block_count,
        symbol_size: SYMBOL_SIZE,
        source_symbols_per_block: source_symbols,
        // Half again as many symbols as strictly needed, so the transfer
        // tolerates a camera missing frames.
        total_symbols_per_block: source_symbols + source_symbols.div_ceil(2) + 4,
        raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
        payload_digest: blake3_digest(&ciphertext),
    };

    let frames = Pipeline::new(SESSION_ID, params, *keys.session_key())
        .expect("build pipeline")
        .encode_to_bytes(&ciphertext)
        .expect("encode frames");

    Transmission {
        frames,
        params,
        secrets,
    }
}

/// Runs the receiving half: authenticate frames, reassemble, verify, decrypt.
fn receive(
    operator: &OperatorKey,
    tx: &Transmission,
    frames: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let keys = TransferKeys::derive(operator, &tx.secrets.salt).map_err(|e| e.to_string())?;

    let mut decoder = PipelineDecoder::new(SESSION_ID, tx.params, *keys.session_key())
        .map_err(|e| e.to_string())?;

    for frame in frames {
        // A real receiver discards frames it cannot authenticate and keeps
        // watching the screen, so rejection is not fatal here either.
        let _ = decoder.accept(frame);
    }

    if !decoder.is_complete() {
        return Err("transfer incomplete".to_string());
    }

    let ciphertext = decoder.finish().map_err(|e| e.to_string())?;
    decrypt_payload(&keys, &tx.secrets.nonce, &SESSION_ID, &ciphertext).map_err(|e| e.to_string())
}

fn payload_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

#[test]
fn transfer_round_trips() {
    let operator = OperatorKey::generate().unwrap();
    let plaintext = payload_of(64 * 1024);
    let tx = send(&operator, &plaintext, 4);
    assert_eq!(receive(&operator, &tx, &tx.frames).unwrap(), plaintext);
}

#[test]
fn transfer_round_trips_across_payload_sizes() {
    let operator = OperatorKey::generate().unwrap();
    for len in [1usize, 255, 256, 257, 4096, 100_000] {
        let plaintext = payload_of(len);
        let tx = send(&operator, &plaintext, 2);
        assert_eq!(
            receive(&operator, &tx, &tx.frames).unwrap(),
            plaintext,
            "round trip failed for a {len}-byte payload"
        );
    }
}

#[test]
fn frames_carry_no_plaintext() {
    // The optical channel is public. A recognizable run in the payload must not
    // be visible in any frame on the wire.
    let operator = OperatorKey::generate().unwrap();
    let plaintext = vec![0xC3u8; 4096];
    let tx = send(&operator, &plaintext, 1);

    for frame in &tx.frames {
        assert!(
            !frame.windows(32).any(|w| w.iter().all(|&b| b == 0xC3)),
            "a frame carried a recognizable run of plaintext"
        );
    }
}

#[test]
fn transfer_survives_dropped_frames() {
    let operator = OperatorKey::generate().unwrap();
    let plaintext = payload_of(32 * 1024);
    let tx = send(&operator, &plaintext, 2);

    // Drop every fourth frame, as a camera missing captures would.
    let received: Vec<Vec<u8>> = tx
        .frames
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 4 != 0)
        .map(|(_, f)| f.clone())
        .collect();

    assert_eq!(receive(&operator, &tx, &received).unwrap(), plaintext);
}

#[test]
fn transfer_survives_reordered_and_duplicated_frames() {
    let operator = OperatorKey::generate().unwrap();
    let plaintext = payload_of(16 * 1024);
    let tx = send(&operator, &plaintext, 2);

    let mut received = tx.frames.clone();
    received.reverse();
    received.extend(tx.frames.iter().cloned());

    assert_eq!(receive(&operator, &tx, &received).unwrap(), plaintext);
}

#[test]
fn transfer_survives_interleaved_corrupt_frames() {
    let operator = OperatorKey::generate().unwrap();
    let plaintext = payload_of(16 * 1024);
    let tx = send(&operator, &plaintext, 1);

    // Every good frame is preceded by a corrupted copy of itself.
    let mut received = Vec::new();
    for frame in &tx.frames {
        let mut bad = frame.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        received.push(bad);
        received.push(frame.clone());
    }

    assert_eq!(receive(&operator, &tx, &received).unwrap(), plaintext);
}

#[test]
fn frames_from_another_transfer_are_rejected() {
    // Recording one transfer and replaying it into another must not contribute
    // symbols, even though both use the same operator key.
    let operator = OperatorKey::generate().unwrap();
    let plaintext = payload_of(8192);

    let first = send(&operator, &plaintext, 1);
    let second = send(&operator, &plaintext, 1);

    // The salt differs per transfer, so the session key differs and the frame
    // MACs from the first transfer do not authenticate under the second.
    assert!(receive(&operator, &second, &first.frames).is_err());
}

#[test]
fn a_receiver_without_the_operator_key_recovers_nothing() {
    let operator = OperatorKey::generate().unwrap();
    let plaintext = payload_of(8192);
    let tx = send(&operator, &plaintext, 1);

    let intruder = OperatorKey::generate().unwrap();
    assert!(receive(&intruder, &tx, &tx.frames).is_err());
}

#[test]
fn tampering_with_ciphertext_is_caught_before_decryption() {
    // Flip a bit in the reassembled ciphertext by corrupting the payload the
    // sender committed to, and confirm the digest check fires rather than a
    // corrupt plaintext being returned.
    let operator = OperatorKey::generate().unwrap();
    let plaintext = payload_of(4096);
    let mut tx = send(&operator, &plaintext, 1);

    tx.params.payload_digest[0] ^= 0x01;
    assert!(receive(&operator, &tx, &tx.frames).is_err());
}

#[test]
fn an_incomplete_transfer_yields_no_data() {
    let operator = OperatorKey::generate().unwrap();
    let plaintext = payload_of(32 * 1024);
    let tx = send(&operator, &plaintext, 4);

    // Far too few frames to decode any block.
    let received: Vec<Vec<u8>> = tx.frames.iter().take(2).cloned().collect();
    assert!(receive(&operator, &tx, &received).is_err());
}

#[test]
fn transfer_is_deterministic() {
    // The same payload, salt, and nonce must produce a byte-identical stream.
    let operator = OperatorKey::generate().unwrap();
    let plaintext = payload_of(8192);
    let tx = send(&operator, &plaintext, 2);

    let keys = TransferKeys::derive(&operator, &tx.secrets.salt).unwrap();
    let ciphertext = encrypt_payload(&keys, &tx.secrets.nonce, &SESSION_ID, &plaintext).unwrap();
    let again = Pipeline::new(SESSION_ID, tx.params, *keys.session_key())
        .unwrap()
        .encode_to_bytes(&ciphertext)
        .unwrap();

    assert_eq!(again, tx.frames);
}
