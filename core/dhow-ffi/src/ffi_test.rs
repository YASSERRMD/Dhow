//! Tests driving the C ABI the way a foreign caller would.
//!
//! Every call goes through the exported `extern "C"` functions with raw
//! pointers, rather than reaching past them into the Rust API, so these cover
//! the boundary itself: null handling, the two-call size convention, buffer
//! bounds, and handle lifetimes.

use crate::error::{DhowStatus, dhow_status_string};
use crate::handle::*;
use crate::{dhow_abi_version, dhow_version_string};
use std::ffi::CString;
use std::ptr;

const SESSION: [u8; 16] = [0x5A; 16];
const SALT: [u8; 32] = [0x11; 32];
const NONCE: [u8; 24] = [0x22; 24];

fn params_for(payload_len: usize) -> DhowSessionParams {
    let symbol_size = 256u32;
    // Account for the AEAD tag the encoder appends before framing.
    let ciphertext_len = (payload_len + 16) as u64;
    let source = ciphertext_len.div_ceil(symbol_size as u64).max(1) as u32;
    DhowSessionParams {
        payload_size: ciphertext_len,
        block_count: 1,
        symbol_size,
        source_symbols_per_block: source,
        total_symbols_per_block: source + source.div_ceil(2) + 4,
        payload_digest: [0u8; 32],
    }
}

/// Collects every frame from an encoder using the two-call size convention.
fn drain_frames(encoder: *mut DhowEncoder) -> Vec<Vec<u8>> {
    let count = unsafe { dhow_encoder_frame_count(encoder) };
    assert!(count > 0, "encoder produced no frames");

    (0..count as usize)
        .map(|i| {
            let mut needed = 0usize;
            let status = unsafe { dhow_encoder_frame(encoder, i, ptr::null_mut(), 0, &mut needed) };
            assert_eq!(status, DhowStatus::Ok);
            assert!(needed > 0);

            let mut buf = vec![0u8; needed];
            let mut written = 0usize;
            let status = unsafe {
                dhow_encoder_frame(encoder, i, buf.as_mut_ptr(), buf.len(), &mut written)
            };
            assert_eq!(status, DhowStatus::Ok);
            assert_eq!(written, needed);
            buf
        })
        .collect()
}

/// Runs a full transfer across the ABI and returns the recovered plaintext.
fn round_trip(plaintext: &[u8]) -> Vec<u8> {
    let key = dhow_key_generate();
    assert!(!key.is_null());

    let params = params_for(plaintext.len());
    let encoder = unsafe {
        dhow_encoder_new(
            key,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params,
            plaintext.as_ptr(),
            plaintext.len(),
        )
    };
    assert!(!encoder.is_null(), "encoder construction failed");

    let frames = drain_frames(encoder);

    // The encoder recomputes payload size and digest from the ciphertext it
    // produced. A real sender puts these in the signed manifest; here the
    // decoder reads them straight back, which is what the manifest carries.
    let mut decoder_params = params;
    assert_eq!(
        unsafe { dhow_encoder_params(encoder, &mut decoder_params) },
        DhowStatus::Ok
    );

    let decoder = unsafe { dhow_decoder_new(key, SESSION.as_ptr(), SALT.as_ptr(), decoder_params) };
    assert!(!decoder.is_null(), "decoder construction failed");

    for frame in &frames {
        let status = unsafe { dhow_decoder_accept(decoder, frame.as_ptr(), frame.len()) };
        assert_eq!(status, DhowStatus::Ok, "frame rejected during round trip");
    }

    assert_eq!(unsafe { dhow_decoder_is_complete(decoder) }, 1);

    let mut needed = 0usize;
    let status = unsafe {
        dhow_decoder_finish(
            decoder,
            key,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    assert_eq!(status, DhowStatus::Ok);

    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let status = unsafe {
        dhow_decoder_finish(
            decoder,
            key,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    assert_eq!(status, DhowStatus::Ok);
    out.truncate(written);

    unsafe {
        dhow_decoder_free(decoder);
        dhow_encoder_free(encoder);
        dhow_key_free(key);
    }

    out
}

// --- Version ---

#[test]
fn test_abi_version_is_reported() {
    assert_eq!(dhow_abi_version(), crate::DHOW_ABI_VERSION);
}

#[test]
fn test_version_string_is_nul_terminated() {
    let ptr = dhow_version_string();
    assert!(!ptr.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
    assert!(!s.is_empty());
}

#[test]
fn test_status_string_covers_every_code() {
    // The lower bound tracks the most negative DhowStatus variant. A new code
    // without a description would otherwise read as "unknown status" to every
    // caller and nothing would notice.
    for code in (DhowStatus::ResumeRejected as i32)..=0 {
        let ptr = dhow_status_string(code);
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(!s.is_empty());
        assert_ne!(s, "unknown status", "code {code} has no description");
    }
    // An out-of-range code is described rather than crashing.
    let s = unsafe { std::ffi::CStr::from_ptr(dhow_status_string(999)) }
        .to_str()
        .unwrap();
    assert_eq!(s, "unknown status");
}

// --- Null handling ---

#[test]
fn test_null_handles_are_rejected_not_dereferenced() {
    unsafe {
        assert_eq!(
            dhow_key_save(ptr::null(), ptr::null()),
            DhowStatus::NullArgument
        );
        assert_eq!(
            dhow_encoder_frame(ptr::null(), 0, ptr::null_mut(), 0, ptr::null_mut()),
            DhowStatus::NullArgument
        );
        assert_eq!(
            dhow_decoder_accept(ptr::null_mut(), ptr::null(), 0),
            DhowStatus::NullArgument
        );
        assert!(dhow_encoder_frame_count(ptr::null()) < 0);
        assert!(dhow_decoder_is_complete(ptr::null()) < 0);
        assert!(dhow_decoder_blocks_complete(ptr::null()) < 0);
    }
}

#[test]
fn test_freeing_null_is_a_no_op() {
    // Cleanup paths should not need a null check.
    unsafe {
        dhow_key_free(ptr::null_mut());
        dhow_encoder_free(ptr::null_mut());
        dhow_decoder_free(ptr::null_mut());
    }
}

#[test]
fn test_encoder_new_rejects_null_arguments() {
    let key = dhow_key_generate();
    let params = params_for(16);
    let payload = [0u8; 16];

    unsafe {
        assert!(
            dhow_encoder_new(
                ptr::null(),
                SESSION.as_ptr(),
                SALT.as_ptr(),
                NONCE.as_ptr(),
                params,
                payload.as_ptr(),
                payload.len()
            )
            .is_null()
        );
        assert!(
            dhow_encoder_new(
                key,
                ptr::null(),
                SALT.as_ptr(),
                NONCE.as_ptr(),
                params,
                payload.as_ptr(),
                payload.len()
            )
            .is_null()
        );
        dhow_key_free(key);
    }
}

// --- Round trip ---

#[test]
fn test_round_trip_across_the_abi() {
    let plaintext = b"payload crossing the C ABI".to_vec();
    assert_eq!(round_trip(&plaintext), plaintext);
}

#[test]
fn test_round_trip_across_sizes() {
    for len in [1usize, 100, 1024, 8192] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        assert_eq!(round_trip(&plaintext), plaintext, "failed at length {len}");
    }
}

// --- Buffer conventions ---

#[test]
fn test_frame_query_reports_size_without_writing() {
    let key = dhow_key_generate();
    let payload = b"size query".to_vec();
    let encoder = unsafe {
        dhow_encoder_new(
            key,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params_for(payload.len()),
            payload.as_ptr(),
            payload.len(),
        )
    };
    assert!(!encoder.is_null());

    let mut needed = 0usize;
    assert_eq!(
        unsafe { dhow_encoder_frame(encoder, 0, ptr::null_mut(), 0, &mut needed) },
        DhowStatus::Ok
    );
    assert!(needed > 0);

    unsafe {
        dhow_encoder_free(encoder);
        dhow_key_free(key);
    }
}

#[test]
fn test_undersized_buffer_is_refused_without_writing() {
    let key = dhow_key_generate();
    let payload = b"buffer bounds".to_vec();
    let encoder = unsafe {
        dhow_encoder_new(
            key,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params_for(payload.len()),
            payload.as_ptr(),
            payload.len(),
        )
    };

    let mut needed = 0usize;
    unsafe { dhow_encoder_frame(encoder, 0, ptr::null_mut(), 0, &mut needed) };

    // One byte short. The canary must survive untouched.
    let mut buf = vec![0xEEu8; needed];
    let mut written = 0usize;
    let status =
        unsafe { dhow_encoder_frame(encoder, 0, buf.as_mut_ptr(), needed - 1, &mut written) };
    assert_eq!(status, DhowStatus::BufferTooSmall);
    assert!(
        buf.iter().all(|&b| b == 0xEE),
        "a rejected write still touched the buffer"
    );

    unsafe {
        dhow_encoder_free(encoder);
        dhow_key_free(key);
    }
}

#[test]
fn test_out_of_range_frame_index_is_rejected() {
    let key = dhow_key_generate();
    let payload = b"index bounds".to_vec();
    let encoder = unsafe {
        dhow_encoder_new(
            key,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params_for(payload.len()),
            payload.as_ptr(),
            payload.len(),
        )
    };

    let count = unsafe { dhow_encoder_frame_count(encoder) } as usize;
    let mut written = 0usize;
    assert_eq!(
        unsafe { dhow_encoder_frame(encoder, count, ptr::null_mut(), 0, &mut written) },
        DhowStatus::InvalidArgument
    );
    assert_eq!(
        unsafe { dhow_encoder_frame(encoder, usize::MAX, ptr::null_mut(), 0, &mut written) },
        DhowStatus::InvalidArgument
    );

    unsafe {
        dhow_encoder_free(encoder);
        dhow_key_free(key);
    }
}

// --- Rejection behaviour ---

#[test]
fn test_garbage_frames_are_rejected_without_crashing() {
    let key = dhow_key_generate();
    let decoder = unsafe { dhow_decoder_new(key, SESSION.as_ptr(), SALT.as_ptr(), params_for(64)) };
    assert!(!decoder.is_null());

    for garbage in [
        vec![],
        vec![0u8; 1],
        vec![0u8; 45],
        vec![0xFFu8; 46],
        vec![0xABu8; 512],
    ] {
        let status = unsafe { dhow_decoder_accept(decoder, garbage.as_ptr(), garbage.len()) };
        assert_eq!(
            status,
            DhowStatus::FrameRejected,
            "garbage of {} bytes was accepted",
            garbage.len()
        );
    }

    assert_eq!(unsafe { dhow_decoder_is_complete(decoder) }, 0);

    unsafe {
        dhow_decoder_free(decoder);
        dhow_key_free(key);
    }
}

#[test]
fn test_finish_before_completion_reports_incomplete() {
    let key = dhow_key_generate();
    let decoder =
        unsafe { dhow_decoder_new(key, SESSION.as_ptr(), SALT.as_ptr(), params_for(4096)) };

    let mut written = 0usize;
    let status = unsafe {
        dhow_decoder_finish(
            decoder,
            key,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            ptr::null_mut(),
            0,
            &mut written,
        )
    };
    assert_eq!(status, DhowStatus::Incomplete);

    unsafe {
        dhow_decoder_free(decoder);
        dhow_key_free(key);
    }
}

#[test]
fn test_invalid_session_parameters_are_rejected() {
    let key = dhow_key_generate();
    let mut params = params_for(64);
    params.symbol_size = 8; // below the FEC minimum

    let decoder = unsafe { dhow_decoder_new(key, SESSION.as_ptr(), SALT.as_ptr(), params) };
    assert!(decoder.is_null(), "invalid parameters produced a decoder");

    unsafe { dhow_key_free(key) };
}

// --- Error channel ---

#[test]
fn test_last_error_is_populated_and_readable() {
    let key = dhow_key_generate();
    let decoder = unsafe { dhow_decoder_new(key, SESSION.as_ptr(), SALT.as_ptr(), params_for(64)) };

    let junk = [0u8; 46];
    unsafe { dhow_decoder_accept(decoder, junk.as_ptr(), junk.len()) };

    let needed = unsafe { crate::dhow_last_error_message(ptr::null_mut(), 0) };
    assert!(needed > 1, "no error message was recorded");

    let mut buf = vec![0i8; needed as usize];
    let got = unsafe { crate::dhow_last_error_message(buf.as_mut_ptr(), buf.len()) };
    assert_eq!(got, needed);

    let text = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_str()
        .unwrap();
    assert!(!text.is_empty());

    unsafe {
        dhow_decoder_free(decoder);
        dhow_key_free(key);
    }
}

#[test]
fn test_last_error_refuses_an_undersized_buffer() {
    let key = dhow_key_generate();
    let decoder = unsafe { dhow_decoder_new(key, SESSION.as_ptr(), SALT.as_ptr(), params_for(64)) };
    let junk = [0u8; 46];
    unsafe { dhow_decoder_accept(decoder, junk.as_ptr(), junk.len()) };

    let needed = unsafe { crate::dhow_last_error_message(ptr::null_mut(), 0) };
    let mut buf = vec![0i8; 1];
    let status = unsafe { crate::dhow_last_error_message(buf.as_mut_ptr(), 1) };
    assert!(status < 0, "an undersized buffer was accepted");
    assert!(needed > 1);

    unsafe {
        dhow_decoder_free(decoder);
        dhow_key_free(key);
    }
}

#[test]
fn test_error_messages_carry_no_key_material() {
    // The key is generated from the CSPRNG, so this checks the shape of the
    // message rather than a specific value: a description should name what
    // went wrong, not echo bytes.
    let key = dhow_key_generate();
    let decoder = unsafe { dhow_decoder_new(key, SESSION.as_ptr(), SALT.as_ptr(), params_for(64)) };
    let junk = [0x5Au8; 46];
    unsafe { dhow_decoder_accept(decoder, junk.as_ptr(), junk.len()) };

    let needed = unsafe { crate::dhow_last_error_message(ptr::null_mut(), 0) };
    let mut buf = vec![0i8; needed as usize];
    unsafe { crate::dhow_last_error_message(buf.as_mut_ptr(), buf.len()) };
    let text = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_str()
        .unwrap()
        .to_lowercase();

    for forbidden in ["operator key", "session key", "payload key", "seed"] {
        assert!(
            !text.contains(forbidden),
            "error message mentioned {forbidden}: {text}"
        );
    }

    unsafe {
        dhow_decoder_free(decoder);
        dhow_key_free(key);
    }
}

// --- Key handles ---

#[test]
fn test_key_save_and_load_round_trip() {
    let dir = std::env::temp_dir().join(format!("dhow-ffi-key-{:?}", std::thread::current().id()));
    let dir = PathBufSanitized(dir);
    std::fs::create_dir_all(&dir.0).unwrap();
    let path = dir.0.join("operator.key");
    let c_path = CString::new(path.to_str().unwrap()).unwrap();

    let key = dhow_key_generate();
    assert_eq!(
        unsafe { dhow_key_save(key, c_path.as_ptr()) },
        DhowStatus::Ok
    );

    let loaded = unsafe { dhow_key_load(c_path.as_ptr()) };
    assert!(!loaded.is_null(), "saved key failed to load");

    unsafe {
        dhow_key_free(loaded);
        dhow_key_free(key);
    }
    let _ = std::fs::remove_dir_all(&dir.0);
}

#[test]
fn test_key_load_of_missing_file_returns_null() {
    let c_path = CString::new("/nonexistent/dhow/operator.key").unwrap();
    let key = unsafe { dhow_key_load(c_path.as_ptr()) };
    assert!(key.is_null());
}

#[test]
fn test_key_load_rejects_null_path() {
    assert!(unsafe { dhow_key_load(ptr::null()) }.is_null());
}

/// Wrapper whose only purpose is to make the temp directory's cleanup explicit.
struct PathBufSanitized(std::path::PathBuf);

impl std::ops::Deref for PathBufSanitized {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// --- Resume across the ABI ---

/// Builds an encoder plus the parameters a decoder needs for the same session.
fn encode_session(plaintext: &[u8]) -> (*mut DhowKey, Vec<Vec<u8>>, DhowSessionParams) {
    let key = dhow_key_generate();
    assert!(!key.is_null());

    let params = params_for(plaintext.len());
    let encoder = unsafe {
        dhow_encoder_new(
            key,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params,
            plaintext.as_ptr(),
            plaintext.len(),
        )
    };
    assert!(!encoder.is_null());

    let frames = drain_frames(encoder);
    let mut resolved = params;
    assert_eq!(
        unsafe { dhow_encoder_params(encoder, &mut resolved) },
        DhowStatus::Ok
    );
    unsafe { dhow_encoder_free(encoder) };

    (key, frames, resolved)
}

/// Feeds `frames` to a new decoder for `params` and returns the handle.
fn decoder_fed(
    key: *mut DhowKey,
    params: DhowSessionParams,
    frames: &[Vec<u8>],
) -> *mut DhowDecoder {
    let decoder = unsafe { dhow_decoder_new(key, SESSION.as_ptr(), SALT.as_ptr(), params) };
    assert!(!decoder.is_null());
    for frame in frames {
        assert_eq!(
            unsafe { dhow_decoder_accept(decoder, frame.as_ptr(), frame.len()) },
            DhowStatus::Ok
        );
    }
    decoder
}

/// Reads a decoder's resume state using the two-call size convention.
fn resume_state_of(decoder: *mut DhowDecoder, journal_bytes: u64) -> Vec<u8> {
    let mut needed = 0usize;
    assert_eq!(
        unsafe {
            dhow_decoder_resume_state(decoder, journal_bytes, ptr::null_mut(), 0, &mut needed)
        },
        DhowStatus::Ok
    );
    assert!(needed > 0);

    let mut buf = vec![0u8; needed];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            dhow_decoder_resume_state(
                decoder,
                journal_bytes,
                buf.as_mut_ptr(),
                buf.len(),
                &mut written,
            )
        },
        DhowStatus::Ok
    );
    assert_eq!(written, needed);
    buf
}

#[test]
fn test_resume_state_round_trips_across_the_abi() {
    let plaintext: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let (key, frames, params) = encode_session(&plaintext);

    let taken = &frames[..frames.len() / 2];
    let journal_bytes: u64 = taken.iter().map(|f| f.len() as u64).sum();

    let first = decoder_fed(key, params, taken);
    let state = resume_state_of(first, journal_bytes);
    unsafe { dhow_decoder_free(first) };

    // What a restart reads back before it can build anything.
    let mut session_id = [0u8; 16];
    let mut read_bytes = 0u64;
    let mut block_count = 0u32;
    assert_eq!(
        unsafe {
            dhow_resume_state_read(
                state.as_ptr(),
                state.len(),
                session_id.as_mut_ptr(),
                &mut read_bytes,
                &mut block_count,
            )
        },
        DhowStatus::Ok
    );
    assert_eq!(session_id, SESSION);
    assert_eq!(read_bytes, journal_bytes);
    assert_eq!(block_count, params.block_count);

    // Replay, verify, then finish from the frames that were still to come.
    let second = decoder_fed(key, params, taken);
    assert_eq!(
        unsafe { dhow_decoder_resume_verify(second, state.as_ptr(), state.len()) },
        DhowStatus::Ok
    );

    for frame in &frames[taken.len()..] {
        assert_eq!(
            unsafe { dhow_decoder_accept(second, frame.as_ptr(), frame.len()) },
            DhowStatus::Ok
        );
    }
    assert_eq!(unsafe { dhow_decoder_is_complete(second) }, 1);

    unsafe {
        dhow_decoder_free(second);
        dhow_key_free(key);
    }
}

#[test]
fn test_resume_verify_rejects_a_divergent_replay() {
    let plaintext: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
    let (key, frames, params) = encode_session(&plaintext);

    let taken = &frames[..8];
    let full = decoder_fed(key, params, taken);
    let state = resume_state_of(full, 1000);
    unsafe { dhow_decoder_free(full) };

    let short = decoder_fed(key, params, &taken[..7]);
    let status = unsafe { dhow_decoder_resume_verify(short, state.as_ptr(), state.len()) };
    assert_eq!(status, DhowStatus::ResumeRejected);

    unsafe {
        dhow_decoder_free(short);
        dhow_key_free(key);
    }
}

#[test]
fn test_resume_state_read_rejects_a_corrupted_file() {
    let plaintext: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    let (key, frames, params) = encode_session(&plaintext);
    let decoder = decoder_fed(key, params, &frames[..4]);
    let good = resume_state_of(decoder, 500);

    // Every byte the digests cover must be load-bearing at the boundary too,
    // not only inside Rust.
    for offset in [0usize, 4, 8, 30, 40, 92, 100] {
        let mut bad = good.clone();
        bad[offset] ^= 0x01;
        assert_eq!(
            unsafe {
                dhow_resume_state_read(
                    bad.as_ptr(),
                    bad.len(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            },
            DhowStatus::ResumeRejected,
            "corruption at offset {offset} was accepted"
        );
        assert_eq!(
            unsafe { dhow_decoder_resume_verify(decoder, bad.as_ptr(), bad.len()) },
            DhowStatus::ResumeRejected,
            "verify accepted corruption at offset {offset}"
        );
    }

    unsafe {
        dhow_decoder_free(decoder);
        dhow_key_free(key);
    }
}

#[test]
fn test_resume_calls_reject_null_arguments() {
    let state = [0u8; 128];

    assert_eq!(
        unsafe { dhow_decoder_resume_state(ptr::null(), 0, ptr::null_mut(), 0, ptr::null_mut()) },
        DhowStatus::NullArgument
    );
    assert_eq!(
        unsafe { dhow_decoder_resume_verify(ptr::null(), state.as_ptr(), state.len()) },
        DhowStatus::NullArgument
    );
    assert_eq!(
        unsafe {
            dhow_resume_state_read(
                ptr::null(),
                16,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        DhowStatus::NullArgument
    );
}

#[test]
fn test_resume_state_honours_the_buffer_size_contract() {
    let plaintext: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    let (key, frames, params) = encode_session(&plaintext);
    let decoder = decoder_fed(key, params, &frames[..4]);

    let mut needed = 0usize;
    assert_eq!(
        unsafe { dhow_decoder_resume_state(decoder, 0, ptr::null_mut(), 0, &mut needed) },
        DhowStatus::Ok
    );

    // One byte short must fail without writing, not truncate silently.
    let mut small = vec![0xEEu8; needed - 1];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            dhow_decoder_resume_state(decoder, 0, small.as_mut_ptr(), small.len(), &mut written)
        },
        DhowStatus::BufferTooSmall
    );
    assert!(
        small.iter().all(|&b| b == 0xEE),
        "a rejected call wrote into the caller's buffer"
    );

    unsafe {
        dhow_decoder_free(decoder);
        dhow_key_free(key);
    }
}

#[test]
fn test_resume_state_read_rejects_a_truncated_file() {
    let plaintext: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    let (key, frames, params) = encode_session(&plaintext);
    let decoder = decoder_fed(key, params, &frames[..4]);
    let good = resume_state_of(decoder, 500);

    for len in [0usize, 1, 64, 127, good.len() - 1] {
        assert_eq!(
            unsafe {
                dhow_resume_state_read(
                    good.as_ptr(),
                    len,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            },
            DhowStatus::ResumeRejected,
            "a {len}-byte state was accepted"
        );
    }

    unsafe {
        dhow_decoder_free(decoder);
        dhow_key_free(key);
    }
}

#[test]
fn test_abi_version_matches_the_constant() {
    // Pinned to the constant rather than to a literal. A literal has to be
    // edited in step with every bump, which makes the test a chore that gets
    // updated reflexively rather than a check anyone reads.
    assert_eq!(dhow_abi_version(), crate::DHOW_ABI_VERSION);
    // The Go bindings assert the number itself, which is where a mismatch
    // between the two sides actually matters.
}

// --- Digests ---

/// Formats a digest as lower-case hex.
///
/// Written out rather than pulled from a crate: this is the only place in this
/// package that needs it, and a test dependency is still a dependency.
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn test_blake3_matches_the_published_vectors() {
    // The empty digest and the one-byte digest are the two values every BLAKE3
    // implementation is checked against first.
    let cases: [(&[u8], &str); 2] = [
        (
            b"",
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
        (
            b"\x00",
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        ),
    ];

    for (input, expected) in cases {
        let mut out = [0u8; 32];
        let status = unsafe { dhow_blake3(input.as_ptr(), input.len(), out.as_mut_ptr()) };
        assert_eq!(status, DhowStatus::Ok);
        assert_eq!(hex_of(&out), expected, "input {input:?}");
    }
}

#[test]
fn test_blake3_distinguishes_inputs_that_differ_by_one_bit() {
    let a = [0x00u8; 64];
    let mut b = a;
    b[63] = 0x01;

    let mut da = [0u8; 32];
    let mut db = [0u8; 32];
    assert_eq!(
        unsafe { dhow_blake3(a.as_ptr(), a.len(), da.as_mut_ptr()) },
        DhowStatus::Ok
    );
    assert_eq!(
        unsafe { dhow_blake3(b.as_ptr(), b.len(), db.as_mut_ptr()) },
        DhowStatus::Ok
    );
    assert_ne!(da, db);
}

#[test]
fn test_blake3_rejects_null_arguments() {
    let data = [1u8, 2, 3];
    let mut out = [0u8; 32];

    assert_eq!(
        unsafe { dhow_blake3(data.as_ptr(), data.len(), ptr::null_mut()) },
        DhowStatus::NullArgument
    );
    assert_eq!(
        unsafe { dhow_blake3(ptr::null(), 8, out.as_mut_ptr()) },
        DhowStatus::NullArgument
    );

    // Null is null whatever the length says, matching every other buffer
    // argument here. A caller hashing an empty file passes a valid pointer.
    assert_eq!(
        unsafe { dhow_blake3(ptr::null(), 0, out.as_mut_ptr()) },
        DhowStatus::NullArgument
    );
    let empty = [0u8; 1];
    assert_eq!(
        unsafe { dhow_blake3(empty.as_ptr(), 0, out.as_mut_ptr()) },
        DhowStatus::Ok
    );
}

// --- Identities ---

/// Builds a `DhowFileEntry` array plus the CStrings backing its names.
///
/// The CStrings are returned alongside the entries because the entries only
/// borrow their names; dropping them first would leave dangling pointers, which
/// is exactly the mistake a foreign caller can make and the reason the lifetime
/// is spelled out in the header.
fn entry_array(files: &[(&str, u64, u8, bool)]) -> (Vec<CString>, Vec<DhowFileEntry>) {
    let names: Vec<CString> = files.iter().map(|f| CString::new(f.0).unwrap()).collect();
    let entries = files
        .iter()
        .zip(&names)
        .map(|((_, size, digest_byte, executable), name)| DhowFileEntry {
            name: name.as_ptr(),
            size: *size,
            digest: [*digest_byte; 32],
            executable: u8::from(*executable),
            reserved: [0; 7],
        })
        .collect();
    (names, entries)
}

fn sample_files() -> Vec<(&'static str, u64, u8, bool)> {
    vec![
        ("docs/readme.md", 100, 0x01, false),
        ("run.sh", 12, 0x02, true),
        ("nested/deep/blob.bin", 65536, 0x03, false),
    ]
}

#[test]
fn identity_generates_saves_and_loads() {
    let dir = std::env::temp_dir().join(format!("dhow-ffi-identity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = CString::new(dir.join("sender.key").to_str().unwrap()).unwrap();

    let identity = dhow_identity_generate();
    assert!(!identity.is_null());
    assert_eq!(
        unsafe { dhow_identity_save(identity, path.as_ptr()) },
        DhowStatus::Ok
    );

    let loaded = unsafe { dhow_identity_load(path.as_ptr()) };
    assert!(!loaded.is_null(), "saved identity did not load back");

    // The same identity must produce the same public key, or a receiver
    // holding the public half would stop being able to verify after a reload.
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let pa = unsafe { dhow_identity_public(identity) };
    let pb = unsafe { dhow_identity_public(loaded) };
    assert_eq!(
        unsafe { dhow_public_bytes(pa, a.as_mut_ptr()) },
        DhowStatus::Ok
    );
    assert_eq!(
        unsafe { dhow_public_bytes(pb, b.as_mut_ptr()) },
        DhowStatus::Ok
    );
    assert_eq!(a, b);

    unsafe {
        dhow_public_free(pa);
        dhow_public_free(pb);
        dhow_identity_free(loaded);
        dhow_identity_free(identity);
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_operator_key_does_not_load_as_an_identity() {
    // The two key kinds are distinguished inside the key file, and confusing
    // them would mean signing with a key both operators hold.
    let dir = std::env::temp_dir().join(format!("dhow-ffi-kind-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = CString::new(dir.join("operator.key").to_str().unwrap()).unwrap();

    let key = dhow_key_generate();
    assert_eq!(unsafe { dhow_key_save(key, path.as_ptr()) }, DhowStatus::Ok);
    assert!(
        unsafe { dhow_identity_load(path.as_ptr()) }.is_null(),
        "an operator key loaded as an identity"
    );
    unsafe { dhow_key_free(key) };
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn public_identity_round_trips_through_a_file() {
    let dir = std::env::temp_dir().join(format!("dhow-ffi-public-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = CString::new(dir.join("sender.pub").to_str().unwrap()).unwrap();

    let identity = dhow_identity_generate();
    let public = unsafe { dhow_identity_public(identity) };
    assert_eq!(
        unsafe { dhow_public_save(public, path.as_ptr()) },
        DhowStatus::Ok
    );

    let loaded = unsafe { dhow_public_load(path.as_ptr()) };
    assert!(!loaded.is_null());

    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    unsafe { dhow_public_bytes(public, a.as_mut_ptr()) };
    unsafe { dhow_public_bytes(loaded, b.as_mut_ptr()) };
    assert_eq!(a, b);

    unsafe {
        dhow_public_free(loaded);
        dhow_public_free(public);
        dhow_identity_free(identity);
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn fingerprint_follows_the_two_call_convention() {
    let identity = dhow_identity_generate();
    let public = unsafe { dhow_identity_public(identity) };

    let mut needed = 0usize;
    assert_eq!(
        unsafe { dhow_public_fingerprint(public, ptr::null_mut(), 0, &mut needed) },
        DhowStatus::Ok
    );
    assert_eq!(needed, 23, "8 hex bytes joined by colons");

    let mut buf = vec![0u8; needed];
    assert_eq!(
        unsafe { dhow_public_fingerprint(public, buf.as_mut_ptr(), buf.len(), ptr::null_mut()) },
        DhowStatus::Ok
    );
    let text = String::from_utf8(buf).unwrap();
    assert_eq!(text.split(':').count(), 8, "fingerprint was {text}");

    // One byte short must be refused rather than truncated.
    let mut small = vec![0u8; needed - 1];
    assert_eq!(
        unsafe {
            dhow_public_fingerprint(public, small.as_mut_ptr(), small.len(), ptr::null_mut())
        },
        DhowStatus::BufferTooSmall
    );

    unsafe {
        dhow_public_free(public);
        dhow_identity_free(identity);
    }
}

#[test]
fn identity_calls_reject_null_handles() {
    assert!(unsafe { dhow_identity_public(ptr::null()) }.is_null());
    assert_eq!(
        unsafe { dhow_identity_save(ptr::null(), ptr::null()) },
        DhowStatus::NullArgument
    );
    assert_eq!(
        unsafe { dhow_public_bytes(ptr::null(), ptr::null_mut()) },
        DhowStatus::NullArgument
    );
    // Freeing null is a no-op on every handle type here.
    unsafe {
        dhow_identity_free(ptr::null_mut());
        dhow_public_free(ptr::null_mut());
        dhow_manifest_free(ptr::null_mut());
    }
}

// --- Manifests ---

#[test]
fn a_manifest_round_trips_its_whole_inventory() {
    let identity = dhow_identity_generate();
    let public = unsafe { dhow_identity_public(identity) };
    let files = sample_files();
    let (_names, entries) = entry_array(&files);
    let params = params_for(4096);

    let built = unsafe {
        dhow_manifest_build(
            identity,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params,
            entries.as_ptr(),
            entries.len(),
        )
    };
    assert!(!built.is_null(), "manifest build failed");

    let mut needed = 0usize;
    assert_eq!(
        unsafe { dhow_manifest_bytes(built, ptr::null_mut(), 0, &mut needed) },
        DhowStatus::Ok
    );
    let mut wire = vec![0u8; needed];
    assert_eq!(
        unsafe { dhow_manifest_bytes(built, wire.as_mut_ptr(), wire.len(), ptr::null_mut()) },
        DhowStatus::Ok
    );

    let verified = unsafe { dhow_manifest_verify(public, wire.as_ptr(), wire.len(), ptr::null()) };
    assert!(
        !verified.is_null(),
        "a manifest we just signed did not verify"
    );

    // Session material.
    let mut session = [0u8; 16];
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    unsafe {
        dhow_manifest_session_id(verified, session.as_mut_ptr());
        dhow_manifest_salt(verified, salt.as_mut_ptr());
        dhow_manifest_nonce(verified, nonce.as_mut_ptr());
    }
    assert_eq!(session, SESSION);
    assert_eq!(salt, SALT);
    assert_eq!(nonce, NONCE);

    let mut out_params = params_for(0);
    assert_eq!(
        unsafe { dhow_manifest_params(verified, &mut out_params) },
        DhowStatus::Ok
    );
    assert_eq!(out_params.payload_size, params.payload_size);
    assert_eq!(out_params.block_count, params.block_count);
    assert_eq!(out_params.symbol_size, params.symbol_size);
    assert_eq!(
        out_params.source_symbols_per_block,
        params.source_symbols_per_block
    );
    assert_eq!(
        out_params.total_symbols_per_block,
        params.total_symbols_per_block
    );
    assert_eq!(out_params.payload_digest, params.payload_digest);

    // Inventory, through the indexed accessors.
    assert_eq!(
        unsafe { dhow_manifest_file_count(verified) },
        files.len() as i32
    );
    for (i, (name, size, digest_byte, executable)) in files.iter().enumerate() {
        let mut needed = 0usize;
        assert_eq!(
            unsafe { dhow_manifest_file_name(verified, i, ptr::null_mut(), 0, &mut needed) },
            DhowStatus::Ok
        );
        let mut buf = vec![0u8; needed];
        assert_eq!(
            unsafe {
                dhow_manifest_file_name(verified, i, buf.as_mut_ptr(), buf.len(), ptr::null_mut())
            },
            DhowStatus::Ok
        );
        assert_eq!(String::from_utf8(buf).unwrap(), *name);

        let mut got_size = 0u64;
        assert_eq!(
            unsafe { dhow_manifest_file_size(verified, i, &mut got_size) },
            DhowStatus::Ok
        );
        assert_eq!(got_size, *size);

        let mut digest = [0u8; 32];
        assert_eq!(
            unsafe { dhow_manifest_file_digest(verified, i, digest.as_mut_ptr()) },
            DhowStatus::Ok
        );
        assert_eq!(digest, [*digest_byte; 32]);

        assert_eq!(
            unsafe { dhow_manifest_file_executable(verified, i) },
            i32::from(*executable),
            "executable bit wrong for {name}"
        );
    }

    unsafe {
        dhow_manifest_free(verified);
        dhow_manifest_free(built);
        dhow_public_free(public);
        dhow_identity_free(identity);
    }
}

#[test]
fn an_empty_inventory_round_trips() {
    // A dataset of no files is a strange thing to send and not a malformed one.
    let identity = dhow_identity_generate();
    let public = unsafe { dhow_identity_public(identity) };

    let built = unsafe {
        dhow_manifest_build(
            identity,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params_for(0),
            ptr::null(),
            0,
        )
    };
    assert!(!built.is_null());

    let mut needed = 0usize;
    unsafe { dhow_manifest_bytes(built, ptr::null_mut(), 0, &mut needed) };
    let mut wire = vec![0u8; needed];
    unsafe { dhow_manifest_bytes(built, wire.as_mut_ptr(), wire.len(), ptr::null_mut()) };

    let verified = unsafe { dhow_manifest_verify(public, wire.as_ptr(), wire.len(), ptr::null()) };
    assert!(!verified.is_null());
    assert_eq!(unsafe { dhow_manifest_file_count(verified) }, 0);

    unsafe {
        dhow_manifest_free(verified);
        dhow_manifest_free(built);
        dhow_public_free(public);
        dhow_identity_free(identity);
    }
}

#[test]
fn a_manifest_signed_by_another_identity_is_rejected() {
    let sender = dhow_identity_generate();
    let stranger = dhow_identity_generate();
    let stranger_public = unsafe { dhow_identity_public(stranger) };
    let (_names, entries) = entry_array(&sample_files());

    let built = unsafe {
        dhow_manifest_build(
            sender,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params_for(4096),
            entries.as_ptr(),
            entries.len(),
        )
    };
    let mut needed = 0usize;
    unsafe { dhow_manifest_bytes(built, ptr::null_mut(), 0, &mut needed) };
    let mut wire = vec![0u8; needed];
    unsafe { dhow_manifest_bytes(built, wire.as_mut_ptr(), wire.len(), ptr::null_mut()) };

    assert!(
        unsafe { dhow_manifest_verify(stranger_public, wire.as_ptr(), wire.len(), ptr::null()) }
            .is_null(),
        "a manifest verified against the wrong identity"
    );

    unsafe {
        dhow_manifest_free(built);
        dhow_public_free(stranger_public);
        dhow_identity_free(stranger);
        dhow_identity_free(sender);
    }
}

#[test]
fn any_altered_byte_fails_verification() {
    let identity = dhow_identity_generate();
    let public = unsafe { dhow_identity_public(identity) };
    let (_names, entries) = entry_array(&sample_files());

    let built = unsafe {
        dhow_manifest_build(
            identity,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params_for(4096),
            entries.as_ptr(),
            entries.len(),
        )
    };
    let mut needed = 0usize;
    unsafe { dhow_manifest_bytes(built, ptr::null_mut(), 0, &mut needed) };
    let mut good = vec![0u8; needed];
    unsafe { dhow_manifest_bytes(built, good.as_mut_ptr(), good.len(), ptr::null_mut()) };

    for offset in 0..good.len() {
        let mut wire = good.clone();
        wire[offset] = wire[offset].wrapping_add(1);
        assert!(
            unsafe { dhow_manifest_verify(public, wire.as_ptr(), wire.len(), ptr::null()) }
                .is_null(),
            "a manifest with byte {offset} altered still verified"
        );
    }

    unsafe {
        dhow_manifest_free(built);
        dhow_public_free(public);
        dhow_identity_free(identity);
    }
}

#[test]
fn session_binding_is_applied_when_asked_for() {
    let identity = dhow_identity_generate();
    let public = unsafe { dhow_identity_public(identity) };
    let (_names, entries) = entry_array(&sample_files());

    let built = unsafe {
        dhow_manifest_build(
            identity,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params_for(4096),
            entries.as_ptr(),
            entries.len(),
        )
    };
    let mut needed = 0usize;
    unsafe { dhow_manifest_bytes(built, ptr::null_mut(), 0, &mut needed) };
    let mut wire = vec![0u8; needed];
    unsafe { dhow_manifest_bytes(built, wire.as_mut_ptr(), wire.len(), ptr::null_mut()) };

    let matching =
        unsafe { dhow_manifest_verify(public, wire.as_ptr(), wire.len(), SESSION.as_ptr()) };
    assert!(!matching.is_null(), "the right session was rejected");

    let other = [0x99u8; 16];
    assert!(
        unsafe { dhow_manifest_verify(public, wire.as_ptr(), wire.len(), other.as_ptr()) }
            .is_null(),
        "a manifest from another session was accepted"
    );

    unsafe {
        dhow_manifest_free(matching);
        dhow_manifest_free(built);
        dhow_public_free(public);
        dhow_identity_free(identity);
    }
}

#[test]
fn indexed_accessors_reject_an_out_of_range_index() {
    let identity = dhow_identity_generate();
    let (_names, entries) = entry_array(&sample_files());
    let built = unsafe {
        dhow_manifest_build(
            identity,
            SESSION.as_ptr(),
            SALT.as_ptr(),
            NONCE.as_ptr(),
            params_for(4096),
            entries.as_ptr(),
            entries.len(),
        )
    };

    let past_the_end = entries.len();
    let mut size = 0u64;
    assert_eq!(
        unsafe { dhow_manifest_file_size(built, past_the_end, &mut size) },
        DhowStatus::InvalidArgument
    );
    let mut digest = [0u8; 32];
    assert_eq!(
        unsafe { dhow_manifest_file_digest(built, past_the_end, digest.as_mut_ptr()) },
        DhowStatus::InvalidArgument
    );
    assert_eq!(
        unsafe {
            dhow_manifest_file_name(built, past_the_end, ptr::null_mut(), 0, ptr::null_mut())
        },
        DhowStatus::InvalidArgument
    );
    assert!(unsafe { dhow_manifest_file_executable(built, past_the_end) } < 0);
    // usize::MAX is the index a caller reaches by passing -1 from C.
    assert!(unsafe { dhow_manifest_file_executable(built, usize::MAX) } < 0);

    unsafe {
        dhow_manifest_free(built);
        dhow_identity_free(identity);
    }
}

#[test]
fn a_reserved_byte_in_a_file_entry_is_rejected() {
    // The reserved bytes exist so the struct's layout survives a future flag.
    // A caller that sets one is either using a newer header than this library
    // or has left the struct uninitialised, and both are worth refusing.
    let identity = dhow_identity_generate();
    let name = CString::new("a.txt").unwrap();
    let entry = DhowFileEntry {
        name: name.as_ptr(),
        size: 1,
        digest: [0; 32],
        executable: 0,
        reserved: [0, 0, 0, 1, 0, 0, 0],
    };
    assert!(
        unsafe {
            dhow_manifest_build(
                identity,
                SESSION.as_ptr(),
                SALT.as_ptr(),
                NONCE.as_ptr(),
                params_for(16),
                &entry,
                1,
            )
        }
        .is_null()
    );
    unsafe { dhow_identity_free(identity) };
}

#[test]
fn manifest_build_rejects_null_arguments() {
    let identity = dhow_identity_generate();
    let (_names, entries) = entry_array(&sample_files());

    // A null identity.
    assert!(
        unsafe {
            dhow_manifest_build(
                ptr::null(),
                SESSION.as_ptr(),
                SALT.as_ptr(),
                NONCE.as_ptr(),
                params_for(16),
                entries.as_ptr(),
                entries.len(),
            )
        }
        .is_null()
    );

    // A null salt.
    assert!(
        unsafe {
            dhow_manifest_build(
                identity,
                SESSION.as_ptr(),
                ptr::null(),
                NONCE.as_ptr(),
                params_for(16),
                entries.as_ptr(),
                entries.len(),
            )
        }
        .is_null()
    );

    // A non-zero count with a null array.
    assert!(
        unsafe {
            dhow_manifest_build(
                identity,
                SESSION.as_ptr(),
                SALT.as_ptr(),
                NONCE.as_ptr(),
                params_for(16),
                ptr::null(),
                3,
            )
        }
        .is_null()
    );

    unsafe { dhow_identity_free(identity) };
}

#[test]
fn a_traversal_name_never_reaches_a_verified_manifest() {
    // Signing something is not the same as it being safe to extract. The name
    // policy applies on the way in as well as on the way out.
    let identity = dhow_identity_generate();
    let name = CString::new("../../etc/passwd").unwrap();
    let entry = DhowFileEntry {
        name: name.as_ptr(),
        size: 1,
        digest: [0; 32],
        executable: 0,
        reserved: [0; 7],
    };
    assert!(
        unsafe {
            dhow_manifest_build(
                identity,
                SESSION.as_ptr(),
                SALT.as_ptr(),
                NONCE.as_ptr(),
                params_for(16),
                &entry,
                1,
            )
        }
        .is_null(),
        "a traversal name was signed"
    );
    unsafe { dhow_identity_free(identity) };
}
