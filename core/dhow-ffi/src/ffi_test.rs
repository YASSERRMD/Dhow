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
    for code in -11..=0 {
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
