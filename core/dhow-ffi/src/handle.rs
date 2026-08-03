//! Handle-based encoder, decoder, and key API.
//!
//! # Ownership
//!
//! Every `_new` function returns a handle the caller owns and must release with
//! the matching `_free`. Passing null to a `_free` is a no-op, so cleanup paths
//! need no null check. Using a handle after freeing it is undefined behaviour,
//! exactly as with any C API.
//!
//! Buffers are always caller-allocated. This library never hands back a pointer
//! the caller must free, which removes the class of bugs where two allocators
//! disagree about a block of memory. Functions that produce variable-length
//! output follow one convention: call with a null buffer to learn the required
//! size, then call again with a buffer of at least that size.

use crate::error::{DhowStatus, clear_last_error, fail};
use crate::guard::{guard, guard_ptr};
use dhow_codec::blake3::{Blake3Hasher, blake3_digest};
use dhow_codec::pipeline::{Pipeline, PipelineDecoder};
use dhow_codec::qr::{
    Ecc, QrCodeEncoder, capacity as qr_capacity, max_symbol_size as qr_max_symbol_size,
};
use dhow_codec::resume::ResumeFile;
use dhow_codec::session::{RaptorQParams, SessionParams};
use dhow_crypt::aead::{TransferKeys, decrypt_payload, encrypt_payload};
use dhow_crypt::kdf::Salt;
use dhow_crypt::key::{
    IdentityKey, OperatorKey, PublicIdentity, load_identity, load_operator, load_public,
    save_identity, save_operator, save_public,
};
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;

/// Session parameters as they cross the ABI.
///
/// A plain `#[repr(C)]` struct rather than a handle: these are public
/// parameters the caller composes and inspects, and passing them by value
/// avoids a getter for every field.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DhowSessionParams {
    /// Size of the encrypted payload in bytes.
    pub payload_size: u64,
    /// Number of source blocks.
    pub block_count: u32,
    /// Symbol size in bytes.
    pub symbol_size: u32,
    /// Source symbols per block.
    pub source_symbols_per_block: u32,
    /// Total symbols per block, including repair.
    pub total_symbols_per_block: u32,
    /// BLAKE3 digest of the encrypted payload.
    pub payload_digest: [u8; 32],
}

impl DhowSessionParams {
    fn to_session_params(self) -> SessionParams {
        SessionParams {
            payload_size: self.payload_size,
            block_count: self.block_count,
            symbol_size: self.symbol_size,
            source_symbols_per_block: self.source_symbols_per_block,
            total_symbols_per_block: self.total_symbols_per_block,
            // RaptorQ's own parameters are derived from the block layout rather
            // than chosen by the caller, so they are not part of the ABI.
            raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
            payload_digest: self.payload_digest,
        }
    }
}

/// An opaque operator key.
pub struct DhowKey {
    inner: OperatorKey,
}

/// An opaque frame encoder.
pub struct DhowEncoder {
    frames: Vec<Vec<u8>>,
    params: DhowSessionParams,
}

/// An opaque frame decoder.
pub struct DhowDecoder {
    inner: PipelineDecoder,
}

/// Reads a caller-supplied slice, or returns `None` when it is unusable.
///
/// # Safety
///
/// `ptr` must be null, or point to at least `len` readable bytes.
unsafe fn slice_from<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    if len == 0 {
        return Some(&[]);
    }
    // SAFETY: the caller guarantees `len` readable bytes at `ptr`, and the
    // returned slice does not outlive the call it is used in.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Copies `data` into a caller buffer following the two-call size convention.
///
/// # Safety
///
/// `buf` must be null, or point to at least `len` writable bytes.
unsafe fn write_out(data: &[u8], buf: *mut u8, len: usize, written: *mut usize) -> DhowStatus {
    if !written.is_null() {
        // SAFETY: caller guarantees `written` is null or writable.
        unsafe { *written = data.len() };
    }

    if buf.is_null() {
        // Size query.
        return DhowStatus::Ok;
    }

    if len < data.len() {
        return fail(
            DhowStatus::BufferTooSmall,
            format!(
                "buffer of {len} bytes is too small; {} required",
                data.len()
            ),
        );
    }

    // SAFETY: `buf` is non-null with `len >= data.len()` writable bytes, and
    // the regions cannot overlap because `data` is owned by this library.
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len()) };
    DhowStatus::Ok
}

/// Reads a NUL-terminated path from the caller.
///
/// # Safety
///
/// `path` must be null or point to a NUL-terminated C string.
unsafe fn path_from(path: *const c_char) -> Option<PathBuf> {
    if path.is_null() {
        return None;
    }
    // SAFETY: caller guarantees NUL termination.
    let cstr = unsafe { std::ffi::CStr::from_ptr(path) };
    cstr.to_str().ok().map(PathBuf::from)
}

// --- Keys ---

/// Generates a new operator key.
///
/// Returns null on failure; the key material never crosses the boundary.
#[unsafe(no_mangle)]
pub extern "C" fn dhow_key_generate() -> *mut DhowKey {
    guard_ptr(|| {
        clear_last_error();
        match OperatorKey::generate() {
            Ok(inner) => Box::into_raw(Box::new(DhowKey { inner })),
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                std::ptr::null_mut()
            }
        }
    })
}

/// Loads an operator key from a key file.
///
/// Fails if the file is missing, malformed, or readable by anyone but its
/// owner. Returns null on failure.
///
/// # Safety
///
/// `path` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_key_load(path: *const c_char) -> *mut DhowKey {
    guard_ptr(|| {
        clear_last_error();
        // SAFETY: forwarded from this function's own contract.
        let Some(path) = (unsafe { path_from(path) }) else {
            crate::error::set_last_error("key path was null or not valid UTF-8");
            return std::ptr::null_mut();
        };
        match load_operator(&path) {
            Ok(inner) => Box::into_raw(Box::new(DhowKey { inner })),
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                std::ptr::null_mut()
            }
        }
    })
}

/// Writes an operator key to a key file with owner-only permissions.
///
/// # Safety
///
/// `key` must be a live handle and `path` a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_key_save(key: *const DhowKey, path: *const c_char) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if key.is_null() {
            return fail(DhowStatus::NullArgument, "key handle was null");
        }
        // SAFETY: forwarded from this function's own contract.
        let Some(path) = (unsafe { path_from(path) }) else {
            return fail(DhowStatus::NullArgument, "key path was null or not UTF-8");
        };
        // SAFETY: `key` is non-null and the caller guarantees it is live.
        let key = unsafe { &*key };
        match save_operator(&path, &key.inner) {
            Ok(()) => DhowStatus::Ok,
            Err(e) => fail(DhowStatus::KeyFailed, e.to_string()),
        }
    })
}

/// Releases a key handle. Passing null is a no-op.
///
/// # Safety
///
/// `key` must be null or a handle from this library that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_key_free(key: *mut DhowKey) {
    if key.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `key` came from `Box::into_raw` here and
    // has not already been freed. Dropping zeroizes the key material.
    drop(unsafe { Box::from_raw(key) });
}

// --- Encoder ---

/// Encrypts `payload` and builds the full frame stream for a session.
///
/// The encoder holds every frame, so [`dhow_encoder_frame_count`] and
/// [`dhow_encoder_frame`] can serve them in any order and as many times as the
/// sender needs, which is what a repeating display loop requires.
///
/// # Safety
///
/// `key` must be a live handle; `session_id` and `salt` must point to 16 and 32
/// readable bytes; `payload` must point to `payload_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_encoder_new(
    key: *const DhowKey,
    session_id: *const u8,
    salt: *const u8,
    nonce: *const u8,
    params_in: DhowSessionParams,
    payload: *const u8,
    payload_len: usize,
) -> *mut DhowEncoder {
    guard_ptr(|| {
        clear_last_error();
        let params = params_in;

        if key.is_null() {
            crate::error::set_last_error("key handle was null");
            return std::ptr::null_mut();
        }

        // SAFETY: sizes are fixed by the ABI contract documented above.
        let (Some(session_id), Some(salt), Some(nonce), Some(payload)) = (unsafe {
            (
                slice_from(session_id, 16),
                slice_from(salt, 32),
                slice_from(nonce, 24),
                slice_from(payload, payload_len),
            )
        }) else {
            crate::error::set_last_error("a required pointer argument was null");
            return std::ptr::null_mut();
        };

        let mut sid = [0u8; 16];
        sid.copy_from_slice(session_id);
        let mut salt_bytes = [0u8; 32];
        salt_bytes.copy_from_slice(salt);
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes.copy_from_slice(nonce);

        // SAFETY: `key` is non-null and the caller guarantees it is live.
        let key = unsafe { &*key };

        let keys = match TransferKeys::derive(&key.inner, &Salt::from_bytes(salt_bytes)) {
            Ok(k) => k,
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                return std::ptr::null_mut();
            }
        };

        let ciphertext = match encrypt_payload(
            &keys,
            &dhow_crypt::aead::Nonce::from_bytes(nonce_bytes),
            &sid,
            payload,
        ) {
            Ok(c) => c,
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                return std::ptr::null_mut();
            }
        };

        // The caller declares the payload size and digest; both must describe
        // the ciphertext, not the plaintext, since that is what is framed.
        let mut params = params.to_session_params();
        params.payload_size = ciphertext.len() as u64;
        params.payload_digest = blake3_digest(&ciphertext);

        let pipeline = match Pipeline::new(sid, params, *keys.session_key()) {
            Ok(p) => p,
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                return std::ptr::null_mut();
            }
        };

        let mut resolved = params_in;
        resolved.payload_size = params.payload_size;
        resolved.payload_digest = params.payload_digest;

        match pipeline.encode_to_bytes(&ciphertext) {
            Ok(frames) => Box::into_raw(Box::new(DhowEncoder {
                frames,
                params: resolved,
            })),
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                std::ptr::null_mut()
            }
        }
    })
}

/// Returns the session parameters the encoder actually used.
///
/// The caller supplies a payload size and digest describing the *plaintext*,
/// but framing operates on ciphertext, which is longer by the AEAD tag. The
/// encoder recomputes both and reports them here, because these are the values
/// that must travel in the signed manifest for a receiver to configure its
/// decoder. Without this the caller would have to reimplement the length and
/// digest rules to fill in the manifest.
///
/// # Safety
///
/// `encoder` must be a live handle and `out` must point to a writable
/// [`DhowSessionParams`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_encoder_params(
    encoder: *const DhowEncoder,
    out: *mut DhowSessionParams,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if encoder.is_null() || out.is_null() {
            return fail(DhowStatus::NullArgument, "a required pointer was null");
        }
        // SAFETY: both are non-null and the caller guarantees they are valid.
        unsafe {
            *out = (*encoder).params;
        }
        DhowStatus::Ok
    })
}

/// Returns the number of frames the encoder holds, or a negative status.
///
/// # Safety
///
/// `encoder` must be null or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_encoder_frame_count(encoder: *const DhowEncoder) -> c_int {
    if encoder.is_null() {
        return DhowStatus::NullArgument as c_int;
    }
    // SAFETY: `encoder` is non-null and the caller guarantees it is live.
    let encoder = unsafe { &*encoder };
    encoder.frames.len() as c_int
}

/// Copies frame `index` into `buf`.
///
/// Call with a null `buf` to learn the frame's size, which is reported through
/// `written`.
///
/// # Safety
///
/// `encoder` must be a live handle; `buf` must be null or point to `len`
/// writable bytes; `written` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_encoder_frame(
    encoder: *const DhowEncoder,
    index: usize,
    buf: *mut u8,
    len: usize,
    written: *mut usize,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if encoder.is_null() {
            return fail(DhowStatus::NullArgument, "encoder handle was null");
        }
        // SAFETY: `encoder` is non-null and the caller guarantees it is live.
        let encoder = unsafe { &*encoder };

        let Some(frame) = encoder.frames.get(index) else {
            return fail(
                DhowStatus::InvalidArgument,
                format!(
                    "frame index {index} out of range; encoder holds {}",
                    encoder.frames.len()
                ),
            );
        };

        // SAFETY: forwarded from this function's own contract.
        unsafe { write_out(frame, buf, len, written) }
    })
}

/// Releases an encoder handle. Passing null is a no-op.
///
/// # Safety
///
/// `encoder` must be null or a handle from this library that has not been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_encoder_free(encoder: *mut DhowEncoder) {
    if encoder.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `encoder` came from `Box::into_raw` here
    // and has not already been freed.
    drop(unsafe { Box::from_raw(encoder) });
}

// --- Decoder ---

/// Creates a decoder for a session.
///
/// # Safety
///
/// `key` must be a live handle; `session_id` and `salt` must point to 16 and 32
/// readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_decoder_new(
    key: *const DhowKey,
    session_id: *const u8,
    salt: *const u8,
    params: DhowSessionParams,
) -> *mut DhowDecoder {
    guard_ptr(|| {
        clear_last_error();

        if key.is_null() {
            crate::error::set_last_error("key handle was null");
            return std::ptr::null_mut();
        }

        // SAFETY: sizes are fixed by the ABI contract documented above.
        let (Some(session_id), Some(salt)) =
            (unsafe { (slice_from(session_id, 16), slice_from(salt, 32)) })
        else {
            crate::error::set_last_error("a required pointer argument was null");
            return std::ptr::null_mut();
        };

        let mut sid = [0u8; 16];
        sid.copy_from_slice(session_id);
        let mut salt_bytes = [0u8; 32];
        salt_bytes.copy_from_slice(salt);

        // SAFETY: `key` is non-null and the caller guarantees it is live.
        let key = unsafe { &*key };

        let keys = match TransferKeys::derive(&key.inner, &Salt::from_bytes(salt_bytes)) {
            Ok(k) => k,
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                return std::ptr::null_mut();
            }
        };

        match PipelineDecoder::new(sid, params.to_session_params(), *keys.session_key()) {
            Ok(inner) => Box::into_raw(Box::new(DhowDecoder { inner })),
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                std::ptr::null_mut()
            }
        }
    })
}

/// Feeds one captured frame to the decoder.
///
/// A rejected frame returns [`DhowStatus::FrameRejected`] and leaves the
/// decoder unchanged. A receiver watching a screen should keep going rather
/// than treat this as fatal: most rejections are ordinary capture noise.
///
/// # Safety
///
/// `decoder` must be a live handle and `frame` must point to `len` readable
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_decoder_accept(
    decoder: *mut DhowDecoder,
    frame: *const u8,
    len: usize,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if decoder.is_null() {
            return fail(DhowStatus::NullArgument, "decoder handle was null");
        }
        // SAFETY: forwarded from this function's own contract.
        let Some(frame) = (unsafe { slice_from(frame, len) }) else {
            return fail(DhowStatus::NullArgument, "frame pointer was null");
        };
        // SAFETY: `decoder` is non-null and the caller guarantees it is live
        // and not aliased by another thread.
        let decoder = unsafe { &mut *decoder };

        match decoder.inner.accept(frame) {
            Ok(_) => DhowStatus::Ok,
            Err(e) => fail(DhowStatus::FrameRejected, e.to_string()),
        }
    })
}

/// Returns 1 when every block has decoded, 0 when not, or a negative status.
///
/// # Safety
///
/// `decoder` must be null or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_decoder_is_complete(decoder: *const DhowDecoder) -> c_int {
    if decoder.is_null() {
        return DhowStatus::NullArgument as c_int;
    }
    // SAFETY: `decoder` is non-null and the caller guarantees it is live.
    let decoder = unsafe { &*decoder };
    i32::from(decoder.inner.is_complete())
}

/// Returns how many blocks have decoded, or a negative status.
///
/// # Safety
///
/// `decoder` must be null or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_decoder_blocks_complete(decoder: *const DhowDecoder) -> c_int {
    if decoder.is_null() {
        return DhowStatus::NullArgument as c_int;
    }
    // SAFETY: `decoder` is non-null and the caller guarantees it is live.
    let decoder = unsafe { &*decoder };
    decoder.inner.blocks_complete() as c_int
}

/// Reassembles, verifies, and decrypts the payload.
///
/// Returns [`DhowStatus::Incomplete`] while blocks are outstanding, and
/// [`DhowStatus::VerificationFailed`] if the reassembled ciphertext does not
/// match the digest the sender committed to. Plaintext is written only after
/// both the digest and the AEAD tag have been checked.
///
/// Call with a null `buf` to learn the plaintext size.
///
/// # Safety
///
/// `decoder` and `key` must be live handles; `session_id` and `nonce` must
/// point to 16 and 24 readable bytes; `buf` must be null or point to `len`
/// writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_decoder_finish(
    decoder: *const DhowDecoder,
    key: *const DhowKey,
    session_id: *const u8,
    salt: *const u8,
    nonce: *const u8,
    buf: *mut u8,
    len: usize,
    written: *mut usize,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if decoder.is_null() || key.is_null() {
            return fail(DhowStatus::NullArgument, "a required handle was null");
        }

        // SAFETY: sizes are fixed by the ABI contract documented above.
        let (Some(session_id), Some(salt), Some(nonce)) = (unsafe {
            (
                slice_from(session_id, 16),
                slice_from(salt, 32),
                slice_from(nonce, 24),
            )
        }) else {
            return fail(DhowStatus::NullArgument, "a required pointer was null");
        };

        let mut sid = [0u8; 16];
        sid.copy_from_slice(session_id);
        let mut salt_bytes = [0u8; 32];
        salt_bytes.copy_from_slice(salt);
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes.copy_from_slice(nonce);

        // SAFETY: both are non-null and the caller guarantees they are live.
        let (decoder, key) = unsafe { (&*decoder, &*key) };

        if !decoder.inner.is_complete() {
            return fail(
                DhowStatus::Incomplete,
                "transfer is not complete; more frames are needed",
            );
        }

        let ciphertext = match decoder.inner.finish() {
            Ok(c) => c,
            Err(e) => return fail(DhowStatus::VerificationFailed, e.to_string()),
        };

        let keys = match TransferKeys::derive(&key.inner, &Salt::from_bytes(salt_bytes)) {
            Ok(k) => k,
            Err(e) => return fail(DhowStatus::KeyFailed, e.to_string()),
        };

        let plaintext = match decrypt_payload(
            &keys,
            &dhow_crypt::aead::Nonce::from_bytes(nonce_bytes),
            &sid,
            &ciphertext,
        ) {
            Ok(p) => p,
            Err(e) => return fail(DhowStatus::CryptoFailed, e.to_string()),
        };

        // SAFETY: forwarded from this function's own contract.
        unsafe { write_out(&plaintext, buf, len, written) }
    })
}

/// Serializes the decoder's progress as a resume file.
///
/// `journal_bytes` is the length of the caller's journal at this moment. The
/// caller owns the journal, so only it knows how long the file is; the decoder
/// knows only which frames were in it.
///
/// Call with a null `buf` to learn the required size.
///
/// # Safety
///
/// `decoder` must be a live handle; `buf` must be null or point to `len`
/// writable bytes; `written` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_decoder_resume_state(
    decoder: *const DhowDecoder,
    journal_bytes: u64,
    buf: *mut u8,
    len: usize,
    written: *mut usize,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if decoder.is_null() {
            return fail(DhowStatus::NullArgument, "decoder handle was null");
        }
        // SAFETY: `decoder` is non-null and the caller guarantees it is live.
        let decoder = unsafe { &*decoder };

        let state = decoder.inner.resume_state(journal_bytes).to_vec();
        // SAFETY: forwarded from this function's own contract.
        unsafe { write_out(&state, buf, len, written) }
    })
}

/// Reads a resume file's header without needing a decoder.
///
/// A restarting receiver needs the session ID and journal length *before* it
/// can build a decoder and replay: the length says how much of the journal is
/// covered, and the session ID says whether this state belongs to the transfer
/// in hand at all.
///
/// Returns [`DhowStatus::ResumeRejected`] if the file is malformed or fails its
/// integrity checks. Any output pointer may be null if the caller does not
/// want that field.
///
/// # Safety
///
/// `state` must point to `state_len` readable bytes. `session_id_out` must be
/// null or point to 16 writable bytes; the other outputs must be null or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_resume_state_read(
    state: *const u8,
    state_len: usize,
    session_id_out: *mut u8,
    journal_bytes_out: *mut u64,
    block_count_out: *mut u32,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        // SAFETY: forwarded from this function's own contract.
        let Some(state) = (unsafe { slice_from(state, state_len) }) else {
            return fail(DhowStatus::NullArgument, "resume state pointer was null");
        };

        let file = match ResumeFile::from_bytes(state) {
            Ok(f) => f,
            Err(e) => return fail(DhowStatus::ResumeRejected, e.to_string()),
        };

        if !session_id_out.is_null() {
            let session_id = file.session_id();
            // SAFETY: the caller guarantees 16 writable bytes, and the source
            // is a local array that cannot overlap it.
            unsafe {
                std::ptr::copy_nonoverlapping(session_id.as_ptr(), session_id_out, 16);
            }
        }
        if !journal_bytes_out.is_null() {
            // SAFETY: the caller guarantees this is writable.
            unsafe { *journal_bytes_out = file.journal_bytes() };
        }
        if !block_count_out.is_null() {
            // SAFETY: the caller guarantees this is writable.
            unsafe { *block_count_out = file.block_count() };
        }

        DhowStatus::Ok
    })
}

/// Checks a resume file against what this decoder holds after a replay.
///
/// Returns [`DhowStatus::ResumeRejected`] when the state is malformed, belongs
/// to another session, or describes a journal other than the one replayed.
///
/// This is not what keeps forged symbols out: every replayed frame is
/// authenticated against the session key on the way in, and a resume file
/// carries no key. What it catches is a stale, truncated, reordered, or
/// swapped pair of files being mistaken for progress that was really made.
///
/// # Safety
///
/// `decoder` must be a live handle and `state` must point to `state_len`
/// readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_decoder_resume_verify(
    decoder: *const DhowDecoder,
    state: *const u8,
    state_len: usize,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if decoder.is_null() {
            return fail(DhowStatus::NullArgument, "decoder handle was null");
        }
        // SAFETY: forwarded from this function's own contract.
        let Some(state) = (unsafe { slice_from(state, state_len) }) else {
            return fail(DhowStatus::NullArgument, "resume state pointer was null");
        };
        // SAFETY: `decoder` is non-null and the caller guarantees it is live.
        let decoder = unsafe { &*decoder };

        let file = match ResumeFile::from_bytes(state) {
            Ok(f) => f,
            Err(e) => return fail(DhowStatus::ResumeRejected, e.to_string()),
        };

        match decoder.inner.verify_resume(&file) {
            Ok(()) => DhowStatus::Ok,
            Err(e) => fail(DhowStatus::ResumeRejected, e.to_string()),
        }
    })
}

/// Releases a decoder handle. Passing null is a no-op.
///
/// # Safety
///
/// `decoder` must be null or a handle from this library that has not been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_decoder_free(decoder: *mut DhowDecoder) {
    if decoder.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `decoder` came from `Box::into_raw` here
    // and has not already been freed.
    drop(unsafe { Box::from_raw(decoder) });
}

// --- Digests ---

/// Computes the BLAKE3 digest of a byte range.
///
/// Exposed so a caller does not need its own BLAKE3. The digests that decide
/// whether a transfer verified are computed by this library; a second
/// implementation on the calling side would be a second thing to be wrong, and
/// the two would disagree silently rather than loudly.
///
/// `data` must be non-null even for a zero-length input, matching every other
/// buffer argument in this API; a caller hashing nothing passes any valid
/// pointer with a length of zero.
///
/// # Safety
///
/// `data` must point to `len` readable bytes, and `out` must point to 32
/// writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_blake3(data: *const u8, len: usize, out: *mut u8) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if out.is_null() {
            return fail(DhowStatus::NullArgument, "output pointer was null");
        }
        // SAFETY: forwarded from this function's own contract.
        let Some(data) = (unsafe { slice_from(data, len) }) else {
            return fail(DhowStatus::NullArgument, "data pointer was null");
        };

        let digest = blake3_digest(data);
        // SAFETY: the caller guarantees 32 writable bytes at `out`, and the
        // source is a local array that cannot overlap it.
        unsafe { std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32) };
        DhowStatus::Ok
    })
}

/// An opaque streaming BLAKE3 hasher.
pub struct DhowHasher {
    inner: Blake3Hasher,
}

/// Creates a streaming BLAKE3 hasher.
///
/// The one-shot [`dhow_blake3`] needs the whole input in memory at once. A
/// caller hashing a file it is streaming somewhere else - which is what
/// packing a dataset does - would otherwise have to buffer the file only to
/// hash it, turning a bounded working set into one that grows with the largest
/// file in the dataset.
///
/// Returns null on failure.
#[unsafe(no_mangle)]
pub extern "C" fn dhow_hasher_new() -> *mut DhowHasher {
    guard_ptr(|| {
        clear_last_error();
        Box::into_raw(Box::new(DhowHasher {
            inner: Blake3Hasher::new(),
        }))
    })
}

/// Adds bytes to a hasher.
///
/// # Safety
///
/// `hasher` must be a live handle and `data` must point to `len` readable
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_hasher_update(
    hasher: *mut DhowHasher,
    data: *const u8,
    len: usize,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if hasher.is_null() {
            return fail(DhowStatus::NullArgument, "hasher handle was null");
        }
        // SAFETY: forwarded from this function's own contract.
        let Some(data) = (unsafe { slice_from(data, len) }) else {
            return fail(DhowStatus::NullArgument, "data pointer was null");
        };
        // SAFETY: `hasher` is non-null and the caller guarantees it is live
        // and not aliased by another thread.
        let hasher = unsafe { &mut *hasher };

        hasher.inner.update(data);
        DhowStatus::Ok
    })
}

/// Writes the digest of everything added so far.
///
/// The hasher is left usable, so a caller may keep adding and finish again.
///
/// # Safety
///
/// `hasher` must be a live handle and `out` must point to 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_hasher_finish(hasher: *const DhowHasher, out: *mut u8) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if hasher.is_null() {
            return fail(DhowStatus::NullArgument, "hasher handle was null");
        }
        if out.is_null() {
            return fail(DhowStatus::NullArgument, "output pointer was null");
        }
        // SAFETY: `hasher` is non-null and the caller guarantees it is live.
        let hasher = unsafe { &*hasher };

        let digest = hasher.inner.clone().finalize();
        // SAFETY: the caller guarantees 32 writable bytes at `out`, and the
        // source is a local array that cannot overlap it.
        unsafe { std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32) };
        DhowStatus::Ok
    })
}

/// Releases a hasher handle. Passing null is a no-op.
///
/// # Safety
///
/// `hasher` must be null or a handle from this library that has not been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_hasher_free(hasher: *mut DhowHasher) {
    if hasher.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `hasher` came from `Box::into_raw` here
    // and has not already been freed.
    drop(unsafe { Box::from_raw(hasher) });
}

// --- QR encoding ---

/// Reports how many bytes one QR code holds at `version` and `ecc`.
///
/// `ecc` is the ASCII letter `L`, `M`, `Q`, or `H`. Returns a negative status
/// on invalid input.
#[unsafe(no_mangle)]
pub extern "C" fn dhow_qr_capacity(version: u8, ecc: c_char) -> c_int {
    let Some(level) = Ecc::from_letter(ecc as u8 as char) else {
        return DhowStatus::InvalidArgument as c_int;
    };
    match qr_capacity(version, level) {
        Ok(n) => n as c_int,
        Err(_) => DhowStatus::InvalidArgument as c_int,
    }
}

/// Reports the largest codec symbol size that still fits one QR code.
///
/// Returns 0 when the version is too small to hold even a frame header, or a
/// negative status on invalid input. A caller uses this to choose a symbol
/// size the optical layer can actually carry, rather than picking one and
/// discovering at render time that frames do not fit.
#[unsafe(no_mangle)]
pub extern "C" fn dhow_qr_max_symbol_size(version: u8, ecc: c_char) -> c_int {
    let Some(level) = Ecc::from_letter(ecc as u8 as char) else {
        return DhowStatus::InvalidArgument as c_int;
    };
    match qr_max_symbol_size(version, level) {
        Ok(Some(n)) => n as c_int,
        Ok(None) => 0,
        Err(_) => DhowStatus::InvalidArgument as c_int,
    }
}

/// Encodes one frame as a QR code and writes its module grid.
///
/// The grid is one byte per module, row-major, 1 for dark. `size` receives the
/// number of modules per side, so the caller knows the grid is `size * size`
/// bytes.
///
/// Call with a null `buf` to learn the required size. Pass `version` 0 to let
/// the encoder choose the smallest version that fits.
///
/// # Safety
///
/// `frame` must point to `frame_len` readable bytes; `buf` must be null or
/// point to `len` writable bytes; `size` and `written` must be null or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_qr_encode_frame(
    frame: *const u8,
    frame_len: usize,
    version: u8,
    ecc: c_char,
    buf: *mut u8,
    len: usize,
    size: *mut u32,
    written: *mut usize,
) -> DhowStatus {
    guard(|| {
        clear_last_error();

        let Some(level) = Ecc::from_letter(ecc as u8 as char) else {
            return fail(
                DhowStatus::InvalidArgument,
                "error-correction level must be L, M, Q, or H",
            );
        };

        // SAFETY: forwarded from this function's own contract.
        let Some(frame) = (unsafe { slice_from(frame, frame_len) }) else {
            return fail(DhowStatus::NullArgument, "frame pointer was null");
        };

        let encoded = if version == 0 {
            QrCodeEncoder::encode_with(frame, level)
        } else {
            QrCodeEncoder::encode_at(frame, version, level)
        };

        let qr = match encoded {
            Ok(qr) => qr,
            Err(e) => return fail(DhowStatus::InvalidArgument, e.to_string()),
        };

        if !size.is_null() {
            // SAFETY: caller guarantees `size` is null or writable.
            unsafe { *size = qr.size() as u32 };
        }

        let modules = qr.to_modules();
        // SAFETY: forwarded from this function's own contract.
        unsafe { write_out(&modules, buf, len, written) }
    })
}

// --- Identities ---
//
// The operator key encrypts; the identity signs. They are separate handles
// because they are separate secrets with opposite distribution rules: both
// operators hold the same operator key, and only the sender holds the identity
// secret. A signature made with a key the receiver also holds would prove
// nothing the receiver could not have produced itself.

/// An opaque Ed25519 identity keypair.
pub struct DhowIdentity {
    inner: IdentityKey,
}

/// An opaque Ed25519 public identity.
pub struct DhowPublicIdentity {
    inner: PublicIdentity,
}

/// Generates a new identity keypair.
///
/// Returns null on failure; the secret half never crosses the boundary.
#[unsafe(no_mangle)]
pub extern "C" fn dhow_identity_generate() -> *mut DhowIdentity {
    guard_ptr(|| {
        clear_last_error();
        match IdentityKey::generate() {
            Ok(inner) => Box::into_raw(Box::new(DhowIdentity { inner })),
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                std::ptr::null_mut()
            }
        }
    })
}

/// Loads an identity keypair from a key file.
///
/// Fails if the file is missing, malformed, holds an operator key rather than
/// an identity, or is readable by anyone but its owner.
///
/// # Safety
///
/// `path` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_identity_load(path: *const c_char) -> *mut DhowIdentity {
    guard_ptr(|| {
        clear_last_error();
        // SAFETY: forwarded from this function's own contract.
        let Some(path) = (unsafe { path_from(path) }) else {
            crate::error::set_last_error("identity path was null or not valid UTF-8");
            return std::ptr::null_mut();
        };
        match load_identity(&path) {
            Ok(inner) => Box::into_raw(Box::new(DhowIdentity { inner })),
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                std::ptr::null_mut()
            }
        }
    })
}

/// Writes an identity keypair to a key file with owner-only permissions.
///
/// # Safety
///
/// `identity` must be a live handle and `path` a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_identity_save(
    identity: *const DhowIdentity,
    path: *const c_char,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if identity.is_null() {
            return fail(DhowStatus::NullArgument, "identity handle was null");
        }
        // SAFETY: forwarded from this function's own contract.
        let Some(path) = (unsafe { path_from(path) }) else {
            return fail(
                DhowStatus::NullArgument,
                "identity path was null or not UTF-8",
            );
        };
        // SAFETY: `identity` is non-null and the caller guarantees it is live.
        let identity = unsafe { &*identity };
        match save_identity(&path, &identity.inner) {
            Ok(()) => DhowStatus::Ok,
            Err(e) => fail(DhowStatus::KeyFailed, e.to_string()),
        }
    })
}

/// Returns the public half of an identity as a new handle.
///
/// Returns null on failure.
///
/// # Safety
///
/// `identity` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_identity_public(
    identity: *const DhowIdentity,
) -> *mut DhowPublicIdentity {
    guard_ptr(|| {
        clear_last_error();
        if identity.is_null() {
            crate::error::set_last_error("identity handle was null");
            return std::ptr::null_mut();
        }
        // SAFETY: `identity` is non-null and the caller guarantees it is live.
        let identity = unsafe { &*identity };
        Box::into_raw(Box::new(DhowPublicIdentity {
            inner: identity.inner.public(),
        }))
    })
}

/// Releases an identity handle. Passing null is a no-op.
///
/// # Safety
///
/// `identity` must be null or a handle from this library that has not been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_identity_free(identity: *mut DhowIdentity) {
    if identity.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `identity` came from `Box::into_raw` here
    // and has not already been freed. Dropping zeroizes the secret half.
    drop(unsafe { Box::from_raw(identity) });
}

/// Loads a public identity from a 32-byte public key file.
///
/// # Safety
///
/// `path` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_public_load(path: *const c_char) -> *mut DhowPublicIdentity {
    guard_ptr(|| {
        clear_last_error();
        // SAFETY: forwarded from this function's own contract.
        let Some(path) = (unsafe { path_from(path) }) else {
            crate::error::set_last_error("public identity path was null or not valid UTF-8");
            return std::ptr::null_mut();
        };
        match load_public(&path) {
            Ok(inner) => Box::into_raw(Box::new(DhowPublicIdentity { inner })),
            Err(e) => {
                crate::error::set_last_error(e.to_string());
                std::ptr::null_mut()
            }
        }
    })
}

/// Writes a public identity to a file.
///
/// # Safety
///
/// `public` must be a live handle and `path` a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_public_save(
    public: *const DhowPublicIdentity,
    path: *const c_char,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if public.is_null() {
            return fail(DhowStatus::NullArgument, "public identity handle was null");
        }
        // SAFETY: forwarded from this function's own contract.
        let Some(path) = (unsafe { path_from(path) }) else {
            return fail(
                DhowStatus::NullArgument,
                "public identity path was null or not UTF-8",
            );
        };
        // SAFETY: `public` is non-null and the caller guarantees it is live.
        let public = unsafe { &*public };
        match save_public(&path, &public.inner) {
            Ok(()) => DhowStatus::Ok,
            Err(e) => fail(DhowStatus::KeyFailed, e.to_string()),
        }
    })
}

/// Writes the 32-byte encoding of a public identity.
///
/// # Safety
///
/// `public` must be a live handle and `out` must point to 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_public_bytes(
    public: *const DhowPublicIdentity,
    out: *mut u8,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if public.is_null() {
            return fail(DhowStatus::NullArgument, "public identity handle was null");
        }
        if out.is_null() {
            return fail(DhowStatus::NullArgument, "output pointer was null");
        }
        // SAFETY: `public` is non-null and the caller guarantees it is live.
        let public = unsafe { &*public };
        let bytes = public.inner.to_bytes();
        // SAFETY: the caller guarantees 32 writable bytes at `out`, and the
        // source is a local array that cannot overlap it.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 32) };
        DhowStatus::Ok
    })
}

/// Writes the short fingerprint of a public identity, without its NUL.
///
/// Follows the two-call convention: pass a null buffer to learn the length.
/// The fingerprint is for an operator comparing two machines by eye and must
/// not be used as an identifier in any security check.
///
/// # Safety
///
/// `public` must be a live handle; `buf` must be null or point to `len`
/// writable bytes; `written` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_public_fingerprint(
    public: *const DhowPublicIdentity,
    buf: *mut u8,
    len: usize,
    written: *mut usize,
) -> DhowStatus {
    guard(|| {
        clear_last_error();
        if public.is_null() {
            return fail(DhowStatus::NullArgument, "public identity handle was null");
        }
        // SAFETY: `public` is non-null and the caller guarantees it is live.
        let public = unsafe { &*public };
        let text = public.inner.fingerprint();
        // SAFETY: forwarded from this function's own contract.
        unsafe { write_out(text.as_bytes(), buf, len, written) }
    })
}

/// Releases a public identity handle. Passing null is a no-op.
///
/// # Safety
///
/// `public` must be null or a handle from this library that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_public_free(public: *mut DhowPublicIdentity) {
    if public.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `public` came from `Box::into_raw` here and
    // has not already been freed.
    drop(unsafe { Box::from_raw(public) });
}
