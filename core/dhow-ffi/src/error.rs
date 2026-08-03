//! Error codes and the last-error message channel.
//!
//! Rust errors cannot cross a C ABI as types, so every entry point returns a
//! [`DhowStatus`] code and stashes a human-readable description that the caller
//! can retrieve with [`dhow_last_error_message`].
//!
//! # Message hygiene
//!
//! The stored message is derived from a `Display` implementation in
//! `dhow-codec` or `dhow-crypt`. Those crates are written so their errors never
//! interpolate payload bytes or key material, which is what makes it safe to
//! hand the text to a caller that may log it. Nothing here should ever be given
//! a string built from plaintext.
//!
//! # Threading
//!
//! The message is thread-local. Two threads calling into the library
//! concurrently each see their own last error, so one thread's failure cannot
//! overwrite the description another thread is about to read.

use std::cell::RefCell;
use std::os::raw::{c_char, c_int};

/// Status returned by every `dhow_*` entry point.
///
/// `Ok` is zero and every failure is negative, so callers can test `< 0`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhowStatus {
    /// The call succeeded.
    Ok = 0,
    /// A required pointer argument was null.
    NullArgument = -1,
    /// An argument was outside its permitted range.
    InvalidArgument = -2,
    /// A supplied buffer was too small; no bytes were written.
    BufferTooSmall = -3,
    /// The session parameters were rejected.
    InvalidParameters = -4,
    /// A frame failed parsing, authentication, or its integrity checks.
    FrameRejected = -5,
    /// The decoder does not yet hold enough symbols.
    Incomplete = -6,
    /// A digest, MAC, or signature check failed.
    VerificationFailed = -7,
    /// Encryption or decryption failed.
    CryptoFailed = -8,
    /// Key generation, loading, or storage failed.
    KeyFailed = -9,
    /// An internal error occurred.
    Internal = -10,
    /// A panic was caught at the ABI boundary. Always a bug in this library.
    Panic = -11,
    /// A resume state was malformed, or did not describe the journal replayed
    /// against it.
    ///
    /// Distinct from [`DhowStatus::VerificationFailed`] because the two mean
    /// opposite things to an operator: a failed verification says the transfer
    /// is bad, while a rejected resume says only that the saved progress is
    /// unusable and the transfer can be restarted.
    ResumeRejected = -12,
}

thread_local! {
    /// Description of the most recent failure on this thread.
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Records a failure description for the current thread.
pub(crate) fn set_last_error(message: impl Into<String>) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = message.into();
    });
}

/// Clears the current thread's stored description.
pub(crate) fn clear_last_error() {
    LAST_ERROR.with(|slot| slot.borrow_mut().clear());
}

/// Records `message` and returns `status`, so callers can `return fail(..)`.
pub(crate) fn fail(status: DhowStatus, message: impl Into<String>) -> DhowStatus {
    set_last_error(message);
    status
}

/// Copies the current thread's last error message into `buf` as a
/// NUL-terminated C string.
///
/// Returns the number of bytes written including the terminator, or a negative
/// [`DhowStatus`] on failure. Pass a null `buf` to query the required size,
/// which is returned as a positive count.
///
/// # Safety
///
/// `buf` must either be null or point to at least `len` writable bytes. The
/// caller owns the buffer; this function never allocates on the caller's
/// behalf and never retains the pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dhow_last_error_message(buf: *mut c_char, len: usize) -> c_int {
    LAST_ERROR.with(|slot| {
        let message = slot.borrow();
        let bytes = message.as_bytes();
        let needed = bytes.len() + 1;

        if buf.is_null() {
            return needed as c_int;
        }

        if len < needed {
            return DhowStatus::BufferTooSmall as c_int;
        }

        // SAFETY: `buf` is non-null and the caller promises `len` writable
        // bytes; `needed <= len` was just checked, and the source and
        // destination cannot overlap because the source is thread-local
        // storage owned by this library.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, bytes.len());
            *buf.add(bytes.len()) = 0;
        }

        needed as c_int
    })
}

/// Returns a static, NUL-terminated description of a status code.
///
/// The returned pointer is valid for the lifetime of the process and must not
/// be freed by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn dhow_status_string(status: c_int) -> *const c_char {
    let text: &'static str = match status {
        0 => "ok\0",
        -1 => "null argument\0",
        -2 => "invalid argument\0",
        -3 => "buffer too small\0",
        -4 => "invalid session parameters\0",
        -5 => "frame rejected\0",
        -6 => "incomplete\0",
        -7 => "verification failed\0",
        -8 => "crypto operation failed\0",
        -9 => "key operation failed\0",
        -10 => "internal error\0",
        -11 => "panic caught at ABI boundary\0",
        -12 => "resume state rejected\0",
        _ => "unknown status\0",
    };
    text.as_ptr() as *const c_char
}
