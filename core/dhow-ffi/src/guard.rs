//! Panic containment at the ABI boundary.
//!
//! Unwinding out of an `extern "C"` function is undefined behaviour. Every
//! entry point therefore runs its body inside [`guard`], which catches any
//! panic and converts it to [`DhowStatus::Panic`].
//!
//! This is a backstop, not a strategy. The core crates are written to be
//! panic-free on arbitrary input, and a caught panic is a bug in this library
//! rather than a condition a caller is expected to handle. The guard exists so
//! that such a bug is a diagnosable error code instead of undefined behaviour
//! in the calling process.
//!
//! The panic message is deliberately not forwarded to the caller. A panic
//! payload can contain arbitrary interpolated values, including bytes from the
//! data path, and the whole point of the error channel is that its contents are
//! safe to log.

use crate::error::{DhowStatus, set_last_error};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Runs `body`, converting a panic into [`DhowStatus::Panic`].
pub(crate) fn guard<F>(body: F) -> DhowStatus
where
    F: FnOnce() -> DhowStatus,
{
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(status) => status,
        Err(_) => {
            set_last_error(
                "internal error: a panic was caught at the ABI boundary; this is a bug in dhow",
            );
            DhowStatus::Panic
        }
    }
}

/// Runs `body`, converting a panic into a null pointer.
///
/// Used by constructors, which return a handle rather than a status.
pub(crate) fn guard_ptr<F, T>(body: F) -> *mut T
where
    F: FnOnce() -> *mut T,
{
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(ptr) => ptr,
        Err(_) => {
            set_last_error(
                "internal error: a panic was caught at the ABI boundary; this is a bug in dhow",
            );
            std::ptr::null_mut()
        }
    }
}

/// Runs `body`, swallowing a panic, for entry points that return nothing.
///
/// The `*_free` functions have no channel to report through: their signature
/// returns `()` and a caller has no handle left to ask about. That does not
/// make an unwind across the boundary any less undefined, and a `Drop` impl is
/// exactly the place a panic appears without anyone having written one - a
/// future zeroizing or file-closing drop that asserts something is one line
/// away at any time.
pub(crate) fn guard_unit<F>(body: F)
where
    F: FnOnce(),
{
    if catch_unwind(AssertUnwindSafe(body)).is_err() {
        set_last_error(
            "internal error: a panic was caught at the ABI boundary; this is a bug in dhow",
        );
    }
}

/// Runs `body`, converting a panic into a negative status.
///
/// Used by the entry points that return a count or a capacity as a `c_int`,
/// where a negative value is already the error channel.
pub(crate) fn guard_int<F>(body: F) -> std::os::raw::c_int
where
    F: FnOnce() -> std::os::raw::c_int,
{
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => {
            set_last_error(
                "internal error: a panic was caught at the ABI boundary; this is a bug in dhow",
            );
            DhowStatus::Panic as std::os::raw::c_int
        }
    }
}
