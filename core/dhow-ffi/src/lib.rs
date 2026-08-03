//! dhow-ffi: C ABI surface over `dhow-codec` and `dhow-crypt`.
//!
//! Go owns the CLI, the screen, and the camera; Rust owns everything whose
//! correctness matters. This crate is the seam between them.
//!
//! # Shape of the API
//!
//! The surface is handle-based. A caller creates an encoder, decoder, or key
//! handle, passes it back on each call, and destroys it when finished. Handles
//! are opaque: the C header declares them as incomplete struct types, so the
//! layout of anything behind the boundary cannot be depended upon.
//!
//! Every function returns a [`DhowStatus`] code, or a handle that is null on
//! failure. A description of the most recent failure is available from
//! [`dhow_last_error_message`].
//!
//! # Key material
//!
//! No function takes or returns a raw secret key. Operator keys live behind
//! [`DhowKey`] handles, and the only way to obtain one is to generate it or
//! load it from a key file. The derived session key never leaves Rust at all:
//! [`dhow_encoder_new`] takes a key handle and a salt, and derives internally.
//!
//! # Safety
//!
//! `unsafe` appears only where the ABI requires it: dereferencing caller
//! pointers and writing into caller buffers. Every `unsafe` block states the
//! precondition it relies on. Every entry point runs inside a panic guard,
//! because unwinding across the ABI is undefined behaviour.

#![allow(unsafe_code)]

pub mod error;
#[cfg(test)]
mod ffi_test;
mod guard;
pub mod handle;

pub use error::{DhowStatus, dhow_last_error_message, dhow_status_string};
pub use handle::*;

use std::os::raw::c_char;

/// ABI version of this library.
///
/// Bumped whenever the C surface changes in a way that is not backwards
/// compatible. A caller that links against a mismatched version should refuse
/// to run rather than guess.
pub const DHOW_ABI_VERSION: u32 = 4;

/// Returns the ABI version this library was built with.
#[unsafe(no_mangle)]
pub extern "C" fn dhow_abi_version() -> u32 {
    DHOW_ABI_VERSION
}

/// Returns the crate version as a static NUL-terminated string.
///
/// The pointer is valid for the lifetime of the process and must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn dhow_version_string() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}
