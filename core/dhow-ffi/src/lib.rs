//! dhow-ffi: C ABI surface over dhow-codec and dhow-crypt.
//!
//! This crate exposes a handle-based C API. `unsafe` is permitted only at the
//! ABI boundary, and every `unsafe` block carries a `// SAFETY:` comment.

#![allow(unsafe_code)]
