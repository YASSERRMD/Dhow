//! dhow-codec: fountain coding (RaptorQ), chunking, and framing for Dhow.
//!
//! This crate owns the correctness-critical encoding and decoding logic.
//! It is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

fn deliberate_lint_error() {
    let x = 1;
}
