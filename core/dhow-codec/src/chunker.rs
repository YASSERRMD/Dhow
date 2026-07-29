//! Deterministic payload chunking into source blocks and symbols.
//!
//! This module implements the chunking algorithm described in `proto/block.md`:
//!
//! - The payload is divided into `B` blocks. The first `S mod B` blocks have
//!   `ceil(S / B)` bytes; the remaining blocks have `floor(S / B)` bytes.
//! - Each block is divided into symbols of fixed size `N`. The last symbol of
//!   a block is zero-padded to `N` bytes if the block size is not a multiple of `N`.
//!
//! All operations are deterministic: given the same input parameters, the same
//! chunk layout is always produced.

/// Maximum payload size: 4 GiB.
pub const MAX_PAYLOAD_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Minimum symbol size in bytes.
pub const MIN_SYMBOL_SIZE: u32 = 1;

/// Maximum symbol size in bytes (limited by the frame payload length field, u16).
pub const MAX_SYMBOL_SIZE: u32 = 65535;

/// Minimum block count.
pub const MIN_BLOCK_COUNT: u32 = 1;

/// Maximum block count.
pub const MAX_BLOCK_COUNT: u32 = 1024;
