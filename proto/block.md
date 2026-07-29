# Block and Symbol Structure (v1)

> Version 1.0

This document describes how the encrypted payload is divided into source blocks
and symbols, and how repair symbols are generated.

## Payload Chunking

The encrypted payload is divided into source blocks. Each source block is
divided into symbols of fixed size.

### Parameters

| Parameter | Symbol | Description |
|-----------|--------|-------------|
| S | Payload Size | Total size of the encrypted payload |
| B | Block Count | Number of source blocks |
| N | Symbol Size | Size of each symbol in bytes |
| K | Source Symbols Per Block | Number of source symbols per block |

### Block Division

The payload is divided into `B` blocks. The first `S mod B` blocks have
`ceil(S / B)` bytes; the remaining blocks have `floor(S / B)` bytes.

If a block's size is not a multiple of `N`, the last symbol is padded with
zero bytes to reach `N` bytes.

### Symbol Division

Each block of size `M` bytes is divided into `ceil(M / N)` symbols. The last
symbol is zero-padded to `N` bytes if `M` is not a multiple of `N`.

### Example

For a payload of 1000 bytes, block count 2, symbol size 256:

- Block 0: 500 bytes -> 2 symbols (256 + 244 padded to 256)
- Block 1: 500 bytes -> 2 symbols (256 + 244 padded to 256)

## RaptorQ Encoding

RaptorQ encoding is applied per block. For each block:

1. The source symbols are the symbols from step 2 above.
2. Repair symbols are generated using the `raptorq` crate.
3. The total number of symbols per block is `K + overhead`, where `overhead`
   is the number of repair symbols.

### Deterministic Ordering

Repair symbols are generated in a deterministic order. Given the same input
symbols and parameters, the same repair symbols are produced. This is guaranteed
by the `raptorq` crate's deterministic encoding.

## Frame Mapping

Each symbol (source or repair) is carried in a frame:

- **Block Index**: The index of the source block (0-based)
- **Symbol Index**: The index of the symbol within the block (0-based for
  source symbols, K-based for repair symbols)

## Padding

Padding bytes are zero. The original payload size is recorded in the session
header, so the receiver knows how many padding bytes to strip after reassembly.
