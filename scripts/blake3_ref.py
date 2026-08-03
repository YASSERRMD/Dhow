#!/usr/bin/env python3
"""Pure-Python BLAKE3, following the reference implementation in the spec.

Why this exists: the golden vectors in ``proto/vectors.json`` are meant to be a
*second* implementation of Dhow's wire formats, written from the spec, so that
a bug in the Rust core shows up as a disagreement rather than as two copies of
the same mistake. A digest computed by calling into the Rust core would defeat
that, and there is no BLAKE3 in the standard library.

Speed is irrelevant here: this hashes a few hundred bytes at vector-generation
time, not payloads.

Run this file directly to check it against the published test vectors.
"""

OUT_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3

IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]


def _mask32(x: int) -> int:
    return x & 0xFFFFFFFF


def _add32(x: int, y: int) -> int:
    return _mask32(x + y)


def _rotr32(x: int, n: int) -> int:
    return _mask32(x << (32 - n)) | (x >> n)


def _g(state, a, b, c, d, mx, my):
    state[a] = _add32(state[a], _add32(state[b], mx))
    state[d] = _rotr32(state[d] ^ state[a], 16)
    state[c] = _add32(state[c], state[d])
    state[b] = _rotr32(state[b] ^ state[c], 12)
    state[a] = _add32(state[a], _add32(state[b], my))
    state[d] = _rotr32(state[d] ^ state[a], 8)
    state[c] = _add32(state[c], state[d])
    state[b] = _rotr32(state[b] ^ state[c], 7)


def _round(state, m):
    # Columns.
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    # Diagonals.
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def _permute(m):
    return [m[i] for i in MSG_PERMUTATION]


def _compress(chaining_value, block_words, counter, block_len, flags):
    state = [
        *chaining_value,
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        _mask32(counter),
        _mask32(counter >> 32),
        block_len,
        flags,
    ]
    block = list(block_words)

    for _ in range(6):
        _round(state, block)
        block = _permute(block)
    _round(state, block)

    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= chaining_value[i]
    return state


def _words_from_block(block: bytes):
    padded = block + b"\x00" * (BLOCK_LEN - len(block))
    return [int.from_bytes(padded[i : i + 4], "little") for i in range(0, BLOCK_LEN, 4)]


def _chunk_chaining_value(chunk: bytes, chunk_counter: int, flags: int):
    """Compresses one chunk (at most CHUNK_LEN bytes) to its chaining value."""
    cv = list(IV)
    blocks = [chunk[i : i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)] or [b""]

    for index, block in enumerate(blocks):
        block_flags = flags
        if index == 0:
            block_flags |= CHUNK_START
        if index == len(blocks) - 1:
            block_flags |= CHUNK_END
        cv = _compress(cv, _words_from_block(block), chunk_counter, len(block), block_flags)[:8]

    return cv


def _parent_output(left_cv, right_cv, flags):
    return _compress(list(IV), left_cv + right_cv, 0, BLOCK_LEN, PARENT | flags)


def blake3(data: bytes, out_len: int = OUT_LEN) -> bytes:
    """Returns the BLAKE3 hash of ``data``."""
    if out_len > OUT_LEN:
        raise ValueError("extended output is not needed here and is not implemented")

    chunks = [data[i : i + CHUNK_LEN] for i in range(0, len(data), CHUNK_LEN)] or [b""]

    # A single chunk is its own root: the last compression carries ROOT rather
    # than feeding a parent node.
    if len(chunks) == 1:
        cv = list(IV)
        blocks = [chunks[0][i : i + BLOCK_LEN] for i in range(0, len(chunks[0]), BLOCK_LEN)] or [
            b""
        ]
        for index, block in enumerate(blocks):
            flags = 0
            if index == 0:
                flags |= CHUNK_START
            if index == len(blocks) - 1:
                flags |= CHUNK_END | ROOT
            state = _compress(cv, _words_from_block(block), 0, len(block), flags)
            cv = state[:8]
        return b"".join(w.to_bytes(4, "little") for w in state[:8])[:out_len]

    # Otherwise build the binary tree left to right, merging whenever the count
    # of completed chunks makes a subtree whole. The final chunk is never
    # pushed: it stays as the running right-hand value and is merged down the
    # stack, so the last merge is the one that carries ROOT.
    stack = []
    for counter, chunk in enumerate(chunks[:-1]):
        cv = _chunk_chaining_value(chunk, counter, 0)
        total = counter + 1
        while total & 1 == 0:
            cv = _parent_output(stack.pop(), cv, 0)[:8]
            total >>= 1
        stack.append(cv)

    right = _chunk_chaining_value(chunks[-1], len(chunks) - 1, 0)
    while len(stack) > 1:
        right = _parent_output(stack.pop(), right, 0)[:8]
    state = _parent_output(stack.pop(), right, ROOT)
    return b"".join(w.to_bytes(4, "little") for w in state[:8])[:out_len]


# Published BLAKE3 test vectors: input is the repeating byte pattern
# 0, 1, ..., 250, 0, 1, ... of the given length.
_KNOWN_ANSWERS = {
    0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    1: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    2: "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
    63: "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
    64: "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
    65: "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
    1023: "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
    1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
    1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
    2048: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
    3072: "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
}


def _pattern(length: int) -> bytes:
    return bytes(i % 251 for i in range(length))


def _self_test() -> int:
    failures = 0
    for length, expected in sorted(_KNOWN_ANSWERS.items()):
        got = blake3(_pattern(length)).hex()
        status = "PASS" if got == expected else "FAIL"
        if got != expected:
            failures += 1
            print(f"  {status} len={length}\n    expected {expected}\n    got      {got}")
        else:
            print(f"  {status} len={length}")
    return failures


if __name__ == "__main__":
    import sys

    print("=== BLAKE3 reference self-test ===")
    sys.exit(1 if _self_test() else 0)
