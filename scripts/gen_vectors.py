#!/usr/bin/env python3
"""
Golden vector generator for Dhow wire formats.

Generates deterministic test vectors for:
- Frame header
- Session header
- Manifest header
- Resume file header

Vectors are deterministic: the same input always produces the same output.
No randomness is used except for the session ID, which is a fixed test value.
"""

import struct
import json
import sys
import os

from blake3_ref import blake3 as blake3_ref

# Fixed test session ID (16 bytes)
TEST_SESSION_ID = bytes(range(16))  # 0x000102030405060708090a0b0c0d0e0f

# Fixed test payload digest (32 bytes of 0xAA)
TEST_PAYLOAD_DIGEST = bytes([0xAA] * 32)

# Fixed test signature (64 bytes of 0xBB)
TEST_SIGNATURE = bytes([0xBB] * 64)

# Fixed test integrity digest (32 bytes of 0xCC)
TEST_INTEGRITY_DIGEST = bytes([0xCC] * 32)


def crc32c(data: bytes) -> int:
    """Compute CRC32C (Castagnoli) checksum."""
    # CRC32C polynomial: 0x82F63B78 (reversed)
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def blake3(data: bytes) -> bytes:
    """Compute BLAKE3 digest (32 bytes)."""
    return blake3_ref(data)


def generate_frame_header_vector() -> dict:
    """Generate a golden vector for a frame header."""
    magic = b"DHOW"
    version = 0x01
    frame_type = 0x01  # Repair symbol
    reserved = 0x0000
    session_id = TEST_SESSION_ID
    truncated_mac = bytes(range(8))  # 0x0001020304050607
    block_index = 0x00000001
    symbol_index = 0x00000002
    payload_length = 0x00FF
    payload = bytes(range(255))  # 255 bytes of test data

    # Compute CRC32C over payload
    crc = crc32c(payload)

    # Build header
    header = (
        magic
        + struct.pack("<B", version)
        + struct.pack("<B", frame_type)
        + struct.pack("<H", reserved)
        + session_id
        + truncated_mac
        + struct.pack("<I", block_index)
        + struct.pack("<I", symbol_index)
        + struct.pack("<H", payload_length)
        + struct.pack("<I", crc)
    )

    return {
        "name": "frame_header_v1",
        "description": "Golden vector for frame header v1",
        "inputs": {
            "magic": "DHOW",
            "version": 1,
            "frame_type": 1,
            "reserved": 0,
            "session_id": session_id.hex(),
            "truncated_mac": truncated_mac.hex(),
            "block_index": block_index,
            "symbol_index": symbol_index,
            "payload_length": payload_length,
            "payload": payload.hex(),
        },
        "outputs": {
            "header_hex": header.hex(),
            "header_size": len(header),
            "crc32c": crc,
        },
    }


def generate_session_header_vector() -> dict:
    """Generate a golden vector for a session header."""
    magic = b"DSES"
    version = 0x01
    reserved = b"\x00\x00\x00"
    session_id = TEST_SESSION_ID
    payload_size = 0x00001000  # 4096 bytes
    block_count = 0x00000004
    symbol_size = 0x00000100  # 256 bytes
    source_symbols_per_block = 0x00000010  # 16
    total_symbols_per_block = 0x00000014  # 20 (16 source + 4 repair)
    raptorq_z = 0x00000004
    raptorq_n = 0x00000001
    raptorq_psi = 0x0010
    payload_digest = TEST_PAYLOAD_DIGEST
    reserved2 = b"\x00" * 32

    # Build header (without CRC)
    header_no_crc = (
        magic
        + struct.pack("<B", version)
        + reserved
        + session_id
        + struct.pack("<Q", payload_size)
        + struct.pack("<I", block_count)
        + struct.pack("<I", symbol_size)
        + struct.pack("<I", source_symbols_per_block)
        + struct.pack("<I", total_symbols_per_block)
        + struct.pack("<I", raptorq_z)
        + struct.pack("<I", raptorq_n)
        + struct.pack("<H", raptorq_psi)
        + payload_digest
        + reserved2
    )

    crc = crc32c(header_no_crc)
    header = header_no_crc + struct.pack("<I", crc)

    return {
        "name": "session_header_v1",
        "description": "Golden vector for session header v1",
        "inputs": {
            "magic": "DSES",
            "version": 1,
            "reserved": 0,
            "session_id": session_id.hex(),
            "payload_size": payload_size,
            "block_count": block_count,
            "symbol_size": symbol_size,
            "source_symbols_per_block": source_symbols_per_block,
            "total_symbols_per_block": total_symbols_per_block,
            "raptorq_z": raptorq_z,
            "raptorq_n": raptorq_n,
            "raptorq_psi": raptorq_psi,
            "payload_digest": payload_digest.hex(),
            "reserved2": reserved2.hex(),
        },
        "outputs": {
            "header_hex": header.hex(),
            "header_size": len(header),
            "crc32c": crc,
        },
    }


# Session material carried in a v2 manifest. Fixed values, so the vector is
# reproducible; none of them is secret.
MANIFEST_SALT = bytes(range(0x40, 0x60))
MANIFEST_NONCE = bytes(range(0x80, 0x98))
MANIFEST_PAYLOAD_SIZE = 0x0000000000010000
MANIFEST_BLOCK_COUNT = 0x00000004
MANIFEST_SYMBOL_SIZE = 0x00000100
MANIFEST_SOURCE_SYMBOLS = 0x00000040
MANIFEST_TOTAL_SYMBOLS = 0x00000060
MANIFEST_RQ_Z = 0x00000001
MANIFEST_RQ_N = 0x00000001
MANIFEST_RQ_PSI = 0x0001


def manifest_header_no_crc(file_count: int, total_size: int) -> bytes:
    """Build a v2 manifest header up to but not including the CRC field.

    Shared by the header vector and the full-manifest vector, because two
    copies of a 160-byte layout drift and the drift is invisible until a
    conformance run on someone else's implementation fails.
    """
    return (
        b"DHMF"
        + struct.pack("<B", 0x02)
        + b"\x00\x00\x00"
        + TEST_SESSION_ID
        + struct.pack("<I", file_count)
        + struct.pack("<Q", total_size)
        + TEST_PAYLOAD_DIGEST
        + MANIFEST_SALT
        + MANIFEST_NONCE
        + struct.pack("<Q", MANIFEST_PAYLOAD_SIZE)
        + struct.pack("<I", MANIFEST_BLOCK_COUNT)
        + struct.pack("<I", MANIFEST_SYMBOL_SIZE)
        + struct.pack("<I", MANIFEST_SOURCE_SYMBOLS)
        + struct.pack("<I", MANIFEST_TOTAL_SYMBOLS)
        + struct.pack("<I", MANIFEST_RQ_Z)
        + struct.pack("<I", MANIFEST_RQ_N)
        + struct.pack("<H", MANIFEST_RQ_PSI)
        + b"\x00\x00"
    )


def manifest_file_entry(name: bytes, size: int, digest: bytes, executable: bool) -> bytes:
    """Build a v2 manifest file entry."""
    return (
        struct.pack("<H", len(name))
        + name
        + struct.pack("<Q", size)
        + digest
        + struct.pack("<B", 1 if executable else 0)
    )


def generate_manifest_header_vector() -> dict:
    """Generate a golden vector for a manifest header."""
    file_count = 0x00000002
    total_size = 0x00002000  # 8192 bytes

    header_no_crc = manifest_header_no_crc(file_count, total_size)
    crc = crc32c(header_no_crc)
    signature = TEST_SIGNATURE
    header = header_no_crc + struct.pack("<I", crc) + signature

    return {
        "name": "manifest_header_v2",
        "description": "Golden vector for manifest header v2",
        "inputs": {
            "magic": "DHMF",
            "version": 2,
            "reserved": 0,
            "session_id": TEST_SESSION_ID.hex(),
            "file_count": file_count,
            "total_size": total_size,
            "payload_digest": TEST_PAYLOAD_DIGEST.hex(),
            "salt": MANIFEST_SALT.hex(),
            "nonce": MANIFEST_NONCE.hex(),
            "payload_size": MANIFEST_PAYLOAD_SIZE,
            "block_count": MANIFEST_BLOCK_COUNT,
            "symbol_size": MANIFEST_SYMBOL_SIZE,
            "source_symbols_per_block": MANIFEST_SOURCE_SYMBOLS,
            "total_symbols_per_block": MANIFEST_TOTAL_SYMBOLS,
            "raptorq_z": MANIFEST_RQ_Z,
            "raptorq_n": MANIFEST_RQ_N,
            "raptorq_psi": MANIFEST_RQ_PSI,
            "signature": signature.hex(),
        },
        "outputs": {
            "header_hex": header.hex(),
            "header_size": len(header),
            "crc32c": crc,
        },
    }


def generate_resume_header_vector() -> dict:
    """Generate a golden vector for a resume file header."""
    magic = b"DHRS"
    version = 0x02
    reserved = b"\x00\x00\x00"
    session_id = TEST_SESSION_ID
    block_count = 0x00000004
    journal_bytes = 0x0000000000002710  # 10000
    journal_digest = blake3(b"dhow resume journal vector")
    reserved2 = b"\x00" * 24

    # Build the header up to but not including the CRC.
    header_no_crc = (
        magic
        + struct.pack("<B", version)
        + reserved
        + session_id
        + struct.pack("<I", block_count)
        + struct.pack("<Q", journal_bytes)
        + journal_digest
        + reserved2
    )
    assert len(header_no_crc) == 92, len(header_no_crc)

    crc = crc32c(header_no_crc)
    integrity_digest = blake3(header_no_crc + struct.pack("<I", crc))
    header = header_no_crc + struct.pack("<I", crc) + integrity_digest

    return {
        "name": "resume_header_v2",
        "description": "Golden vector for resume file header v2",
        "inputs": {
            "magic": "DHRS",
            "version": 2,
            "reserved": 0,
            "session_id": session_id.hex(),
            "block_count": block_count,
            "journal_bytes": journal_bytes,
            "journal_digest": journal_digest.hex(),
            "reserved2": reserved2.hex(),
        },
        "outputs": {
            "header_hex": header.hex(),
            "header_size": len(header),
            "crc32c": crc,
            "integrity_digest": integrity_digest.hex(),
        },
    }


def generate_file_entry_vector() -> dict:
    """Generate a golden vector for a manifest file entry."""
    name = b"test/file.txt"
    name_length = len(name)
    file_size = 0x0000000000000100  # 256 bytes
    file_digest = TEST_PAYLOAD_DIGEST
    executable = True

    entry = manifest_file_entry(name, file_size, file_digest, executable)

    return {
        "name": "manifest_file_entry_v2",
        "description": "Golden vector for manifest file entry v2",
        "inputs": {
            "name": name.decode("utf-8"),
            "name_length": name_length,
            "file_size": file_size,
            "file_digest": file_digest.hex(),
            "flags": 1,
            "executable": executable,
        },
        "outputs": {
            "entry_hex": entry.hex(),
            "entry_size": len(entry),
        },
    }


def generate_block_entry_vector() -> dict:
    """Generate a golden vector for a resume block entry."""
    block_index = 0x00000001
    symbol_count = 0x00000014  # 20 symbols, so ceil(20/8) = 3 bitmap bytes
    held = list(range(16))

    bitmap = bytearray((symbol_count + 7) // 8)
    for symbol in held:
        bitmap[symbol // 8] |= 1 << (symbol % 8)
    bitmap_bytes = bytes(bitmap)

    entry = (
        struct.pack("<I", block_index)
        + struct.pack("<I", symbol_count)
        + struct.pack("<I", len(held))
        + bitmap_bytes
    )

    return {
        "name": "resume_block_entry_v2",
        "description": "Golden vector for resume block entry v2",
        "inputs": {
            "block_index": block_index,
            "symbol_count": symbol_count,
            "symbols_held": len(held),
            "bitmap": bitmap_bytes.hex(),
        },
        "outputs": {
            "entry_hex": entry.hex(),
            "entry_size": len(entry),
        },
    }


def generate_full_manifest_vector() -> dict:
    """Generate a golden vector for a full manifest with file entries."""
    file_count = 0x00000002
    total_size = 0x00002000  # 8192 bytes

    header_no_crc = manifest_header_no_crc(file_count, total_size)
    crc = crc32c(header_no_crc)
    signature = TEST_SIGNATURE

    # One entry of each flag value, so a reader that ignores the flag byte or
    # reads it at the wrong offset fails on this vector rather than passing.
    name1 = b"file1.txt"
    name2 = b"file2.txt"
    file_entry1 = manifest_file_entry(name1, 0x1000, TEST_PAYLOAD_DIGEST, False)
    file_entry2 = manifest_file_entry(name2, 0x1000, TEST_PAYLOAD_DIGEST, True)

    full_manifest = header_no_crc + struct.pack("<I", crc) + signature + file_entry1 + file_entry2

    return {
        "name": "full_manifest_v2",
        "description": "Golden vector for full manifest with file entries v2",
        "inputs": {
            "magic": "DHMF",
            "version": 2,
            "session_id": TEST_SESSION_ID.hex(),
            "file_count": file_count,
            "total_size": total_size,
            "payload_digest": TEST_PAYLOAD_DIGEST.hex(),
            "salt": MANIFEST_SALT.hex(),
            "nonce": MANIFEST_NONCE.hex(),
            "signature": signature.hex(),
            "file_entries": [
                {"name": name1.decode("utf-8"), "size": 0x1000,
                 "digest": TEST_PAYLOAD_DIGEST.hex(), "executable": False},
                {"name": name2.decode("utf-8"), "size": 0x1000,
                 "digest": TEST_PAYLOAD_DIGEST.hex(), "executable": True},
            ],
        },
        "outputs": {
            "manifest_hex": full_manifest.hex(),
            "manifest_size": len(full_manifest),
            "crc32c": crc,
        },
    }


def generate_full_resume_vector() -> dict:
    """Generate a golden vector for a full resume file with block entries."""
    magic = b"DHRS"
    version = 0x02
    reserved = b"\x00\x00\x00"
    session_id = TEST_SESSION_ID
    block_count = 0x00000004
    journal_bytes = 0x0000000000002710  # 10000
    journal_digest = blake3(b"dhow resume journal vector")
    reserved2 = b"\x00" * 24

    header_no_crc = (
        magic
        + struct.pack("<B", version)
        + reserved
        + session_id
        + struct.pack("<I", block_count)
        + struct.pack("<Q", journal_bytes)
        + journal_digest
        + reserved2
    )

    crc = crc32c(header_no_crc)
    integrity_digest = blake3(header_no_crc + struct.pack("<I", crc))

    # Four blocks of 20 symbols: the first two hold symbols 0..15, the rest
    # hold none. 20 symbols occupy three bytes of bitmap, and the bits past
    # symbol 19 stay clear because a reader rejects bits it cannot place.
    described = []
    block_entries = b""
    for i in range(block_count):
        symbol_count = 20
        held = list(range(16)) if i < 2 else []
        bitmap = bytearray((symbol_count + 7) // 8)
        for symbol in held:
            bitmap[symbol // 8] |= 1 << (symbol % 8)
        block_entries += (
            struct.pack("<I", i)
            + struct.pack("<I", symbol_count)
            + struct.pack("<I", len(held))
            + bytes(bitmap)
        )
        described.append(
            {
                "block_index": i,
                "symbol_count": symbol_count,
                "symbols_held": len(held),
                "bitmap": bytes(bitmap).hex(),
            }
        )

    full_resume = header_no_crc + struct.pack("<I", crc) + integrity_digest + block_entries

    return {
        "name": "full_resume_v2",
        "description": "Golden vector for full resume file with block entries v2",
        "inputs": {
            "magic": "DHRS",
            "version": 2,
            "session_id": session_id.hex(),
            "block_count": block_count,
            "journal_bytes": journal_bytes,
            "journal_digest": journal_digest.hex(),
            "block_entries": described,
        },
        "outputs": {
            "resume_hex": full_resume.hex(),
            "resume_size": len(full_resume),
            "crc32c": crc,
            "integrity_digest": integrity_digest.hex(),
        },
    }


def generate_chunker_vector(name, payload_size, block_count, symbol_size):
    """Generate a golden vector for chunker layout."""
    s = payload_size
    b = block_count
    n = symbol_size

    remainder = s % b
    large_size = (s + b - 1) // b
    small_size = s // b

    blocks = []
    offset = 0
    total_symbols = 0

    for i in range(b):
        size = large_size if i < remainder else small_size
        symbol_count = (size + n - 1) // n if size > 0 else 0
        total_symbols += symbol_count

        symbols = []
        for j in range(symbol_count):
            sym_start = j * n
            if size % n != 0 and j == symbol_count - 1:
                sym_size = size % n
                padded = True
            else:
                sym_size = n
                padded = False
            symbols.append({
                "index": j,
                "start": sym_start,
                "size": sym_size,
                "padded": padded,
            })

        blocks.append({
            "index": i,
            "start": offset,
            "size": size,
            "symbol_count": symbol_count,
            "symbols": symbols,
        })
        offset += size

    return {
        "name": name,
        "description": f"Golden vector for chunker: payload_size={payload_size}, block_count={block_count}, symbol_size={symbol_size}",
        "inputs": {
            "payload_size": payload_size,
            "block_count": block_count,
            "symbol_size": symbol_size,
        },
        "outputs": {
            "block_count": b,
            "total_symbols": total_symbols,
            "blocks": blocks,
        },
    }


def main():
    """Generate all golden vectors and write them to a JSON file."""
    vectors = [
        generate_frame_header_vector(),
        generate_session_header_vector(),
        generate_manifest_header_vector(),
        generate_resume_header_vector(),
        generate_file_entry_vector(),
        generate_block_entry_vector(),
        generate_full_manifest_vector(),
        generate_full_resume_vector(),
        generate_chunker_vector("chunker_simple_v1", 1000, 2, 256),
        generate_chunker_vector("chunker_remainder_v1", 1001, 2, 256),
        generate_chunker_vector("chunker_padding_v1", 1000, 1, 256),
        generate_chunker_vector("chunker_exact_multiple_v1", 1024, 2, 256),
        generate_chunker_vector("chunker_single_byte_v1", 1, 1, 256),
        generate_chunker_vector("chunker_empty_v1", 0, 1, 256),
        generate_chunker_vector("chunker_symbol_size_one_v1", 10, 2, 1),
    ]

    output = {
        "version": "1.0",
        "description": "Golden test vectors for Dhow wire formats",
        "generator": "scripts/gen_vectors.py",
        "vectors": vectors,
    }

    output_path = os.path.join(os.path.dirname(__file__), "..", "proto", "vectors.json")
    output_path = os.path.abspath(output_path)

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Generated {len(vectors)} golden vectors to {output_path}")
    for v in vectors:
        print(f"  - {v['name']}: {v['outputs'].get('header_size', v['outputs'].get('entry_size', '?'))} bytes")


if __name__ == "__main__":
    main()
