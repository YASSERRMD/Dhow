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
import hashlib
import json
import sys
import os

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
    h = hashlib.blake2b(digest_size=32)
    h.update(data)
    return h.digest()


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


def generate_manifest_header_vector() -> dict:
    """Generate a golden vector for a manifest header."""
    magic = b"DHMF"
    version = 0x01
    reserved = b"\x00\x00\x00"
    session_id = TEST_SESSION_ID
    file_count = 0x00000002
    total_size = 0x00002000  # 8192 bytes
    payload_digest = TEST_PAYLOAD_DIGEST
    reserved2 = b"\x00" * 32

    # Build header (without CRC and signature)
    header_no_crc = (
        magic
        + struct.pack("<B", version)
        + reserved
        + session_id
        + struct.pack("<I", file_count)
        + struct.pack("<Q", total_size)
        + payload_digest
        + reserved2
    )

    crc = crc32c(header_no_crc)
    signature = TEST_SIGNATURE
    header = header_no_crc + struct.pack("<I", crc) + signature

    return {
        "name": "manifest_header_v1",
        "description": "Golden vector for manifest header v1",
        "inputs": {
            "magic": "DHMF",
            "version": 1,
            "reserved": 0,
            "session_id": session_id.hex(),
            "file_count": file_count,
            "total_size": total_size,
            "payload_digest": payload_digest.hex(),
            "reserved2": reserved2.hex(),
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
    version = 0x01
    reserved = b"\x00\x00\x00"
    session_id = TEST_SESSION_ID
    block_count = 0x00000004
    reserved2 = b"\x00" * 32

    # Build header (without CRC and integrity digest)
    header_no_crc = (
        magic
        + struct.pack("<B", version)
        + reserved
        + session_id
        + struct.pack("<I", block_count)
        + reserved2
    )

    crc = crc32c(header_no_crc)
    integrity_digest = blake3(header_no_crc + struct.pack("<I", crc))
    header = header_no_crc + struct.pack("<I", crc) + integrity_digest

    return {
        "name": "resume_header_v1",
        "description": "Golden vector for resume file header v1",
        "inputs": {
            "magic": "DHRS",
            "version": 1,
            "reserved": 0,
            "session_id": session_id.hex(),
            "block_count": block_count,
            "reserved2": reserved2.hex(),
            "integrity_digest": integrity_digest.hex(),
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

    entry = (
        struct.pack("<H", name_length)
        + name
        + struct.pack("<Q", file_size)
        + file_digest
    )

    return {
        "name": "manifest_file_entry_v1",
        "description": "Golden vector for manifest file entry v1",
        "inputs": {
            "name": name.decode("utf-8"),
            "name_length": name_length,
            "file_size": file_size,
            "file_digest": file_digest.hex(),
        },
        "outputs": {
            "entry_hex": entry.hex(),
            "entry_size": len(entry),
        },
    }


def generate_block_entry_vector() -> dict:
    """Generate a golden vector for a resume block entry."""
    block_index = 0x00000001
    symbol_count = 0x00000014  # 20
    symbols_held = 0x00000010  # 16
    # Bitmap: first 16 bits set (16 symbols held out of 20)
    bitmap = 0xFFFF
    bitmap_bytes = struct.pack("<I", bitmap)

    entry = (
        struct.pack("<I", block_index)
        + struct.pack("<I", symbol_count)
        + struct.pack("<I", symbols_held)
        + bitmap_bytes
    )

    return {
        "name": "resume_block_entry_v1",
        "description": "Golden vector for resume block entry v1",
        "inputs": {
            "block_index": block_index,
            "symbol_count": symbol_count,
            "symbols_held": symbols_held,
            "bitmap": bitmap_bytes.hex(),
        },
        "outputs": {
            "entry_hex": entry.hex(),
            "entry_size": len(entry),
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
