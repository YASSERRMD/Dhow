#!/usr/bin/env python3
"""
Conformance test for Dhow wire-format golden vectors.

Validates that golden vectors in proto/vectors.json conform to the
specification in proto/*.md. This is the test that third-party
implementations must pass.
"""

import json
import os
import sys


def load_vectors():
    """Load golden vectors from proto/vectors.json."""
    vectors_path = os.path.join(
        os.path.dirname(__file__), "..", "proto", "vectors.json"
    )
    vectors_path = os.path.abspath(vectors_path)
    with open(vectors_path) as f:
        return json.load(f)


def check_magic(data, vector_name, expected_magic):
    """Check that the vector starts with the expected magic bytes."""
    hex_str = data["outputs"].get("header_hex") or data["outputs"].get("manifest_hex") or data["outputs"].get("resume_hex") or data["outputs"].get("entry_hex")
    if not hex_str:
        return [f"  {vector_name}: no hex output found"]

    magic_hex = expected_magic.encode().hex()
    if not hex_str.startswith(magic_hex):
        return [f"  {vector_name}: magic mismatch - expected {expected_magic}, got {hex_str[:8]}"]

    return []


def check_version(data, vector_name):
    """Check that the version byte is 0x01."""
    hex_str = data["outputs"].get("header_hex") or data["outputs"].get("manifest_hex") or data["outputs"].get("resume_hex") or data["outputs"].get("entry_hex")
    if not hex_str:
        return [f"  {vector_name}: no hex output found"]

    # Version is at offset 4 (after 4-byte magic)
    version_hex = hex_str[8:10]
    if version_hex != "01":
        return [f"  {vector_name}: version mismatch - expected 0x01, got 0x{version_hex}"]

    return []


def check_reserved_zero(data, vector_name, reserved_offset, reserved_length):
    """Check that reserved fields are zero."""
    hex_str = data["outputs"].get("header_hex") or data["outputs"].get("manifest_hex") or data["outputs"].get("resume_hex") or data["outputs"].get("entry_hex")
    if not hex_str:
        return [f"  {vector_name}: no hex output found"]

    start = reserved_offset * 2  # Convert byte offset to hex char offset
    end = start + reserved_length * 2
    reserved_hex = hex_str[start:end]
    if reserved_hex != "0" * (reserved_length * 2):
        return [f"  {vector_name}: reserved field not zero at offset {reserved_offset}"]

    return []


def main():
    """Run conformance tests."""
    print("=== Dhow Wire-Format Conformance Test ===")
    print()

    all_errors = []

    try:
        data = load_vectors()
    except Exception as e:
        print(f"FAIL: Could not load vectors: {e}")
        sys.exit(1)

    # Check each vector
    for vector in data["vectors"]:
        name = vector["name"]
        print(f"Checking {name}...")

        # Check magic bytes
        magic_map = {
            "frame_header_v1": "DHOW",
            "session_header_v1": "DSES",
            "manifest_header_v1": "DHMF",
            "resume_header_v1": "DHRS",
            "full_manifest_v1": "DHMF",
            "full_resume_v1": "DHRS",
        }

        if name in magic_map:
            errors = check_magic(vector, name, magic_map[name])
            all_errors.extend(errors)

            # Check version
            errors = check_version(vector, name)
            all_errors.extend(errors)

            # Check reserved fields are zero
            # Frame header: reserved at offset 6, length 2
            # Session header: reserved at offset 5, length 3
            # Manifest header: reserved at offset 5, length 3
            # Resume header: reserved at offset 5, length 3
            reserved_map = {
                "frame_header_v1": (6, 2),
                "session_header_v1": (5, 3),
                "manifest_header_v1": (5, 3),
                "resume_header_v1": (5, 3),
                "full_manifest_v1": (5, 3),
                "full_resume_v1": (5, 3),
            }

            if name in reserved_map:
                offset, length = reserved_map[name]
                errors = check_reserved_zero(vector, name, offset, length)
                all_errors.extend(errors)

        if not any(e.startswith(f"  {name}") for e in all_errors):
            print(f"  PASS")

    print()
    if all_errors:
        for e in all_errors:
            print(f"  FAIL: {e}")
        print(f"\nFAILED: {len(all_errors)} errors found")
        sys.exit(1)
    else:
        print("ALL CONFORMANCE TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
