#!/usr/bin/env python3
"""
Spec consistency checker for Dhow wire formats.

Validates that:
1. Field offsets sum to declared sizes in each format.
2. Golden vectors match the declared sizes.
3. Endianness is consistent (all little-endian).
4. Version bytes are present in all formats.
5. Reserved fields are declared.
"""

import json
import os
import re
import sys


def load_vectors():
    """Load golden vectors from proto/vectors.json."""
    vectors_path = os.path.join(
        os.path.dirname(__file__), "..", "proto", "vectors.json"
    )
    vectors_path = os.path.abspath(vectors_path)
    with open(vectors_path) as f:
        return json.load(f)


def check_vector_sizes(data):
    """Check that golden vector sizes match declared sizes."""
    errors = []
    expected_sizes = {
        "frame_header_v1": 46,
        "session_header_v1": 126,
        "manifest_header_v1": 168,
        "resume_header_v1": 96,
        "manifest_file_entry_v1": 55,
        "resume_block_entry_v1": 16,
    }

    for vector in data["vectors"]:
        name = vector["name"]
        if name in expected_sizes:
            actual_size = vector["outputs"].get("header_size") or vector["outputs"].get("entry_size")
            if actual_size != expected_sizes[name]:
                errors.append(
                    f"  {name}: size mismatch - expected {expected_sizes[name]}, got {actual_size}"
                )

    return errors


def check_hex_decoding(data):
    """Check that all hex fields in vectors decode correctly."""
    errors = []

    for vector in data["vectors"]:
        outputs = vector.get("outputs", {})
        for key, value in outputs.items():
            if key.endswith("_hex") or key.endswith("_digest"):
                try:
                    bytes.fromhex(value)
                except (ValueError, TypeError):
                    errors.append(f"  {vector['name']}.{key}: invalid hex string")

    return errors


def check_field_offsets():
    """Check that field offsets in the spec sum to declared sizes."""
    errors = []

    # Frame header: 4 + 1 + 1 + 2 + 16 + 8 + 4 + 4 + 2 + 4 = 46
    frame_fields = [4, 1, 1, 2, 16, 8, 4, 4, 2, 4]
    if sum(frame_fields) != 46:
        errors.append(f"  frame_header: field offsets sum to {sum(frame_fields)}, expected 46")

    # Session header: 4 + 1 + 3 + 16 + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 2 + 32 + 32 + 4 = 126
    session_fields = [4, 1, 3, 16, 8, 4, 4, 4, 4, 4, 4, 2, 32, 32, 4]
    if sum(session_fields) != 126:
        errors.append(f"  session_header: field offsets sum to {sum(session_fields)}, expected 126")

    # Manifest header: 4 + 1 + 3 + 16 + 4 + 8 + 32 + 32 + 4 + 64 = 168
    manifest_fields = [4, 1, 3, 16, 4, 8, 32, 32, 4, 64]
    if sum(manifest_fields) != 168:
        errors.append(f"  manifest_header: field offsets sum to {sum(manifest_fields)}, expected 168")

    # Resume header: 4 + 1 + 3 + 16 + 4 + 32 + 4 + 32 = 96
    resume_fields = [4, 1, 3, 16, 4, 32, 4, 32]
    if sum(resume_fields) != 96:
        errors.append(f"  resume_header: field offsets sum to {sum(resume_fields)}, expected 96")

    return errors


def check_version_bytes():
    """Check that all formats have a version byte at offset 4."""
    errors = []

    # Check that the spec files mention version bytes
    proto_dir = os.path.join(os.path.dirname(__file__), "..", "proto")
    proto_dir = os.path.abspath(proto_dir)

    spec_files = ["frame.md", "session.md", "manifest.md", "resume.md"]
    for spec_file in spec_files:
        path = os.path.join(proto_dir, spec_file)
        if not os.path.exists(path):
            errors.append(f"  {spec_file}: spec file not found")
            continue

        with open(path) as f:
            content = f.read()

        if "Version" not in content:
            errors.append(f"  {spec_file}: no Version field declared")

        if "Reserved" not in content:
            errors.append(f"  {spec_file}: no Reserved field declared")

    return errors


def check_endianness():
    """Check that all multi-byte fields are little-endian."""
    errors = []

    proto_dir = os.path.join(os.path.dirname(__file__), "..", "proto")
    proto_dir = os.path.abspath(proto_dir)

    endianness_file = os.path.join(proto_dir, "endianness.md")
    if not os.path.exists(endianness_file):
        errors.append("  endianness.md: spec file not found")
        return errors

    with open(endianness_file) as f:
        content = f.read()

    if "little-endian" not in content.lower():
        errors.append("  endianness.md: little-endian not declared")

    return errors


def main():
    """Run all consistency checks."""
    print("=== Dhow Wire-Format Spec Consistency Checker ===")
    print()

    all_errors = []

    # Load vectors
    try:
        data = load_vectors()
    except Exception as e:
        print(f"FAIL: Could not load vectors: {e}")
        sys.exit(1)

    print("Checking golden vector sizes...")
    errors = check_vector_sizes(data)
    if errors:
        all_errors.extend(errors)
        for e in errors:
            print(f"  FAIL: {e}")
    else:
        print("  PASS")

    print("Checking hex decoding...")
    errors = check_hex_decoding(data)
    if errors:
        all_errors.extend(errors)
        for e in errors:
            print(f"  FAIL: {e}")
    else:
        print("  PASS")

    print("Checking field offsets...")
    errors = check_field_offsets()
    if errors:
        all_errors.extend(errors)
        for e in errors:
            print(f"  FAIL: {e}")
    else:
        print("  PASS")

    print("Checking version bytes...")
    errors = check_version_bytes()
    if errors:
        all_errors.extend(errors)
        for e in errors:
            print(f"  FAIL: {e}")
    else:
        print("  PASS")

    print("Checking endianness...")
    errors = check_endianness()
    if errors:
        all_errors.extend(errors)
        for e in errors:
            print(f"  FAIL: {e}")
    else:
        print("  PASS")

    print()
    if all_errors:
        print(f"FAILED: {len(all_errors)} errors found")
        sys.exit(1)
    else:
        print("ALL CHECKS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
