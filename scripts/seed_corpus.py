#!/usr/bin/env python3
"""
seed_corpus.py - build fuzz corpora from the golden vectors.

A fuzzer starting from random bytes never reaches a parser guarded by a magic
string, a version byte, and a CRC. It spends its whole budget failing the first
check. Seeding the corpus with structures that are already valid puts it past
the front door, and mutation does the rest.

Every seed here is derived from proto/vectors.json rather than written out by
hand, so a wire-format change that regenerates the vectors regenerates the
corpus with it. A corpus that drifts from the format is a corpus that stops
reaching the code it was built to reach, silently.

Usage:
    scripts/seed_corpus.py [fuzz_dir]

Writes fuzz/corpus/<target>/*.bin. Existing files are left alone, because a
corpus accumulates: inputs a previous run found interesting are worth more than
these seeds and must not be deleted by re-seeding.
"""

import hashlib
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_vectors():
    with open(os.path.join(ROOT, "proto", "vectors.json")) as f:
        return json.load(f)


def vectors_by_name(data):
    return {v["name"]: v for v in data["vectors"]}


def hex_output(vector, *keys):
    """Return the first present hex output of a vector, as bytes."""
    for key in keys:
        value = vector["outputs"].get(key)
        if value:
            return bytes.fromhex(value)
    raise KeyError(f"{vector['name']} has none of {keys}")


def write_seed(corpus_dir, data):
    """Write one seed, named by its own digest so re-running is idempotent."""
    os.makedirs(corpus_dir, exist_ok=True)
    name = hashlib.sha256(data).hexdigest()[:16] + ".bin"
    path = os.path.join(corpus_dir, name)
    if os.path.exists(path):
        return False
    with open(path, "wb") as f:
        f.write(data)
    return True


def truncations(data, count=4):
    """Yield progressively shorter prefixes of a seed.

    Truncation is the mutation a fuzzer is worst at discovering on its own for
    a length-prefixed format: shortening a buffer without adjusting the length
    field inside it is exactly the case a bounds check is there for, and random
    byte flips almost never produce it.
    """
    for divisor in range(2, 2 + count):
        cut = len(data) * (divisor - 1) // divisor
        if 0 < cut < len(data):
            yield data[:cut]


def seed_target(fuzz_dir, target, seeds):
    corpus = os.path.join(fuzz_dir, "corpus", target)
    written = 0
    for data in seeds:
        if not data:
            continue
        if write_seed(corpus, data):
            written += 1
        for shorter in truncations(data):
            if write_seed(corpus, shorter):
                written += 1
    return corpus, written


def main():
    fuzz_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "fuzz")
    by_name = vectors_by_name(load_vectors())

    frame = hex_output(by_name["frame_header_v1"], "header_hex")
    session = hex_output(by_name["session_header_v1"], "header_hex")
    manifest_header = hex_output(by_name["manifest_header_v2"], "header_hex")
    full_manifest = hex_output(by_name["full_manifest_v2"], "manifest_hex")
    entry = hex_output(by_name["manifest_file_entry_v2"], "entry_hex")
    resume_header = hex_output(by_name["resume_header_v2"], "header_hex")
    full_resume = hex_output(by_name["full_resume_v2"], "resume_hex")

    plan = {
        # A bare header, and a header followed by a plausible payload. The
        # frame parser reads a length out of the header and then indexes with
        # it, so both shapes matter.
        "frame_decode": [
            frame,
            frame + b"\x00" * 64,
            frame + bytes(range(256)),
        ],
        "session_header": [session],
        # One entry, and two entries back to back: the second is where an
        # over-reported consumed length would land.
        "manifest_entry": [
            entry,
            entry + entry,
            # A name length that claims more than follows it, which is the
            # shape the bounds check exists for and which mutation reaches
            # only by accident.
            struct.pack("<H", 0xFFFF) + entry[2:],
        ],
        "manifest_verify": [
            manifest_header,
            full_manifest,
            # The header with its declared file count intact and no entries
            # behind it. The parser must not walk off the end looking for them.
            full_manifest[: len(manifest_header)],
        ],
        "resume_load": [resume_header, full_resume],
    }

    total = 0
    for target, seeds in plan.items():
        corpus, written = seed_target(fuzz_dir, target, seeds)
        existing = len(os.listdir(corpus))
        print(f"  {target}: {existing} inputs ({written} new)")
        total += written

    print(f"\nSeeded {total} new inputs from proto/vectors.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
