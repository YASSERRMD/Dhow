#!/usr/bin/env python3
"""
normalize_sbom.py - make a CycloneDX document reproducible.

Usage:
    scripts/normalize_sbom.py <input.json> <output.json> <repo root>

A generated SBOM ships inside the release and is covered by SHA256SUMS and by
the release manifest, so it has to be byte-identical between two builds of the
same source. Three things in a freshly generated document are not:

    serialNumber        a fresh UUID on every run
    metadata.timestamp  wall-clock time
    bom-ref / purl      absolute paths to the build directory

None of the three describes the software. The first two describe *this run of
the generator*, and the third describes the machine it ran on - which is exactly
the information a reproducible build exists to remove, and which would leak a
developer's home directory into a published artifact.

The serial number is replaced with a UUID derived from the document's own
content, so it is still unique per distinct SBOM and is now stable across
rebuilds of the same one. The timestamp is replaced with SOURCE_DATE_EPOCH.
Absolute paths become `/dhow`.
"""

import hashlib
import json
import os
import sys
import uuid


def strip_paths(value, root: str):
    """Replaces the build directory with a placeholder, everywhere."""
    if isinstance(value, str):
        return value.replace(root, "/dhow")
    if isinstance(value, list):
        return [strip_paths(item, root) for item in value]
    if isinstance(value, dict):
        return {key: strip_paths(item, root) for key, item in value.items()}
    return value


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__.strip(), file=sys.stderr)
        return 1

    src, dst, root = sys.argv[1], sys.argv[2], os.path.abspath(sys.argv[3])

    with open(src) as f:
        doc = json.load(f)

    doc = strip_paths(doc, root)

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    doc.setdefault("metadata", {})["timestamp"] = (
        __import__("datetime")
        .datetime.fromtimestamp(epoch, __import__("datetime").timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    # The generator's own version is legitimate metadata and is kept. Its
    # *invocation* is not, so anything that varies per run is already gone by
    # this point.

    # Components in a stable order, so a generator that walks a hash map does
    # not produce a different file on a different day.
    if "components" in doc:
        doc["components"].sort(key=lambda c: (c.get("name", ""), c.get("version", "")))
    if "dependencies" in doc:
        doc["dependencies"].sort(key=lambda d: d.get("ref", ""))
        for dep in doc["dependencies"]:
            if "dependsOn" in dep:
                dep["dependsOn"].sort()

    # A serial number derived from the content: still unique per distinct SBOM,
    # now identical for two builds of the same source. Computed with the field
    # itself removed, or it would depend on its own previous value.
    doc.pop("serialNumber", None)
    digest = hashlib.sha256(
        json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    ).digest()
    doc["serialNumber"] = f"urn:uuid:{uuid.UUID(bytes=digest[:16], version=5)}"

    with open(dst, "w") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"  {os.path.basename(dst)}: {len(doc.get('components', []))} components")
    return 0


if __name__ == "__main__":
    sys.exit(main())
