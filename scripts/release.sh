#!/usr/bin/env bash
#
# release.sh - build a reproducible release, with an SBOM and a dhow signature.
#
# Usage:
#   scripts/release.sh [output dir] [identity key]
#
# Defaults to ./dist and ./release.key, generating the identity if it is absent.
#
# Produces:
#
#   <out>/artifacts/dhow            the binary
#   <out>/artifacts/SHA256SUMS      digests of every artifact
#   <out>/artifacts/sbom-core.json  CycloneDX SBOM of the Rust workspace
#   <out>/artifacts/sbom-cli.json   CycloneDX SBOM of the Go module
#   <out>/artifacts/BUILD-INFO      the toolchain versions and flags used
#   <out>/manifest.bin              a dhow manifest over artifacts/, signed
#   <out>/release.pub               the public half, so it can be checked
#
# The signed things live in a subdirectory and the signature beside it, so
# verification is the command an operator already knows, with no exclusions:
#
#   dhow verify -in <out> -signer <out>/release.pub -dir <out>/artifacts
#
# # Reproducibility
#
# A release nobody can reproduce is a release nobody can audit: if the binary an
# operator downloads cannot be rebuilt byte for byte from the tagged source, then
# "the source is on GitHub" says nothing about what they are running.
#
# Four things make a build non-reproducible here, and each is dealt with rather
# than hoped about:
#
#   1. Absolute paths in compiler output. Rust embeds the build directory in
#      panic messages and debug info; Go embeds it in the same places.
#      --remap-path-prefix and -trimpath replace them with placeholders.
#   2. Timestamps. Nothing in this build records one, but SOURCE_DATE_EPOCH is
#      exported anyway, because a dependency that starts recording one should
#      record the same one on every machine.
#   3. Build IDs. Go's default build ID is derived from the action graph, which
#      includes paths. -buildid= empties it.
#   4. Absolute paths in *linker* output, which the three above do not touch.
#      cgo passes -L${SRCDIR}/../../../core/target/release, and macOS ld64
#      records its inputs' paths in the debug map and derives LC_UUID from them.
#      Neither -trimpath nor --remap-path-prefix reaches the external linker.
#
# The fourth is why the build happens at a **canonical path**. The tree is
# copied to ${DHOW_BUILD_ROOT} and built there, so the paths the linker sees are
# the same on every machine. This is what containerised reproducible builds do
# by building at /build, and the reasoning is the same: reproducibility is a
# property of a documented *procedure*, not of any directory you happen to be
# standing in. Follow the procedure and you get the bytes.
#
# -Wl,-no_uuid would also have made LC_UUID stable, and was rejected: a binary
# without LC_UUID does not start on macOS at all. dyld refuses it. A
# reproducible binary that will not run is not a release.
#
# `scripts/release.sh --check` runs the whole procedure twice from two different
# source locations and compares. That is the only claim about reproducibility
# worth making: not that the flags look right, but that a second build produced
# the same bytes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# --- Reproducibility knobs, shared by every build path below ---

# A fixed epoch rather than the current time. The value is arbitrary and its
# only job is to be the same on every machine.
export SOURCE_DATE_EPOCH=1735689600  # 2025-01-01T00:00:00Z
export TZ=UTC
export LC_ALL=C

# Rust: strip the build directory out of anything that embeds it.
export RUSTFLAGS="--remap-path-prefix=${ROOT}=/dhow --remap-path-prefix=${HOME}/.cargo=/cargo"

# Go: -trimpath removes file system paths, -buildid= empties the build id, and
# -s -w drop the symbol table and DWARF, which are the largest remaining source
# of path-shaped bytes.
GO_LDFLAGS="-s -w -buildid="

# Where every release build happens, whatever directory it was invoked from.
# See the note on the canonical path above.
BUILD_ROOT="${DHOW_BUILD_ROOT:-/tmp/dhow-build}"

usage() {
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
}

# build_binary copies the tree at $2 to the canonical path and compiles dhow
# into $1.
build_binary() {
    local out="$1" tree="$2"

    rm -rf "$BUILD_ROOT"
    mkdir -p "$(dirname "$BUILD_ROOT")"
    cp -R "$tree" "$BUILD_ROOT"
    # Build products from wherever this was invoked would otherwise be reused,
    # which defeats the point of building at a fixed path.
    rm -rf "$BUILD_ROOT/core/target" "$BUILD_ROOT/fuzz/target" "$BUILD_ROOT/dist" \
           "$BUILD_ROOT/.git"

    RUSTFLAGS="--remap-path-prefix=${BUILD_ROOT}=/dhow --remap-path-prefix=${HOME}/.cargo=/cargo" \
        cargo build --release --quiet --manifest-path "$BUILD_ROOT/core/Cargo.toml" -p dhow-ffi

    # dhow-ffi builds a cdylib and a staticlib into the same directory, and
    # cgo's -ldhow_ffi prefers the dylib. A release binary that dynamically
    # links the Rust core from the build directory does not start anywhere
    # else - it was doing exactly that until this phase measured it. Removing
    # the dylib leaves the archive as the only candidate.
    rm -f "$BUILD_ROOT/core/target/release/libdhow_ffi.dylib" \
          "$BUILD_ROOT/core/target/release/deps/libdhow_ffi.dylib" \
          "$BUILD_ROOT/core/target/release/libdhow_ffi.so" \
          "$BUILD_ROOT/core/target/release/deps/libdhow_ffi.so"

    (cd "$BUILD_ROOT" && go build -trimpath -ldflags "$GO_LDFLAGS" -o "$out" ./cli/cmd/dhow)

    rm -rf "$BUILD_ROOT"
}

# --- --check: run the procedure twice and compare ---
#
# Two *source* locations, both built through the canonical path. Copying the
# source elsewhere first is what makes this a test rather than a tautology: if
# anything from the invoking directory reached the output, the two would differ.
if [ "${1:-}" = "--check" ]; then
    echo "=== dhow reproducibility check ==="
    echo "build root ${BUILD_ROOT}"
    echo

    CHECK="$(mktemp -d -t dhow-repro-XXXXXX)"
    trap 'rm -rf "$CHECK" "$BUILD_ROOT"' EXIT

    for pass in a b; do
        echo "building pass ${pass}..."
        cp -R "$ROOT" "$CHECK/tree-$pass"
        rm -rf "$CHECK/tree-$pass/core/target" "$CHECK/tree-$pass/.git" \
               "$CHECK/tree-$pass/fuzz/target" "$CHECK/tree-$pass/dist"
        build_binary "$CHECK/dhow-$pass" "$CHECK/tree-$pass"
    done

    A=$(shasum -a 256 "$CHECK/dhow-a" | cut -d' ' -f1)
    B=$(shasum -a 256 "$CHECK/dhow-b" | cut -d' ' -f1)

    echo
    echo "  pass a  $A"
    echo "  pass b  $B"
    echo

    if [ "$A" != "$B" ]; then
        echo "=== NOT REPRODUCIBLE ===" >&2
        echo "Two runs of the same procedure produced different binaries." >&2
        echo "See docs/RELEASE.md for what usually causes this." >&2
        exit 1
    fi

    # A binary that is reproducible and does not run is not a release. This is
    # the check that would have caught the dynamically-linked core.
    if ! "$CHECK/dhow-a" version >/dev/null 2>&1; then
        echo "=== BUILT BUT DOES NOT RUN ===" >&2
        "$CHECK/dhow-a" version >&2 || true
        exit 1
    fi

    echo "=== REPRODUCIBLE ==="
    exit 0
fi

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

OUT="${1:-$ROOT/dist}"
IDENTITY="${2:-$ROOT/release.key}"

# A release directory that already exists may hold a previous release's
# artifacts, and a manifest over a mixture of two releases describes neither.
rm -rf "$OUT"
mkdir -p "$OUT/artifacts"
OUT="$(cd "$OUT" && pwd)"
ART="$OUT/artifacts"

echo "=== dhow release ==="
echo "output ${OUT}"
echo

# --- The binary ---

echo "building..."
build_binary "$ART/dhow" "$ROOT"

# --- What produced it ---
#
# A reproducible build is only reproducible by someone who knows what to
# reproduce it with. The toolchain versions are part of the artifact.

echo "recording build info..."
{
    echo "source-date-epoch: ${SOURCE_DATE_EPOCH}"
    echo "rustc:             $(rustc --version)"
    echo "cargo:             $(cargo --version)"
    echo "go:                $(go version)"
    echo "host:              $(uname -sm)"
    echo "rustflags:         --remap-path-prefix=<tree>=/dhow --remap-path-prefix=<cargo>=/cargo"
    echo "go-flags:          -trimpath -ldflags '${GO_LDFLAGS}'"
} > "$ART/BUILD-INFO"

# --- SBOM ---
#
# Two documents rather than one merged file. The Rust workspace and the Go
# module are separate dependency graphs with separate ecosystems and separate
# advisory feeds, and merging them would produce a document that is neither.

echo "generating SBOMs..."
command -v cargo-cyclonedx >/dev/null 2>&1 \
    || { echo "cargo-cyclonedx is not installed: cargo install cargo-cyclonedx" >&2; exit 1; }
command -v cyclonedx-gomod >/dev/null 2>&1 \
    || { echo "cyclonedx-gomod is not installed: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest" >&2; exit 1; }

# cargo-cyclonedx writes one document per crate beside its manifest. dhow-ffi
# depends on both other crates, so its document already covers the whole
# workspace; the other two are subsets of it and are deleted rather than
# shipped as three overlapping files a reader has to reconcile.
(cd "$ROOT/core" && cargo cyclonedx --format json --spec-version 1.5 >/dev/null 2>&1)
python3 "$ROOT/scripts/normalize_sbom.py" \
    "$ROOT/core/dhow-ffi/dhow-ffi.cdx.json" "$ART/sbom-core.json" "$ROOT"
find "$ROOT/core" -name '*.cdx.json' -delete

(cd "$ROOT" && cyclonedx-gomod mod -json -output "$ART/sbom-cli.json.raw" >/dev/null 2>&1)
python3 "$ROOT/scripts/normalize_sbom.py" \
    "$ART/sbom-cli.json.raw" "$ART/sbom-cli.json" "$ROOT"
rm -f "$ART/sbom-cli.json.raw"

# --- Checksums ---

echo "checksumming..."
# Sorted, so the file itself is reproducible whatever order the shell globs in.
(cd "$ART" && rm -f SHA256SUMS && shasum -a 256 ./* 2>/dev/null | sed 's| \./| |' | sort -k2 > SHA256SUMS)

# --- The signature, from dhow itself ---
#
# A courier that signs other people's data and not its own releases is making an
# argument it does not believe. The release manifest is an ordinary dhow
# manifest: the same wire format, the same Ed25519 signature over the same
# canonical bytes, checked by the same `dhow verify` an operator already knows.
#
# It is produced by a real `dhow send` over the artifact directory, and the
# frames are discarded. The manifest therefore describes a transfer that was
# genuinely performed - the coding parameters in it are real - and the only
# thing not kept is the frame stream nobody asked for. Sending a release across
# an air gap with the frames kept is `dhow send` on this directory, which is the
# point.

if [ ! -f "$IDENTITY" ]; then
    echo "generating a release identity at ${IDENTITY}..."
    "$ART/dhow" keygen -kind identity -out "$IDENTITY" -quiet
fi
PUBLIC="${IDENTITY%.key}.pub"
[ -f "$PUBLIC" ] || { echo "no public half at ${PUBLIC}" >&2; exit 1; }

echo "signing..."
SIGN_WORK="$(mktemp -d -t dhow-sign-XXXXXX)"
"$ART/dhow" keygen -out "$SIGN_WORK/operator.key" -quiet
"$ART/dhow" send -key "$SIGN_WORK/operator.key" -identity "$IDENTITY" \
    -in "$ART" -out "$SIGN_WORK/frames" \
    -symbol-size 1320 -blocks 1 -overhead 0 -quiet
cp "$SIGN_WORK/frames/manifest.bin" "$OUT/manifest.bin"
cp "$PUBLIC" "$OUT/release.pub"
rm -rf "$SIGN_WORK"

echo "verifying the signature..."
"$ART/dhow" verify -in "$OUT" -signer "$OUT/release.pub" -dir "$ART" >/dev/null

echo
echo "artifacts:"
(cd "$OUT" && find . -type f | sed 's|^\./|  |' | sort)
echo
echo "verify a download with:"
echo "  dhow verify -in <release> -signer <release>/release.pub -dir <release>/artifacts"
echo
echo "=== RELEASE BUILT ==="
