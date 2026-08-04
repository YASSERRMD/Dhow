# Building and Verifying a Release

> Part of the [Contributing guide](../CONTRIBUTING.md).

A release nobody can reproduce is a release nobody can audit. If the binary an
operator downloads cannot be rebuilt byte for byte from the tagged source, then
"the source is on GitHub" says nothing about what they are running.

```bash
make release          # build into ./dist
make release-check    # build twice and compare
```

## What comes out

```
dist/
  artifacts/
    dhow              the binary
    SHA256SUMS        digests of everything beside it
    sbom-core.json    CycloneDX SBOM of the Rust workspace
    sbom-cli.json     CycloneDX SBOM of the Go module
    BUILD-INFO        the toolchain versions and flags used
  manifest.bin        a dhow manifest over artifacts/, signed
  release.pub         the public half, so it can be checked
```

The signed things are in a subdirectory and the signature sits beside it, so
verifying is the command an operator already knows, with nothing to exclude:

```bash
dhow verify -in dist -signer dist/release.pub -dir dist/artifacts
```

## The release is signed by dhow

`manifest.bin` is an ordinary dhow manifest: the same wire format, the same
Ed25519 signature over the same canonical bytes, checked by the same `dhow
verify`. A courier that signs other people's data and not its own releases is
making an argument it does not believe.

It is produced by a real `dhow send` over the artifacts directory whose frames
are then discarded. The manifest therefore describes a transfer that genuinely
happened — the coding parameters in it are real — and the only thing not kept is
a frame stream nobody asked for. Keeping the frames and shipping *those* is
`dhow send` on the same directory, which is how a release crosses an air gap.

**Verifying a download is checking a signature, not a checksum.** `SHA256SUMS`
tells you the files match each other; anyone who can replace the binary can
replace that file too. `manifest.bin` tells you the holder of `release.key`
produced them. What it cannot tell you is that `release.pub` is the right key —
that comes from wherever you got it, and the fingerprint is what you compare.
See the [key ceremony](OPERATIONS.md#2-the-senders-identity).

## Why the build happens at a fixed path

Four things make a build non-reproducible here. Three are the usual ones and are
handled by flags:

| Cause | Fix |
|-------|-----|
| Absolute paths in Rust output | `--remap-path-prefix` |
| Absolute paths in Go output | `-trimpath` |
| Go build ID derived from the action graph | `-ldflags -buildid=` |
| Timestamps | `SOURCE_DATE_EPOCH`, `TZ=UTC`, `LC_ALL=C` |

The fourth is not: **none of those reach the external linker.** cgo passes
`-L${SRCDIR}/../../../core/target/release` to clang, and macOS `ld64` records
its inputs' absolute paths in the debug map and derives `LC_UUID` from them.
Measured: two builds of identical source in different directories produced
binaries differing in 49 bytes, all of them the UUID and the code signature that
covers it.

So the tree is copied to `${DHOW_BUILD_ROOT:-/tmp/dhow-build}` and built there.
This is what containerised reproducible builds do by building at `/build`, and
the reasoning is the same: **reproducibility is a property of a documented
procedure, not of the directory you happen to be standing in.** Follow the
procedure and you get the bytes.

`-Wl,-no_uuid` would also have stabilised the UUID. It was rejected because a
Mach-O binary without `LC_UUID` does not start at all — `dyld` refuses it. A
reproducible binary that will not run is not a release, which is why
`--check` now runs the binary it just built.

## The check is a rebuild, not an inspection

```
$ make release-check
=== dhow reproducibility check ===
build root /tmp/dhow-build

building pass a...
building pass b...

  pass a  70acff9cedcbe690416fc082f8cf70ab6696f801133a17549153fe51d63e56fd
  pass b  70acff9cedcbe690416fc082f8cf70ab6696f801133a17549153fe51d63e56fd

=== REPRODUCIBLE ===
```

Both passes start from *different* source locations and go through the canonical
path. Copying the source elsewhere first is what makes this a test rather than a
tautology: if anything from the invoking directory reached the output, the two
would differ.

## When it says NOT REPRODUCIBLE

Find where the binaries differ before guessing:

```bash
cmp -l a b | wc -l                        # how much differs
cmp -l a b | head -1                      # where it starts
strings -a a | grep "$HOME"               # a leaked path is the usual cause
otool -l a | grep -A2 LC_UUID             # macOS
```

A handful of bytes near the start of a Mach-O is almost always `LC_UUID` and its
code signature. Kilobytes scattered through the middle is a leaked path or a
timestamp. Everything different means the two builds used different toolchains —
compare `BUILD-INFO`.

## SBOMs are normalised before shipping

A freshly generated CycloneDX document carries three things that are not facts
about the software: a new UUID serial number, a wall-clock timestamp, and
absolute build paths. All three would change between two builds of the same
source, and the last would publish a developer's home directory.

`scripts/normalize_sbom.py` replaces the serial number with one derived from the
document's own content — still unique per distinct SBOM, now stable across
rebuilds — pins the timestamp to `SOURCE_DATE_EPOCH`, strips the build path, and
sorts the component and dependency lists.

Two documents rather than one merged file, because the Rust workspace and the Go
module are separate dependency graphs with separate ecosystems and separate
advisory feeds. **`sbom-cli.json` legitimately lists zero components**: `go.mod`
has no `require` block, and the CLI depends on nothing outside the standard
library and the Rust core it links.

## The core is statically linked, and that took fixing

`dhow-ffi` builds a `cdylib` and a `staticlib` into the same directory, and
cgo's `-ldhow_ffi` prefers the dynamic one. Until this was measured, a release
binary linked `libdhow_ffi.dylib` **by its absolute build path**:

```
dyld[91448]: Library not loaded: /tmp/dhow-canon/core/target/release/deps/libdhow_ffi.dylib
```

It ran on the machine that built it and nowhere else. The release build removes
the dynamic library before linking, so the archive is the only candidate, and
`--check` runs the binary afterwards so a regression is caught rather than
shipped.

## What this does not do

**It does not cross-compile.** The phase pack asks for Linux x86_64 and aarch64
builds. Producing those from macOS needs a Linux cross toolchain and sysroot for
cgo, which is not a flag but an installation, and building them on a Linux
runner is both easier and more trustworthy than cross-compiling. `make release`
builds for the host; CI builds for Linux natively. There is no macOS-specific
logic in the script beyond the `.dylib`/`.so` cleanup, which handles both.

**It does not check reproducibility across machines.** Two runs on one machine
agree. Two machines with the same pinned toolchains should also agree, and
nothing here proves it — the toolchain versions are recorded in `BUILD-INFO` so
that a disagreement can be diagnosed rather than argued about.
