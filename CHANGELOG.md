# Changelog

Derived from the phase ledger on `main`. Every entry corresponds to a merged
phase branch and a `phase-NN` tag; [`docs/phase-log.md`](docs/phase-log.md) has
the long form, including what each phase found and where it fell short.

Wire-format changes are marked **BREAKING** and carry a pointer to
[`proto/migration.md`](proto/migration.md).

## Unreleased

### Phase 39 — The four untested security claims

- `scripts/security_lint.py` and a `[bans]` denylist in `deny.toml`, both in the
  gate (28 checks now). Four threat-model rows move from Review and Absent to
  **Enforced**, each shown to bite. **[B-9](docs/BACKLOG.md) closed.**
- **Fixed: fifteen FFI entry points caught no unwind** — seven `*_free`
  functions whose `Drop` runs unguarded, five accessors, and
  `dhow_last_error_message`, whose `RefCell::borrow` panics on re-entry.
- **Fixed: `TransferSecrets` renamed to `TransferParameters`.** Its own doc
  comment said neither field is secret.
- **Fixed: the tamper tests sometimes did not tamper.** `printf '\xa5' | dd`
  sets a byte rather than flipping it, so one time in 256 per offset the
  "tampered" file was identical to the original and the harness reported a
  failure. About three per cent per loopback run.

### Phase 38 — Memory: the copies that do not need an ABI change

- `dhow send` peaks at **7.6x** the dataset size, down from 10.4x; `dhow recv` at
  **5.4x**, down from 6.4x. `scripts/rss.sh` tightened from 12x/8x to **9x/6x**.
- Three copies removed: the frame stream held twice while being serialized, the
  archive copied out of its own builder, and the plaintext decrypted into a
  second buffer instead of in place.
- **The ABI change the objective called for is not here.** Everything left needs
  a feed-and-poll encoder handle and a streaming `dhow_decoder_finish` —
  `DHOW_ABI_VERSION` 5 — and splitting one design across two ABI versions would
  be worse than deferring it. [B-6, B-8](docs/BACKLOG.md) carry the numbers each
  remaining part is worth.

### Phase 37 — Camera capture and QR detection

The half that was missing. A transfer now crosses the optical layer end to end:
frames rendered as QR codes, located in a captured image, sampled through the
camera's perspective, decoded, and pre-filtered before they reach the core.

- `dhow recv -source` names where images come from: `frames` (the default, and
  what every harness above the optical layer uses), `images[:DIR]`, `pipe`, or
  `cmd:COMMAND` for a live camera. Dhow does not open a camera itself; the
  capture program does, and writes Netpbm to its standard output.
- `dhow detect` reads one image and says what is in it, with `-binarized` to
  write out what the binarizer saw. It is what distinguishes a camera problem
  from a key problem.
- `internal/qr` decodes a module grid: format information, unmasking,
  de-interleaving, and Reed-Solomon over GF(256). **No new dependency**;
  `go.mod` still has none and `sbom-cli.json` still lists zero components. The
  decision and what was rejected are in the commit that added it.
- `internal/optical` turns an image into a module grid, and `internal/capture`
  supplies the images, counts every drop, and applies the per-frame CRC
  fast-reject before the FFI crossing that `proto/frame.md` put the CRC there
  for.
- `scripts/optical.sh` is a new gate: an end-to-end transfer through the
  shipped binary's own command line, with a quarter of the captures missing,
  the wrong key, and another session's screen. Twenty-seven gates now.
- **Fixed, all predating the phase and found by running the gate:**
  `cargo clippy -D warnings` and `cargo deny` had both been failing on `main`
  since the chacha20poly1305 0.11 bump.

**Not done: a camera pointed at a screen.** The detector is driven by rendered
frames with synthetic degradation, which is a model of a lens and not a lens.
[B-3](docs/BACKLOG.md) records the measured tolerances and, more usefully, the
list of things the model does not reproduce.

## v1.0.0-rc.1 — Phase 36

Format suite **2.0**, C ABI **4**.

- `scripts/triage.sh` enforces zero unresolved markers, with the fourteen
  false-positive strings in this tree written down with reasons rather than
  silenced by a `grep -v`.
- The gate runs green from a **clean clone**: 26 checks, none skipped, in a
  directory with no build products, no fuzz corpus, and no keys.

**Why this is a release candidate and not 1.0.0.** Two things, both recorded in
[B-11](docs/BACKLOG.md):

1. **The camera path does not exist.** Dhow's purpose is crossing an air gap by
   showing frames on a screen and reading them with a camera. Every layer above
   the optical one is exercised end to end; the tool still cannot do the thing
   it is for.
2. **B-1 is open** — an unreproduced possible-correctness defect whose own entry
   says to treat it as high until reproduced. 2,960 chaos rounds have not
   reproduced it, which bounds how common it is rather than whether it exists.

Everything else a 1.0.0 asks for is done: the format suite is frozen with a
compatibility policy, the ABI is stable, the build is reproducible and the
release signed by dhow itself, the documentation is complete and executed by the
gate, and every threat-model control is traced to a test or recorded as
unenforced.

### Phase 35 — Documentation completion

- Added `docs/ARCHITECTURE.md`, `docs/FFI.md`, and this changelog.
- README rewritten to be accurate about what the tool does not do, with a
  quickstart a script executes rather than a reader trusts.

### Phase 34 — Format spec freeze and CLI conformance

- **`proto/` frozen at suite 2.0**, with a compatibility policy stating what a
  conforming receiver must accept and must reject. There is no forward or
  backward compatibility within the suite, and the reason is written down.
- `scripts/conformance_cli.py` checks a **built binary** against `proto/`.
  The existing suites checked generated vectors against the documents that
  generated them, which cannot catch the implementation drifting from both.
- Fixed: `proto/README.md` claimed suite version 1.0 and listed the manifest and
  resume formats as v1. Both had been v2 since Phases 24 and 28. It also said
  reserved fields are ignored, which no parser here has ever done.

### Phase 33 — Reproducible builds, SBOM, and a signed release

- `scripts/release.sh` produces a byte-reproducible build, CycloneDX SBOMs for
  both dependency graphs, and a release manifest **signed by dhow itself**.
  Verifying a download is `dhow verify`.
- Fixed: the release binary **linked the Rust core dynamically by its absolute
  build path** and ran only on the machine that built it. `cgo`'s `-ldhow_ffi`
  prefers the cdylib over the staticlib when both are present.
- Reproducibility needed a canonical build path, not just flags:
  `--remap-path-prefix` and `-trimpath` do not reach the external linker, and
  macOS `ld64` derives `LC_UUID` from its inputs' absolute paths.
- Not done: cross-compilation for Linux. [B-10](docs/BACKLOG.md).

### Phase 32 — Security review and threat model v1

- `docs/THREAT-MODEL.md` v1: a 47-row traceability table naming, for every
  control, the test that fails if it is removed — or recording that nothing
  enforces it. **Six rows are enforced by nothing** and say so.
- `cargo geiger` confirms zero unsafe expressions in `dhow-codec` and
  `dhow-crypt`.
- Fixed: the Assets table described the operator key as an Ed25519 identity key.
  It is a 32-byte symmetric secret, and one of two keys with opposite
  distribution rules.
- Opened [B-9](docs/BACKLOG.md) for four testable-but-untested claims, including
  that nothing enforces "no network calls in the data path".

### Phase 31 — Benchmarks and a memory budget

- criterion benchmarks for the Rust data path, `go test -bench` for packing, and
  a peak-RSS budget the gate enforces.
- **`crc32c_digest` was 4.6x too slow** — 513 MiB/s against BLAKE3's 2.1 GiB/s,
  making it the largest per-frame cost in the encoder, ahead of the keyed MAC it
  precedes. Replaced with slicing-by-eight: −78% time, and frame handling 3.7x
  faster. Output unchanged by construction.
- Measured: `send` peaks at **10.4x** the dataset size and `recv` at **6.4x**.
  Roughly 9 GiB and 6 GiB for a 1 GiB transfer.
  [B-6, B-8](docs/BACKLOG.md).

### Phase 30 — Property and differential testing

- A differential test of the Go-driven ABI path against the pure-Rust path on
  identical inputs, with a reference binary that calls no `extern "C"` function.
- 28 new property tests. `dhow-crypt` had none before, which was the wrong way
  round: the codec's failure mode is a dataset that does not reassemble, and the
  crypt crate's is a dataset that reassembles into something an attacker chose.

### Phase 29 — Fuzzing the parsers

- Five `cargo-fuzz` targets over the frame, session, manifest, entry, and resume
  parsers, each asserting the invariants its parser promises rather than only
  that it did not crash. **2.37 billion executions, zero crashes.**
- The minimized corpus is committed and replayed on **stable** by
  `dhow-codec`'s `replay_test`, so a regression is caught on a machine that has
  never installed nightly.
- Fixed: `Manifest::from_bytes` accepted and silently ignored trailing bytes, so
  `to_vec()` could describe less than its input. The resume parser had rejected
  the same shape since Phase 12.
- AddressSanitizer is disabled on macOS; its runtime hangs before executing a
  single input. Documented rather than worked around silently.

### Phase 28 — The signed manifest, wired through the CLI

- **BREAKING: manifest wire format v2.** The fixed header grows 168 → 228 bytes
  and gains the salt, nonce, and full coding parameter set; file entries grow to
  43+name with a flag byte carrying the executable bit.
  [migration](proto/migration.md).
- `dhow keygen -kind identity` produces an Ed25519 signing key. `send` signs;
  `recv`, `verify`, and `display` take `-signer` and **read nothing out of a
  transfer before the signature checks**.
- The unsigned `transfer.json` is deleted, not deprecated. Closes B-2.
- ABI **4**: 16 new functions for identity handles and manifest build and
  verify.
- Fixed: v1's payload digest was a digest of the concatenated file digests, not
  BLAKE3 of the payload as the spec said. Nothing depended on it, because
  nothing read the manifest.
- Fixed: `gofmt` was documented as a gate and had never run.
- Fixed: the conformance suite reported PASS on checks that matched nothing.

### Phase 27 — Chaos and soak

- `scripts/chaos.sh`: randomised fault injection from a printed seed. Every
  round must complete and verify, or fail closed writing nothing.
- Found and recorded [B-1](docs/BACKLOG.md), an unreproduced failure. Still open
  after 2,960 rounds.

### Phase 26 — Operator UX and the operations guide

- `docs/OPERATIONS.md`, and `scripts/drill.sh`, which follows the guide from a
  cold start so it fails the build when it drifts from the tool.

### Phase 25 — Verification that checks contents

- `dhow verify` gained a per-file inventory. Before it, a dataset of the right
  shape and entirely wrong contents passed.

### Phase 24 — Interruption and resume, full stack

- **BREAKING: resume file v2**, binding the index to its journal by digest and
  length. Local state only; no effect over the optical channel.

### Phases 18–23 — The FFI boundary and the optical layer

- `dhow-ffi` with a cbindgen-generated header and an ABI drift gate; Go bindings;
  the CLI surface; QR encoding with a measured capacity table; the screen
  renderer; loopback integration.

### Phases 5–17 — The core

- Chunker, integrity primitives, frame and session wire formats, RaptorQ encode
  and decode, session model, resume state, key handling, payload AEAD, and
  manifest signing and verification.

### Phases 1–4 — Foundation

- Monorepo scaffold with pinned toolchains, CI with lint and audit gates, the
  wire-format specification and its golden vectors, the error taxonomy, and a
  logger that is silent on the data path.

## Format versions

| Format | Version | Changed in |
|--------|---------|-----------|
| Frame header | 1 | Phase 8 |
| Session header | 1 | Phase 11 |
| Manifest | **2** | Phase 28 |
| Resume file | **2** | Phase 24 |
| C ABI | **4** | Phase 28 |
| Key file | 1 | Phase 15 |
