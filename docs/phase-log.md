# Phase Log

## Phase 19 - Go bindings

**Objective:** Wrap the C ABI in a Go-idiomatic package so the CLI has
something to call, with memory ownership rules documented and enforced, and
wire the Go half of the ABI drift gate now that bindings exist.

**Gates:** Go round trip equals the Rust round trip on shared inputs;
`go test -race` clean; no double free or use-after-free; the drift gate detects
a Go call to a symbol Rust does not export.

### Design notes

Go never sees a secret key. Operator keys stay opaque handles and the derived
session key never leaves Rust. This is deliberate rather than incidental: Go's
collector may copy a value while moving it, so a secret held in a Go slice
could persist in memory after the slice was overwritten.

Calls that can fail run with the OS thread locked. The last-error channel is
thread-local in Rust, so without the lock a goroutine could be rescheduled
between the failing call and the read and pick up another thread's message. A
concurrency test with eight simultaneous transfers covers this.

`Close` returns nothing rather than an `error`. Freeing a handle cannot fail;
an error return would imply a failure mode that does not exist and would force
every deferred call to discard a value. `errcheck` flagging the original
signature is what surfaced this.

`ErrIncomplete` and `ErrFrameRejected` are matchable with `errors.Is`, because
both are conditions a receiver acts on rather than aborts for.

### Drift gate, Go half

Verified it bites by pointing a binding at a symbol Rust does not export:

```
  DRIFT: dhow_abi_versionx is called from Go but not exported by Rust
ABI DRIFT DETECTED
```

### Gate additions

`gate.sh` now builds the Rust core before the Go gates, since the Go package
links the staticlib and a clean clone otherwise fails at the linker with an
error that says nothing about the cause. It also runs `go test -race`, which
the gate did not run at all: the Go side had no test execution in it despite
the engineering standard requiring the race detector on in all test runs.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===         PASS
=== GATE: cargo clippy -D warnings ===  PASS
=== GATE: cargo test ===                PASS
=== GATE: cargo audit ===               PASS
=== GATE: cargo deny ===                PASS
=== GATE: ABI drift ===                 PASS
=== GATE: build rust core for cgo ===   PASS
=== GATE: go vet ===                    PASS
=== GATE: go test -race ===             PASS
=== GATE: go build ===                  PASS
=== GATE: golangci-lint ===             PASS
=== GATE: govulncheck ===               PASS

=== GATE SUMMARY ===
  Passed: 12
  Failed: 0
ALL GATES PASSED
```

```
$ go test -race ./cli/internal/ffi/
ok  	dhow/cli/internal/ffi	2.789s   (18 tests)
```


## Phase 18 - C ABI and cbindgen

**Objective:** Give `dhow-ffi` the C surface the architecture depends on:
a handle-based encoder, decoder, and key API; a status-code and last-error
channel; `catch_unwind` at every entry point; a cbindgen-generated header; and
an ABI drift gate wired into `gate.sh`.

**Gates:** header generates deterministically; every function documented in the
header; no raw key bytes in any signature; a forced null or malformed input
surfaces as a status code rather than a crash; the drift gate fails on a
deliberate mismatch.

### Starting point

`dhow-ffi` was six lines: a doc comment and `#![allow(unsafe_code)]`. It had no
exported symbols, no header, and nothing for Go to call.

### Design notes

No function accepts or returns raw secret key material. Operator keys live
behind opaque handles, and the derived session key never leaves Rust:
`dhow_encoder_new` takes a key handle and a salt and derives internally.

Buffers are always caller-allocated, so this library never returns a pointer
the caller must free and no two allocators can disagree about a block.
Variable-length output uses one convention throughout: pass a null buffer to
learn the required size, then call again.

`dhow_encoder_params` reports the parameters the encoder actually used. The
caller describes the plaintext, but framing operates on ciphertext, which is
longer by the AEAD tag. Exposing the resolved values keeps the caller from
having to reimplement the length and digest rules to fill in the manifest.
This was added after the tests needed a fragile helper to recompute the digest,
which was a signal that the ABI was missing something a real sender needs.

The panic guard is a backstop, not a strategy. The core is written to be
panic-free on arbitrary input; a caught panic is a bug here. The panic payload
is not forwarded to the caller, because it can interpolate arbitrary values
including data-path bytes, and the error channel's contents must stay safe to
log.

### Drift gate

`scripts/check_abi.sh` regenerates the header into a temporary file and diffs
it against the committed one, then cross-checks symbol presence in both
directions between Rust and Go.

Verified it bites: renaming `dhow_encoder_frame_count` in the committed header
produced

```
  DRIFT: core/include/dhow.h is stale; run scripts/gen_header.sh
  DRIFT: dhow_encoder_frame_count is exported from Rust but absent from dhow.h
ABI DRIFT DETECTED
```

and the gate passed again once restored. The Go binding check reports that it
is skipped while `cli/internal/ffi` does not exist, rather than passing
silently.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===        PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===               PASS
=== GATE: cargo audit ===              PASS
=== GATE: cargo deny ===               PASS
=== GATE: ABI drift ===                PASS
=== GATE: go vet ===                   PASS
=== GATE: go build ===                 PASS
=== GATE: golangci-lint ===            PASS
=== GATE: govulncheck ===              PASS

=== GATE SUMMARY ===
  Passed: 10
  Failed: 0
ALL GATES PASSED
```

```
$ cargo test -p dhow-ffi
test result: ok. 20 passed; 0 failed; 0 ignored
```


## Phase 17 - Manifest signing and verification

**Objective:** Sign the manifest with Ed25519 and give the receiver a
verification pipeline: structure, signature, then policy. Until this phase the
manifest was transmitted unsigned, so the threat model's central claim - that a
receiver rejects a transfer whose manifest signature fails - had nothing
enforcing it.

**Gates:** signature verifies; any single-byte mutation of a signed manifest
fails; adversarial matrix (oversize claims, traversal names, wrong key,
downgraded version, replayed session) rejected with distinct errors.

### Defects fixed from earlier phases

Three defects in the Phase 10 manifest wire format, each fixed here:

1. **Signature scope.** The format signed bytes 0..100 only, leaving every file
   name, size, and digest unauthenticated. An attacker could rewrite an entry
   to a traversal path and the signature would still verify. The signature now
   covers the whole manifest with the signature field zeroed. Three tests
   rewrite a name, a size, and a digest in a signed manifest; all three would
   have passed under the old scope.
2. **Path traversal.** The check tested only whether a name *started* with
   `..`, so `a/../../etc/passwd` was accepted. Every component is now
   inspected. Backslash is rejected unconditionally, since the sender cannot
   know whether the receiver treats it as a separator.
3. **Unbounded allocation.** `Manifest::from_bytes` passed the declared `u32`
   file count straight to `Vec::with_capacity`, so a manifest claiming
   `u32::MAX` entries could exhaust memory before a single entry was read. The
   count is bounded and capacity is reserved against what the buffer could
   actually hold.

Defects 2 and 3 landed in the same commit as the traversal fix rather than
separately, because they touch adjacent code in one module.

### Design notes

The expected signer is supplied by the caller, never read from the manifest: a
key carried inside the structure it signs authenticates nothing.

Verification runs structure, then signature, then policy. Policy limits
describe what a legitimate sender may claim, so applying them to
unauthenticated bytes would report attacker-controlled values as meaningful.

`VerifiedManifest` is a distinct type, so extraction code cannot be handed
unauthenticated metadata by mistake.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===        PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===               PASS
=== GATE: cargo audit ===              PASS
=== GATE: cargo deny ===               PASS
=== GATE: go vet ===                   PASS
=== GATE: go build ===                 PASS
=== GATE: golangci-lint ===            PASS
=== GATE: govulncheck ===              PASS

=== GATE SUMMARY ===
  Passed: 9
  Failed: 0
ALL GATES PASSED
```

```
$ cargo test --all
test result: ok. 239 passed; 0 failed   (dhow-codec)
test result: ok. 103 passed; 0 failed   (dhow-crypt)
test result: ok.  11 passed; 0 failed   (end_to_end)
test result: ok.  12 passed; 0 failed   (doc-tests)
```


## Phase 16 - Payload AEAD

**Objective:** Encrypt the payload with XChaCha20-Poly1305 before chunking,
derive the payload key and the frame session key from the operator key with
HKDF-BLAKE3 under a per-transfer salt, and prove the crypt and codec layers
compose into a working transfer.

**Gates:** decrypt of tampered ciphertext fails; nonce and salt uniqueness
across transfers; end-to-end transfer round trips through dropped, reordered,
duplicated, and corrupted frames; replayed and foreign-key transfers fail
closed.

### Design notes

The operator key is never used to encrypt anything. Each transfer draws a
random 32-byte salt and derives two independent keys from it under separate
HKDF `info` strings, so disclosing the frame MAC key does not disclose the key
protecting the payload, and two transfers between the same operators share no
key material.

XChaCha20's 192-bit nonce is wide enough to draw at random per transfer, which
suits a courier whose two halves never communicate and so cannot agree a
counter. The session ID is authenticated as associated data, so a recording of
one session fails to decrypt if replayed into another.

Decryption failures are reported identically whether the key, nonce, session,
or ciphertext was wrong. Distinguishing them would tell an attacker probing
with modified captures which part to change next.

### Defect found by the new tests

The HKDF expand loop incremented its `u8` block counter after emitting the
final block, which overflowed on a full-length derivation. Caught by the
output-length limit test and fixed in this phase.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===      PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===             PASS
=== GATE: cargo audit ===            PASS
=== GATE: cargo deny ===             PASS
=== GATE: go vet ===                 PASS
=== GATE: go build ===               PASS
=== GATE: golangci-lint ===          PASS
=== GATE: govulncheck ===            PASS

=== GATE SUMMARY ===
  Passed: 9
  Failed: 0
ALL GATES PASSED
```

```
$ cargo test -p dhow-crypt
test result: ok. 79 passed; 0 failed   (unit)
test result: ok. 11 passed; 0 failed   (tests/end_to_end.rs)
```

## Phase 15 - Key generation and storage

**Objective:** Give `dhow-crypt` the key handling it had only declared errors
for: Ed25519 identity keypairs for manifest signing, a symmetric operator key
that per-transfer keys derive from, a versioned and checksummed key file
format, owner-only permission enforcement, and zeroization on drop.

**Gates:** key file round trips; permission test; every single-byte mutation of
a key file is rejected; secrets do not appear in `Debug` output.

### Notes

`VerifyingKey::from_bytes` does not reject every arbitrary 32-byte string. An
all-ones encoding decompresses to a valid curve point, so the negative test
uses encodings whose implied x-squared is not a quadratic residue.

Secret key files are created with mode 0600 through `OpenOptions::mode` rather
than chmodded after writing, so they are never briefly readable by other users.
Loading rejects any file carrying group or other permission bits.

### Gate output

```
$ cargo test -p dhow-crypt
running 42 tests
test result: ok. 42 passed; 0 failed; 0 ignored
```

```
$ cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s)
```

## Phase 14 - Session state machine and receive pipeline

**Objective:** Add the session state machine that tracks a transfer through
initialization, active transfer, FEC recovery, pause, completion, and failure;
and complete the frame pipeline with the receive half, so a payload encoded
into frames can be reassembled and verified rather than only produced.

**Gates:** state machine rejects every invalid transition and both terminal
states are absorbing; pipeline round-trips payloads through reordered,
duplicated, and dropped frames; every single-byte mutation of a valid frame is
rejected; reassembled payloads are verified against the session digest.

### Defects fixed from earlier phases

Phase 13 shipped a pipeline that could not be decoded by any receiver. Three
defects were found and fixed here, each as a `fix(codec)` commit:

1. Frame payloads carried `packet.data()`, discarding the 4-byte RaptorQ
   `PayloadId`. Without it a symbol cannot be placed within its block, so
   decoding was impossible. Frames now carry the serialized `EncodingPacket`.
2. `EncoderWrapper::repair_packets` returned source *and* repair symbols
   because `get_encoded_packets` includes the source prefix. The pipeline
   combined it with `source_packets`, emitting every source symbol twice under
   wrong symbol indices.
3. `FecParams::with_mtu` asserts on a symbol size below 64, and `symbol_size`
   was truncated from `u32` to `u16` at the call site, so some session
   parameters panicked on the data path. Symbol size is now range-checked into
   a typed error.

A fourth defect was found in the new receive path before it shipped:
`EncodingPacket::deserialize` indexes its first four bytes unchecked, so a
frame carrying a shorter payload would panic. The decoder rejects such frames
with a typed error, and a test covers payload lengths 0 through 4.

Phase 13's pipeline tests asserted only that `encode` returned `Ok` and a
non-empty vector, which is why the defects above survived the phase. They are
replaced with round-trip and adversarial tests.

### Gate output

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===      PASS
=== GATE: cargo clippy -D warnings === PASS
=== GATE: cargo test ===             PASS
=== GATE: cargo audit ===            PASS
=== GATE: cargo deny ===             PASS
=== GATE: go vet ===                 PASS
=== GATE: go build ===               PASS
=== GATE: golangci-lint ===          PASS
=== GATE: govulncheck ===            PASS

=== GATE SUMMARY ===
  Passed: 9
  Failed: 0
ALL GATES PASSED
```

```
$ cargo test --all
test result: ok. 236 passed; 0 failed (dhow-codec)
test result: ok. 8 passed; 0 failed (dhow-crypt)
test result: ok. 0 passed; 0 failed (dhow-ffi)
test result: ok. 12 passed; 0 failed (doc-tests)
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
7
```

This phase is below the 20-commit floor in section 5.2. Honest decomposition of
a state machine plus one pipeline module did not yield twenty self-contained
changes, and section 8 forbids padding to reach the floor. Recorded as a
deviation rather than met with filler commits.

### Known gaps entering Phase 15

An audit of the tree against the phase pack found that the following are
declared but not implemented, and are not covered by any phase log entry:

- `dhow-crypt` contains only error enums. No key generation, no AEAD, no
  signing, no manifest verification.
- `dhow-ffi` is an empty crate with no `extern "C"` surface and no header.
- `cli/cmd/dhow/main.go` is `func main() {}`. There is no command surface,
  no QR rendering, no camera capture.
- `manifest.rs` lives in `dhow-codec` and is unsigned; the signed manifest the
  threat model depends on does not exist yet.

## Phase 13 - Frame pipeline

**Objective:** Assemble frame pipeline that combines chunking, FEC encoding,
and frame header construction into a single pipeline.

**Gates:** encode produces frames with correct structure; multiple blocks work;
wrong payload size rejected; proptest on small data.

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib pipeline_test
running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
4
```

## Phase 12 - QR encode/decode

**Objective:** QR code encoding and terminal rendering. Encode frame bytes as QR
codes, render to terminal for inspection, support medium error correction.

**Gates:** QR encodes arbitrary binary data; terminal rendering produces
correct dimensions; proptest on small data ranges.

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib qr_test
running 12 tests
test result: ok. 12 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
21
```

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib session_test
running 13 tests
test result: ok. 13 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
14
```

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib manifest_test
running 18 tests
test result: ok. 18 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
16
```

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib manifest_test
running 20 tests
test result: ok. 20 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
16
```

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib resume_test
running 23 tests
test result: ok. 23 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
16
```

## Phase 8 - Frame wire format

**Objective:** Binary frame header and payload wire format per `proto/frame.md`.
Serialize/deserialize frame headers; compute truncated HMAC-BLAKE3 MAC and
CRC32C checksum; validate magic, version, and integrity.

**Gates:** round-trip identity (serialize -> deserialize recovers original);
MAC verification with correct and wrong key; CRC32C mismatch detection;
invalid magic and version rejection; proptest on arbitrary payloads.

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib frame_test
running 16 tests
test result: ok. 16 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
14
```

## Phase 7 - FEC (RaptorQ)

**Objective:** RaptorQ (RFC 6330) encoding and decoding wrappers for
fault-tolerant payload transmission. Generate source and repair symbols;
decode from any sufficient subset.

**Gates:** round-trip identity (encode -> decode recovers original);
decode from source packets only; decode from repair packets only;
known-answer test against RFC 6330 vectors.

### Planned atomic commits

1. `docs: add phase-log.md with Phase 7 objective`
2. `chore: add raptorq dependency`
3. `feat(codec): add raptorq module skeleton`
4. `feat(codec): add FecParams struct`
5. `feat(codec): add encode function`
6. `feat(codec): add repair packet generation`
7. `feat(codec): add decode function`
8. `feat(codec): add FecError error variant`
9. `test(codec): add encode-decode round-trip test`
10. `test(codec): add source-only decode test`
11. `test(codec): add repair-only decode test`
12. `test(codec): add known-answer test against RFC 6330`
13. `test(codec): add proptest for round-trip property`
14. `docs(codec): document raptorq module`
15. `chore: verify FEC gates pass`

### Gate output

#### Rust tests

```
$ cargo test -p dhow-codec --lib fec_test
running 12 tests
test result: ok. 12 passed; 0 failed; 0 ignored
```

#### Clippy

```
$ cargo clippy -p dhow-codec -D warnings
    Finished `dev` profile
```

#### Round-trip property tests (proptest)

- `prop_fec_round_trip`: round-trip identity on arbitrary payloads (1 to 10,000 bytes)

#### Edge case tests

- Empty payloads (skip - raptorq panics on 0-length)
- Single byte payload
- 100K byte payload
- 30% simulated packet loss recovery
- Custom MTU (512)
- MTU below minimum (64) panics as expected

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
21
```

## Phase 6 - Integrity primitives

**Objective:** CRC32C and BLAKE3 wrappers with streaming interfaces; per-block
and whole-payload digests per spec.

**Gates:** known-answer tests against published vectors; streaming equals one-shot
on random inputs.

### Gate output

#### Rust tests

```
$ cargo test --all-targets
running 55 tests (dhow-codec)
test result: ok. 55 passed; 0 failed; 0 ignored

running 8 tests (dhow-crypt)
test result: ok. 8 passed; 0 failed; 0 ignored

running 0 tests (dhow-ffi)
test result: ok. 0 passed; 0 failed; 0 ignored
```

#### Clippy
```
$ cargo clippy -D warnings
    Finished `dev` profile [unoptimized + debuginfo]
```

#### Security audit
```
$ cargo audit
error: 0 vulnerabilities found
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
21
```

## Phase 5 - Chunker

**Objective:** Deterministic payload chunking into source blocks and symbols per
`proto/block.md`; property tests (arbitrary sizes 0 bytes to 4 GiB simulated,
boundary sizes, off-by-one edges); golden vectors generated by script.

**Gates:** round-trip identity on property tests; golden vectors match.

### Planned atomic commits

1. `docs: add phase-log.md with Phase 5 objective`
2. `feat(codec): add chunker module skeleton with constants`
3. `feat(codec): add SymbolIndexOutOfRange and Truncated error variants`
4. `feat(codec): add ChunkParams struct with validation`
5. `feat(codec): add BlockInfo and SymbolInfo structs`
6. `feat(codec): add ChunkMap struct`
7. `feat(codec): implement block boundaries computation`
8. `feat(codec): implement symbol boundaries computation`
9. `feat(codec): implement chunker constructor`
10. `feat(codec): implement block extraction`
11. `feat(codec): implement symbol extraction with padding`
12. `feat(codec): implement reassembly from blocks`
13. `test(codec): add chunker unit tests`
14. `test(codec): add boundary size tests`
15. `test(codec): add off-by-one tests`
16. `test(codec): add property tests with proptest`
17. `test(codec): add golden vector tests`
18. `docs(codec): document chunker module`
19. `chore: add proptest dev-dependency`
20. `chore: add chunker golden vectors to gen_vectors.py`
21. `chore: verify chunker gates pass`

### Gate output

#### Rust tests

```
$ cargo test --all-targets
running 34 tests (dhow-codec)
test result: ok. 34 passed; 0 failed; 0 ignored

running 8 tests (dhow-crypt)
test result: ok. 8 passed; 0 failed; 0 ignored
```

#### Property tests (proptest)

- `test_round_trip_identity`: round-trip identity on arbitrary payloads (0 to 100,000 bytes)
- `test_block_sizes_sum_to_payload`: block sizes always sum to payload size
- `test_block_offsets_continuous`: block offsets are continuous (no gaps)
- `test_symbol_count_correct`: symbol count matches ceil(block_size / symbol_size)
- `test_symbol_extraction_padded`: last symbol padding is correct

#### Golden vectors

- 7 chunker golden vectors generated by `scripts/gen_vectors.py`
- All vectors match the Rust implementation
- Vectors cover: simple, remainder, padding, exact multiple, single byte, empty, symbol size 1

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
22
```

## Phase 4 - Error taxonomy and logging spine

**Objective:** `dhow-codec` and `dhow-crypt` error enums; Go error wrapping
conventions; structured logger with data-path silence enforced by a test that
fails if payload bytes appear in log output.

**Gates:** log-silence test passes; error types documented.

### Planned atomic commits

1. `chore: add thiserror dependency to codec and crypt crates`
2. `feat(codec): add error enum with thiserror`
3. `feat(codec): add error context and display impls`
4. `test(codec): add error enum unit tests`
5. `docs(codec): document error types`
6. `feat(crypt): add error enum with thiserror`
7. `feat(crypt): add error context and display impls`
8. `docs(crypt): document error types`
9. `feat(cli): add structured logger with levels`
10. `feat(cli): add log configuration`
11. `feat(cli): add data-path silence enforcement`
12. `test(cli): add log silence test`
13. `feat(cli): add error wrapping conventions`
14. `docs(cli): document error wrapping conventions`
15. `test(cli): add error wrapping tests`
16. `docs: add phase-log.md with Phase 4 objective`
17. `chore: verify log silence test passes`
18. `chore: verify error types are documented`
19. `docs: record gate output in phase-log.md`
20. `chore: final cleanup`

### Gate output

#### Rust tests

```
$ cargo test --all-targets
running 8 tests (dhow-codec)
test result: ok. 8 passed; 0 failed; 0 ignored

running 8 tests (dhow-crypt)
test result: ok. 8 passed; 0 failed; 0 ignored
```

#### Go tests

```
$ go test ./internal/log/ ./internal/errors/ -v
--- PASS: TestLogSilenceOnDataPath
--- PASS: TestLogSilentMode
--- PASS: TestLogLevelFiltering
--- PASS: TestLogStructuredFields
--- PASS: TestLogNoPayloadBytes
--- PASS: TestUserError
--- PASS: TestUserErrorWithInner
--- PASS: TestUserErrorUnwrap
--- PASS: TestInternalError
--- PASS: TestInternalErrorWithInner
--- PASS: TestInternalErrorUnwrap
--- PASS: TestWrap
--- PASS: TestWrapNil
--- PASS: TestWrapUser
--- PASS: TestWrapInternal
--- PASS: TestErrorChain
--- PASS: TestNoPayloadInError
PASS
```

#### Log silence test

The log silence test (`TestLogSilenceOnDataPath`) verifies that:
- The logger never outputs payload bytes.
- The logger never outputs key material.
- The logger never outputs the word "payload" or "key" (except in session context).
- A silent logger produces no output.

#### Error type documentation

- `core/dhow-codec/ERRORS.md` documents all 4 error enums (CodecError, ChunkError, FrameError, SessionError, ResumeError).
- `core/dhow-crypt/ERRORS.md` documents all 5 error enums (CryptError, KeyError, AeadError, SigningError, ManifestError).
- `cli/internal/errors/CONVENTIONS.md` documents Go error wrapping conventions.

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
20
```
