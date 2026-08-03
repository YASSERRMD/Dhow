# Dhow Threat Model (v1)

> Version 1 - audited in Phase 32. Every control below is traced to a named
> test or gate in the [traceability table](#traceability), or recorded there as
> unenforced.

## Scope

Dhow moves a dataset between two air-gapped networks by encoding it as a
fountain-coded stream of QR frames. The sender renders frames on a screen; the
receiver captures them with a camera, decodes, verifies, and reassembles.

**Trust boundary:** The optical channel is fully public and fully hostile.
Neither the camera feed, the screen recording, nor the QR frames are trusted.

## Assets

| Asset | Held by | Description |
|-------|---------|-------------|
| Plaintext payload | both | The original dataset being transferred |
| Operator key | **both operators** | A long-term 32-byte symmetric secret. Encrypts the payload and authenticates frames. Because both sides hold it, it cannot answer *who* produced a transfer. |
| Identity key | **the sender only** | A long-term Ed25519 signing key. Signs the manifest, and is what answers "who produced this". |
| Public identity | both | The identity's public half. Not secret, but its **integrity** matters: a receiver given the wrong one verifies transfers from whoever holds the matching secret. |
| Transfer keys | neither, transiently | Payload and session keys derived per transfer from the operator key and a fresh salt. Never leave Rust. |
| Manifest | both | Signed metadata: file names, sizes, digests, executable bits, salt, nonce, and coding parameters |
| Resume state | receiver | Receiver progress on disk. Holds no key material. |
| Frame stream | public | QR codes rendered on a screen anyone can watch |

Until Phase 32 this table described the operator key as "Long-term identity key
(Ed25519)", conflating the two secrets that Phase 28 separated - and describing
a symmetric key as an asymmetric one. That is the kind of error an audit exists
to find: every control built on the distinction was correct, and the document
readers rely on was not.

## Attack Surfaces

### 1. Hostile frames (malformed, corrupted, replayed)

An attacker controls the optical channel. They may:

- Render frames from a different session (cross-session injection).
- Replay frames from a previous transfer of a different payload.
- Truncate, reorder, or duplicate frames.
- Corrupt frame payloads (bit flips, truncation).
- Render frames with oversized declared lengths to cause OOM.
- Render frames with invalid magic bytes or version numbers.

**Controls:**
- Per-frame CRC32C for fast reject of corrupted frames.
- Session binding: each frame carries a truncated MAC binding it to the session.
- Frame parser is adversarial: never panics on any input.
- Decoder rejects frames from foreign sessions.
- Length fields are validated before any allocation.

### 2. Shoulder-surfing of the screen

An attacker observes the screen during transfer and may capture partial data.

**Controls:**
- Payload is encrypted before encoding; screen shows only ciphertext symbols.
- Session fingerprint displayed so operators can visually verify sender/receiver match.

### 3. Replayed recordings of a previous transfer

An attacker records a previous transfer and replays it to the receiver.

**Controls:**
- Session ID is random per transfer; replayed frames from a different session are rejected.
- Manifest is signed; a replayed manifest must have been signed by the legitimate operator key.
- Receiver must verify the manifest signature before accepting any data.

### 4. Tampered resume state

An attacker with write access to the receiver's state directory modifies the
saved progress - the journal of accepted frames, the index over it, or both -
to poison the reassembly that follows a restart.

**Controls:**
- Every frame replayed from the journal is re-authenticated against the session
  key: MAC, CRC, session binding, and symbol bounds, exactly as on first
  capture. This is the control that matters. The state directory holds no key
  material, so an attacker who can rewrite these files still cannot produce a
  frame the decoder will accept.
- The index carries a CRC32C and a BLAKE3 integrity digest, and is rejected on
  any mismatch. These catch corruption, not forgery: an attacker who can
  rewrite the file can recompute both.
- The index is bound to the journal by a digest over the accepted frames in
  acceptance order, and by the journal length it covers. A journal that is
  truncated, reordered, extended, or substituted no longer reproduces it.
- The index names its own session, and a state belonging to another transfer is
  refused before any replay begins.
- Every one of these failures is fail-closed: the receiver stops and tells the
  operator to discard the state, rather than resuming from whatever survived.

**Residual risk:** an attacker with write access to the state directory can
delete it, costing the operator the frames captured so far. There is no defence
against that at this layer, and the cost is bounded by re-running the capture.

### 5. Malicious datasets (zip bombs, path traversal)

An attacker crafts a dataset with:

- Zip bombs (extreme compression ratios causing resource exhaustion).
- Path traversal in file names (`../../etc/passwd`).
- Symlinks or special files.

**Controls:**
- File names are sanitized against traversal before packaging.
- Zip-bomb limits enforced (max uncompressed size, max ratio).
- Archive is deterministic (sorted entries, fixed metadata, no timestamps).
- Extraction is traversal-safe.

### 6. Compromised receiver storage

An attacker with write access to the receiver's storage may:

- Modify received files after transfer.
- Tamper with the manifest or resume state.

**Controls:**
- `dhow verify` re-checks all file digests against the signed manifest.
- Manifest signature must verify; any tampering is detected.

**Residual risk: the trust anchor is a file on that storage.** `verify` checks
the signature against the `sender.pub` it is handed. An attacker who can
rewrite the dataset *and* substitute that file verifies successfully against a
key they hold. Nothing in the tool can close this; the control is the operator
comparing the fingerprint out of band when the key first arrives, and keeping
the key somewhere the dataset's own storage cannot reach. See
[VERIFY.md](VERIFY.md).

## What the manifest signature covers

Since the manifest was wired through the CLI (Phase 28), a receiver reads
*nothing* out of a transfer before checking its signature. The signed structure
carries:

| Field | Why it is signed |
|-------|------------------|
| File inventory: names, sizes, digests, executable bits | Signing only the fixed header would let an attacker rewrite an entry to a traversal path without disturbing the signature. |
| Payload digest | Binds the manifest to the bytes that were encoded. |
| Session id | With the binding check, stops a correctly signed manifest from an earlier transfer between the same operators being replayed into this one. |
| Salt and nonce | Public by design, but public is not the same as unauthenticated. Under the unsigned record a substituted nonce produced a decryption failure — fail-closed, but reporting the wrong cause. |
| Coding parameters | Inputs to the transfer. An input nobody signed is an input an attacker can choose. |

The two keys answer different questions and neither substitutes for the other:

- The **operator key** is symmetric and held by both sides. It answers "was
  this produced by someone in the group", and cannot answer "which one",
  because either side could have produced any transfer made with it.
- The **identity key** is held only by the sender. It answers "which one".

A deployment that skips the identity and relies on the operator key alone has a
receiver that cannot distinguish a transfer the sender made from one the
receiver made, which matters as soon as more than two machines hold the key.

## Traceability

Every claim this document makes is one of two things: something a named test or
gate enforces on every run, or something a person checked once. Both are
legitimate; conflating them is not, and this table exists so the difference is
visible without reading the code.

The Status column has exactly three values:

- **Enforced** - a named test or gate fails if the control is removed. The
  Evidence column names it precisely enough to run.
- **Review** - the property holds by construction or was verified by reading the
  code, and nothing would fail if it stopped holding. These are the rows that
  deserve attention.
- **Absent** - the control described in an earlier version of this document does
  not exist.

Before this audit the Status column read "Planned (Phase 15)" against work that
had shipped in Phase 15, and similar for eleven other rows. That is worse than
an empty column, because it was relied upon.

### Cryptography

| # | Claim | Status | Evidence |
|---|-------|--------|----------|
| 1 | Payload is encrypted before encoding | Enforced | `dhow-crypt` `aead_test::test_ciphertext_does_not_contain_the_plaintext`, `property_test::aead_round_trips` |
| 2 | Tampered ciphertext fails rather than decrypting differently | Enforced | `property_test::any_altered_byte_fails_to_decrypt` (every byte, strategy-chosen) |
| 3 | Payload key and session key are distinct | Enforced | `property_test::the_two_derived_keys_differ`, `aead_test::test_payload_and_session_keys_differ` |
| 4 | Derivation is deterministic from key and salt | Enforced | `property_test::derivation_is_deterministic` |
| 5 | A different salt derives different keys | Enforced | `property_test::a_different_salt_derives_different_keys` |
| 6 | Manifest is signed with Ed25519 | Enforced | `crypt::manifest_test::test_signed_manifest_verifies`, `property_test::a_signed_manifest_verifies` |
| 7 | Any single-byte change to a manifest fails verification | Enforced | `property_test::any_altered_byte_fails_verification`, `ffi_test::any_altered_byte_fails_verification` |
| 8 | Signing is deterministic | Enforced | `property_test::signing_is_deterministic` |
| 9 | No secret-dependent branching in `dhow-crypt` | **Review** | Constant-time comparison is used where this crate compares secrets (`subtle::ConstantTimeEq` in `key.rs:139` and `key.rs:296`); everything else is delegated to RustCrypto primitives. **Nothing tests this.** A future comparison written with `==` would pass every gate. |

### Keys

| # | Claim | Status | Evidence |
|---|-------|--------|----------|
| 10 | Key material zeroized on drop | **Review** | `Drop` impls call `zeroize()` in `key.rs:104`, `key.rs:191`, `aead.rs:112`. **Nothing tests it**: observing that a dropped buffer was overwritten needs reading freed memory, which is exactly what this project will not write. A drop impl deleted by accident would pass every gate. |
| 11 | Key files are written 0600 | Enforced | `key_test::test_saved_secret_key_is_owner_only`, `test_saving_over_a_permissive_file_tightens_permissions` |
| 12 | A group- or world-readable key is refused | Enforced | `key_test::test_loading_rejects_group_or_world_readable_key`; end to end by `scripts/drill.sh` |
| 13 | The two key kinds are not interchangeable | Enforced | `key_test::test_loading_rejects_wrong_key_kind`, `cli_test::TestSendRefusesAnOperatorKeyAsAnIdentity` |
| 14 | Key material never crosses the FFI as raw bytes | **Review** | No `extern "C"` signature in `handle.rs` takes or returns key bytes; keys are `DhowKey`/`DhowIdentity` handles. `scripts/check_abi.sh` compares the three views of the ABI but does **not** check this property. A future function taking a `*const u8` key would pass. |
| 15 | `Debug` never reveals key material | Enforced | `property_test::debug_output_never_contains_key_material` (any four consecutive secret bytes, over arbitrary keys), `key_test::test_debug_does_not_reveal_operator_key` |
| 16 | Error messages never contain key material | Enforced | `key_test::test_key_errors_do_not_contain_key_material`, `ffi_test::test_error_messages_carry_no_key_material` |
| 17 | Logs never contain payload bytes or key material | Enforced | `cli/internal/log` `TestLogSilenceOnDataPath`, `TestLogNoPayloadBytes` |

### Frames and the optical channel

| # | Claim | Status | Evidence |
|---|-------|--------|----------|
| 18 | Per-frame CRC32C rejects corruption | Enforced | `frame_test::test_frame_crc_mismatch`, `pipeline_property_test::every_single_byte_mutation_of_a_frame_is_rejected` |
| 19 | Frames are bound to their session by a MAC | Enforced | `pipeline_test::test_decoder_rejects_frame_from_another_session`, `pipeline_property_test::no_frame_from_another_session_is_accepted` (arbitrary session ids) |
| 20 | Frames are bound to the session key | Enforced | `pipeline_property_test::no_frame_under_another_key_is_accepted` |
| 21 | Per-block BLAKE3 verifies a decode | Enforced | `pipeline_test::test_finish_rejects_payload_that_fails_its_digest` |
| 22 | Whole-payload BLAKE3 travels in the signed manifest | Enforced | `ffi_test::a_manifest_round_trips_its_whole_inventory` (payload digest compared), `crypt::property_test` manifest group |
| 23 | The frame parser never panics on any input | Enforced | `fuzz/fuzz_targets/frame_decode.rs`, 376M executions in Phase 29; replayed on stable by `dhow-codec::replay_test::frame_header_seeds_round_trip` |
| 24 | A corrupt frame does not poison a decode | Enforced | `pipeline_property_test::a_corrupt_frame_never_poisons_the_decode`, `scripts/loopback.sh` |
| 25 | Length fields are bounded before they drive an allocation | Enforced | `manifest.rs` capacity bound, exercised by `fuzz/fuzz_targets/manifest_verify.rs` and `resume_load.rs` |
| 26 | Duplicated and reordered frames change nothing | Enforced | `pipeline_property_test::duplicates_do_not_help_or_harm`, `frame_order_does_not_change_the_result` |
| 27 | A shoulder-surfer sees only ciphertext | Review | Follows from row 1: the renderer is handed frames the encoder produced, and the encoder encrypts before framing. No test photographs a screen. |

### Manifest and extraction

| # | Claim | Status | Evidence |
|---|-------|--------|----------|
| 28 | File names are sanitized against traversal | Enforced | `manifest_test::test_file_entry_rejects_traversal_in_any_component`, `pack_test::TestValidateNameRejectsTraversal`, `TestExtractRejectsTraversalEntry`, `ffi_test::a_traversal_name_never_reaches_a_verified_manifest`, and `fuzz/fuzz_targets/manifest_entry.rs` asserting the rules independently of `validate_name` |
| 29 | Extraction is bounded against a bomb | Enforced | `pack_test::TestExtractRejectsAbsurdEntryCount`, `TestExtractRejectsOversizedDeclaredFile`, `TestExtractRejectsTruncatedBody` |
| 30 | Extraction never overwrites or follows a symlink | Enforced | `pack_test::TestExtractRefusesToOverwriteExistingFile` (`O_EXCL`), `TestSymlinksAreSkipped` |
| 31 | The archive is deterministic | Enforced | `pack_test::TestArchiveIsDeterministic`, `TestArchiveIgnoresTimestamps`, `TestEntriesAreSortedByName` |
| 32 | A receiver reads nothing from an unverified manifest | Enforced | `cli_test::TestRecvRejectsAManifestSignedByAnotherIdentity`, `TestEveryManifestByteIsUnderTheSignature` (exhaustive), `scripts/loopback.sh` |
| 33 | The archive is reconciled against the signed inventory | Enforced | `cli.go` `reconcile`, exercised on every `recv` in `scripts/loopback.sh` and `scripts/chaos.sh` |
| 34 | A manifest accounts for every byte it was parsed from | Enforced | `manifest_test::trailing_bytes_after_the_last_entry_are_rejected` (found in Phase 29) |

### Resume state

| # | Claim | Status | Evidence |
|---|-------|--------|----------|
| 35 | Replayed frames are re-authenticated, not trusted | Enforced | `pipeline_test::test_resume_rejects_a_replay_that_lost_a_frame`, `test_resume_rejects_a_replay_in_a_different_order` |
| 36 | The index is bound to its journal | Enforced | `pipeline_test::test_journal_digest_reproduces_on_replay_and_notices_any_change`; end to end in `scripts/loopback.sh` (both halves tampered, exit 2) |
| 37 | State from another session is refused | Enforced | `pipeline_test::test_resume_rejects_state_from_another_session` |
| 38 | State for a different block layout is refused | Enforced | `pipeline_test::test_resume_rejects_state_for_a_different_block_layout` |
| 39 | The resume parser never panics | Enforced | `fuzz/fuzz_targets/resume_load.rs`, 648M executions in Phase 29 |
| 40 | Every resume failure is fail-closed | Enforced | `scripts/loopback.sh` asserts exit 2 and no output for both tamper cases |

### Build and supply chain

| # | Claim | Status | Evidence |
|---|-------|--------|----------|
| 41 | `cargo audit` and `cargo deny` run | Enforced | `scripts/gate.sh`, `.github/workflows/ci.yml` |
| 42 | `govulncheck` runs | Enforced | `scripts/gate.sh`, CI |
| 43 | `golangci-lint` runs with a committed config | Enforced | `scripts/gate.sh`, `.golangci.yml` |
| 44 | `unsafe` appears only in `dhow-ffi` | Enforced | `#![forbid(unsafe_code)]` in `dhow-codec` and `dhow-crypt` is a compile error, not a lint; confirmed independently by `cargo geiger` (below) |
| 45 | Every FFI entry point catches unwinds | Review | Every `extern "C"` body in `handle.rs` is wrapped in `guard` or `guard_ptr`. `ffi_test` covers null handling at each entry point but does not force a panic through each one. |
| 46 | No network calls in the data path | **Absent** | Nothing checks this. `cargo deny` checks licenses, advisories, and duplicate versions - not sockets. The dependency list contains no networking crate, which was verified by reading it, and nothing would notice if one were added. |
| 47 | The gate bites when a control is removed | Enforced, partially | Demonstrated in-phase for the fuzz targets (Phase 29), the differential harness (Phase 30), and the conformance suite (Phase 29). Not demonstrated for every gate; the Phase 2 lint-gate demonstration was a one-off and is not re-run. |

### Gaps, restated

Six rows are not enforced by anything: **9** (no secret-dependent branching),
**10** (zeroization), **14** (no raw keys across the ABI), **27**
(shoulder-surfing), **45** (unwind guards at every entry point), and **46** (no
network calls). Of those:

- **10 and 27 are probably not testable** in a way worth having. Observing a
  zeroized buffer means reading freed memory, and photographing a screen is not
  a unit test.
- **9, 14, 45, and 46 are testable** and are not tested. Each is a lint or a
  source-level check over a small surface: a scan for `==` on secret types, a
  scan of `extern "C"` signatures for pointer-shaped key arguments, a scan for a
  `guard` wrapper in every entry point, and a dependency-name denylist. They are
  recorded in `docs/BACKLOG.md` as **B-9**.

## `cargo geiger`

Run from `core/dhow-ffi`, which pulls in the whole tree:

```
Functions  Expressions  Impls  Traits  Methods  Dependency

51/51      1020/1066    0/0    0/0     0/0      !  dhow-ffi 0.1.0
0/0        0/0          0/0    0/0     0/0      :) |-- dhow-codec 0.1.0
0/0        0/0          0/0    0/0     0/0      :) `-- dhow-crypt 0.1.0
```

This is the architecture the master spec fixes, confirmed by a tool rather than
asserted: **zero unsafe expressions in `dhow-codec` and `dhow-crypt`**, and all
of it in `dhow-ffi`, where the ABI requires it.

The `dhow-ffi` count is large because every `extern "C"` function that
dereferences a caller pointer is `unsafe fn`, and each carries a `// SAFETY:`
comment naming the precondition it relies on. The count is a fact about the
shape of a C ABI, not a measure of risk on its own - which is why B-7 (no fuzz
target reaches `dhow-ffi`) is the more useful thing to act on.

The full dependency tree carries 91/336 unsafe functions and 3336/13774 unsafe
expressions, almost all of it in `libc`, `generic-array`, `curve25519-dalek`,
and `zeroize`. Those are the audited primitives the spec requires be used rather
than reimplemented, and their `unsafe` is the price of that decision.

## Open Questions

- Should the screen display be rate-limited to prevent optical side-channel attacks?
- Should there be a maximum total transfer time to limit exposure?
- How to handle camera autofocus hunting on QR codes?
