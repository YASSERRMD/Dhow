# Dhow Threat Model (v0)

> Version 0 - initial draft, Phase 2

## Scope

Dhow moves a dataset between two air-gapped networks by encoding it as a
fountain-coded stream of QR frames. The sender renders frames on a screen; the
receiver captures them with a camera, decodes, verifies, and reassembles.

**Trust boundary:** The optical channel is fully public and fully hostile.
Neither the camera feed, the screen recording, nor the QR frames are trusted.

## Assets

| Asset | Description |
|-------|-------------|
| Plaintext payload | The original dataset being transferred |
| Encryption key | Derived per-transfer from the operator key |
| Operator key | Long-term identity key (Ed25519) |
| Manifest | Signed metadata: file names, sizes, digests, coding parameters |
| Resume state | Receiver progress on disk |
| Frame stream | QR codes rendered on screen |

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

## Security Requirements Checklist

| # | Requirement | Status |
|---|-------------|--------|
| 1 | Payload encrypted before encoding (XChaCha20-Poly1305) | Planned (Phase 14) |
| 2 | Manifest signed with Ed25519 | Planned (Phase 15) |
| 3 | Per-frame CRC32C for fast reject | Planned (Phase 7) |
| 4 | Per-block BLAKE3 for decode verification | Planned (Phase 6) |
| 5 | Whole-payload BLAKE3 in signed manifest | Planned (Phase 6) |
| 6 | Frames bound to session via truncated MAC | Planned (Phase 11) |
| 7 | Key material zeroized on drop | Planned (Phase 13) |
| 8 | Key material never crosses FFI as raw bytes | Planned (Phase 18) |
| 9 | No secret-dependent branching in dhow-crypt | Planned (Phase 14) |
| 10 | Parser never panics on adversarial input | Planned (Phase 8) |
| 11 | FFI catches panics, translates to error codes | Planned (Phase 19) |
| 12 | cargo audit and cargo deny in CI | Done (Phase 2) |
| 13 | govulncheck in CI | Done (Phase 2) |
| 14 | golangci-lint in CI | Done (Phase 2) |
| 15 | No network calls in data path | Enforced (no deps with sockets) |
| 16 | File names sanitized against traversal | Planned (Phase 29) |
| 17 | Zip-bomb limits | Planned (Phase 29) |
| 18 | Resume state integrity digest | Done (Phase 12) |
| 18a | Replayed journal frames re-authenticated | Done (Phase 24) |
| 18b | Resume index bound to its journal by digest and length | Done (Phase 24) |
| 18c | Resume state from a foreign session refused | Done (Phase 24) |
| 19 | Deterministic archive | Planned (Phase 29) |
| 20 | `dhow verify` for post-transfer verification | Planned (Phase 30) |
| 21 | Gate bites test (deliberate lint error caught) | Done (Phase 2) |
| 22 | Threat model reviewed against section 3 checklist | Done (Phase 2) |

## Open Questions

- Should the screen display be rate-limited to prevent optical side-channel attacks?
- Should there be a maximum total transfer time to limit exposure?
- How to handle camera autofocus hunting on QR codes?
