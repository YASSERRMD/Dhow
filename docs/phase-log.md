# Phase Log

## Phase 2 - CI, lint gates, and threat model v0

**Objective:** CI pipeline running fmt, clippy `-D warnings`, golangci-lint, tests,
`cargo audit`, `cargo deny`, `govulncheck`; `docs/THREAT-MODEL.md` v0 covering the
attack surfaces in section 3.

**Gates:** CI green on a deliberately-introduced-then-fixed lint error (prove the
gate bites); threat model reviewed against section 3 checklist.

### Planned atomic commits

1. `chore(ci): add CI workflow with all gate jobs`
2. `chore: add cargo-deny configuration`
3. `chore: add golangci-lint configuration`
4. `docs: add THREAT-MODEL.md v0`
5. `docs: add phase-log.md with Phase 2 objective`
6. `chore: add dependabot configuration`
7. `chore: add CONTRIBUTING.md`
8. `chore: add CODEOWNERS`
9. `chore: add .github/PULL_REQUEST_TEMPLATE.md`
10. `chore: add SECURITY.md`
11. `chore: add .cargo/config.toml`
12. `chore: update Makefile with CI targets`
13. `test: introduce deliberate lint error to prove gate bites`
14. `fix: resolve deliberate lint error`
15. `chore: verify cargo audit passes`
16. `chore: verify cargo deny passes`
17. `chore: verify golangci-lint passes`
18. `chore: verify govulncheck passes`
19. `docs: update threat model with checklist`
20. `docs: record gate output in phase-log.md`

### Gate output

#### Gate bites test

Deliberate lint error introduced in `core/dhow-codec/src/lib.rs`:

```rust
fn deliberate_lint_error() {
    let x = 1;
}
```

Result - gate caught it:

```
=== GATE: cargo clippy -D warnings ===
error: unused variable: `x`
 --> dhow-codec/src/lib.rs:9:9
  |
9 |     let x = 1;
  |         ^ help: if this is intentional, prefix it with an underscore: `_x`

error: function `deliberate_lint_error` is never used
 --> dhow-codec/src/lib.rs:8:4
  |
8 | fn deliberate_lint_error() {
  |    ^^^^^^^^^^^^^^^^^^^^^

GATES FAILED
EXIT CODE: 1
```

After fix (removing the function), gate passes.

#### Full gate run

```
$ ./scripts/gate.sh
=== GATE: cargo fmt --check ===
  PASS
=== GATE: cargo clippy -D warnings ===
  PASS
=== GATE: cargo test ===
  PASS
=== GATE: cargo audit ===
    Scanning Cargo.lock for vulnerabilities (3 crate dependencies)
  PASS
=== GATE: cargo deny ===
advisories ok, bans ok, licenses ok, sources ok
  PASS
=== GATE: go vet ===
  PASS
=== GATE: go build ===
  PASS
=== GATE: golangci-lint ===
0 issues.
  PASS
=== GATE: govulncheck ===
No vulnerabilities found.
  PASS
=== GATE SUMMARY ===
  Passed: 9
  Failed: 0
ALL GATES PASSED
```

### Atomic commit count

```
$ git log --oneline main..HEAD | wc -l
22
```

### Threat model review

`docs/THREAT-MODEL.md` v0 covers all attack surfaces from section 3:
- Hostile frames (malformed, corrupted, replayed) - controls: CRC32C, session binding, adversarial parser
- Shoulder-surfing of the screen - controls: encryption, session fingerprint
- Replayed recordings - controls: random session ID, signed manifest
- Tampered resume files - controls: integrity digest, typed error rejection
- Malicious datasets (zip bombs, path traversal) - controls: sanitization, limits
- Compromised receiver storage - controls: `dhow verify`
