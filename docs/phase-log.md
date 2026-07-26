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

(To be filled in by the final commit.)
