# Contributing to Dhow

Thank you for your interest in contributing to Dhow. This document outlines the
process for contributing.

## Development

1. Clone the repository.
2. Ensure Rust (pinned in `rust-toolchain.toml`) and Go (pinned in `go.mod`) are installed.
3. Run `./scripts/gate.sh` to verify all checks pass.

## Branching

- Create a branch from `main` for your work.
- Follow Conventional Commits format.
- Each phase is built on a branch named `phase/NN-short-slug`.

## Testing

- All new code must include tests.
- Run `cargo test` and `go test` before submitting.
- Property tests and golden vectors are required for wire-format changes.

## Security

- Report security vulnerabilities to the maintainers privately.
- Do not commit secrets, keys, or credentials.
- All cryptographic code must use audited primitives.
