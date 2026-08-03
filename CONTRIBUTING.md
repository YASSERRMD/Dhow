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

## Fuzzing

`scripts/fuzz.sh` runs the `cargo-fuzz` targets over the parsers. The gate runs
ten seconds per target and CI runs 120; neither is a search.

Search like this:

```bash
scripts/fuzz.sh 3600
```

It needs a second toolchain, and [docs/FUZZING.md](docs/FUZZING.md) explains why
that is the shape of the answer, what was rejected, and what it costs. When a
target finds something, the input goes in `fuzz/regressions/` and the fix goes in
the same commit.

## Soaking

`scripts/chaos.sh` runs randomised fault-injection rounds against the shipped
binary. The gate runs twelve on a fixed seed and CI runs forty; neither is a
search.

Search like this:

```bash
scripts/chaos.sh 500
```

It prints its seed. A failing round prints the seed and the exact parameters,
and re-running with that seed reproduces it:

```bash
scripts/chaos.sh 500 1754210000
```

Set `CHAOS_VERBOSE=1` to see the parameters of every round rather than only of
a failure.

Run a soak before a release, and after any change to the codec, the framing, or
the resume path. A round has exactly two acceptable outcomes — completed and
verified, or failed closed having written nothing. Anything else is a defect,
including a round that exits with a code the harness does not expect.
