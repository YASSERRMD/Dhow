# Dhow

**Dhow** is a production-grade air-gapped data courier. It moves datasets between two
networks that never touch by encoding data as a fountain-coded stream of QR frames
rendered on a screen, captured by a camera on the receiving machine, decoded,
verified, and reassembled. There is no network path between sender and receiver.

## Status

Under active development, built phase by phase; see
[docs/phase-log.md](docs/phase-log.md) for what each phase delivered and what
it found.

`dhow` is a runnable binary today. It performs a complete encrypted, signed
transfer - `keygen`, `send`, `display`, `recv`, `verify` - with the payload
encrypted and authenticated before it is ever framed, fountain-coded so a lossy
optical channel still completes, resumable if the receiver is interrupted, and
verifiable against a signed per-file inventory long after the fact.

A transfer uses two keys. The **operator key** is symmetric and shared by both
sides; it encrypts. The sender's **identity key** stays on the sending machine
and signs the manifest, so a receiver can tell a transfer the sender made from
one anybody holding the shared key could have made. `recv` and `verify` read
nothing out of a transfer before checking that signature.

**Not yet built:** camera capture and QR detection. Frames currently move
between the two halves through a directory, which exercises everything above
the optical layer without hardware. Until the camera path lands, this is a
tool you can test end to end but not yet run across a real air gap.

## Documentation

- [Operations Guide](docs/OPERATIONS.md) — setup, parameters, troubleshooting,
  the two-key ceremony
- [Resuming an Interrupted Receive](docs/RESUME.md)
- [Verifying a Received Dataset](docs/VERIFY.md)
- [Threat Model](docs/THREAT-MODEL.md)
- [Fuzzing](docs/FUZZING.md) — the toolchain decision, the targets, the corpus
- [Benchmarks and the Memory Budget](docs/BENCHMARKS.md) — baselines, and what
  a 1 GiB transfer costs today
- [Phase Log](docs/phase-log.md)

Wire formats live in [proto/](proto/).

## License

See [LICENSE](LICENSE).
