# Dhow

**Dhow** is a production-grade air-gapped data courier. It moves datasets between two
networks that never touch by encoding data as a fountain-coded stream of QR frames
rendered on a screen, captured by a camera on the receiving machine, decoded,
verified, and reassembled. There is no network path between sender and receiver.

## Status

Under active development, built phase by phase; see
[docs/phase-log.md](docs/phase-log.md) for what each phase delivered and what
it found.

`dhow` is a runnable binary today. It performs a complete encrypted transfer -
`keygen`, `send`, `display`, `recv`, `verify` - with the payload encrypted and
authenticated before it is ever framed, fountain-coded so a lossy optical
channel still completes, resumable if the receiver is interrupted, and
verifiable against a per-file inventory long after the fact.

**Not yet built:** camera capture and QR detection. Frames currently move
between the two halves through a directory, which exercises everything above
the optical layer without hardware. Until the camera path lands, this is a
tool you can test end to end but not yet run across a real air gap.

## Documentation

See [docs/](docs/) for the threat model, the operations guides, and the phase
log. Wire formats live in [proto/](proto/).

## License

See [LICENSE](LICENSE).
