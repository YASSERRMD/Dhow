# Dhow

**Dhow** moves a dataset between two networks that never touch. It packs a
directory, encrypts it, fountain-codes it into a stream of QR frames, and shows
them on a screen; a camera on the other side reads them back, verifies, and
reassembles. There is no network path between sender and receiver, ever.

## Status

`dhow` is a runnable binary. It performs a complete encrypted, signed transfer —
`keygen`, `send`, `display`, `recv`, `verify` — with the payload encrypted and
authenticated before it is ever framed, fountain-coded so a lossy channel still
completes, resumable if the receiver is interrupted, and verifiable against a
signed per-file inventory long after the fact.

**The camera half is not built.** Frames move between the two halves through a
directory, which exercises every layer above the optical one without hardware.
You can test this end to end today; you cannot yet run it across a real air gap.
See [B-3](docs/BACKLOG.md).

Two more limits worth knowing before relying on it, both measured rather than
guessed:

- **Memory.** Both halves hold the whole payload in memory. A 1 GiB transfer
  needs roughly 9 GiB resident to send and 6 GiB to receive.
  [The numbers](docs/BENCHMARKS.md), [B-6 and B-8](docs/BACKLOG.md).
- **Throughput.** RaptorQ encoding dominates and runs at about 690 MiB/s on an
  M4. A transfer's wall-clock cost is set there, not by the screen.

Built phase by phase; [`docs/phase-log.md`](docs/phase-log.md) records what each
phase delivered, what it found, and where it fell short.

## Quickstart

Verified by [`scripts/quickstart.sh`](scripts/quickstart.sh), which runs exactly
these commands. If they stop working, the build fails.

```bash
# Build
cd core && cargo build --release -p dhow-ffi && cd ..
go build -o dhow ./cli/cmd/dhow

# Two keys, two jobs. The operator key is shared; the identity is not.
./dhow keygen -out operator.key
./dhow keygen -kind identity -out sender.key

# Send: pack, encrypt, sign, and encode a directory into frames
./dhow send -key operator.key -identity sender.key -in ./mydata -out ./frames

# Receive: verify the signature, decode, decrypt, and extract
./dhow recv -key operator.key -signer sender.pub -in ./frames -out ./received

# Check it again, months later, without re-running the transfer
./dhow verify -in ./frames -signer sender.pub -dir ./received
```

`operator.key` goes to both machines. `sender.key` **never leaves the sending
machine**; carry `sender.pub` to the receiver and compare the fingerprint
`keygen` printed. The [key ceremony](docs/OPERATIONS.md#key-ceremony) explains
why that comparison is the step that matters.

## The two keys

|  | `operator.key` | `sender.key` |
|--|----------------|--------------|
| Kind | 32-byte symmetric | Ed25519 |
| Held by | **both** operators | the sender only |
| Does | encrypts the payload, authenticates frames | signs the manifest |
| Answers | "did someone in the group make this" | "which one" |

The operator key cannot answer the second question, because both sides hold it —
either could have produced any transfer made with it. `recv` and `verify` read
nothing out of a transfer before the signature checks, which matters more than
it sounds: the session id, salt, nonce, and every coding parameter come from the
signed manifest.

## Documentation

| | |
|--|--|
| [Operations Guide](docs/OPERATIONS.md) | Setup, coding parameters, the key ceremony, troubleshooting |
| [Architecture](docs/ARCHITECTURE.md) | How the pieces fit and why the seams are there |
| [Verifying a Dataset](docs/VERIFY.md) | What `dhow verify` proves, and what it does not |
| [Resuming a Receive](docs/RESUME.md) | Interrupted transfers |
| [Threat Model](docs/THREAT-MODEL.md) | Attack surfaces, and every control traced to a test |
| [Binding the C ABI](docs/FFI.md) | Using the core from something other than Go |
| [Benchmarks and Memory](docs/BENCHMARKS.md) | Baselines, and what a 1 GiB transfer costs |
| [Fuzzing](docs/FUZZING.md) | The toolchain decision, the targets, the corpus |
| [Building a Release](docs/RELEASE.md) | Reproducible builds, SBOMs, verifying a download |
| [Backlog](docs/BACKLOG.md) | Known defects and deferred work |
| [Changelog](CHANGELOG.md) | What changed, by phase |

Wire formats are specified in [`proto/`](proto/), frozen at suite 2.0, with a
[conformance suite](scripts/conformance_cli.py) a third-party implementation can
run against itself.

## Building and testing

```bash
make gate     # everything: fmt, lint, tests, audit, fuzz, chaos, RSS, release
make test     # just the tests
make bench    # benchmarks
```

`./scripts/gate.sh` runs 24 checks. It is slow on purpose — it includes a chaos
soak, a loopback transfer, a reproducible-build check, and a bounded fuzz pass.
Checks that need tooling not required to build dhow are **skipped and counted
separately**, never folded into the pass count.

## License

See [LICENSE](LICENSE).
