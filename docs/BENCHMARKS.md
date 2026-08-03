# Benchmarks and the Memory Budget

> Part of the [Contributing guide](../CONTRIBUTING.md).

Two different things live here. The **benchmarks** measure how fast the data
path is, so a change that makes it three times slower shows up as a number in a
diff rather than as an operator noticing a transfer now takes all afternoon. The
**memory budget** is a threshold the gate enforces, because a receiver that
needs more resident memory than the machine has does not run slowly, it fails.

## Running them

```bash
make bench                       # criterion, and the Go benchmarks
scripts/rss.sh                   # peak RSS at 16 MiB, against the gate's budget
scripts/rss.sh 1024 12 8         # the real thing, if you have the minutes
```

`scripts/gate.sh` builds the benchmarks without running them to completion — a
full criterion pass is minutes, and a gate that takes minutes is a gate people
skip. Building proves they have not rotted against the code they measure, which
is the failure that actually happens. The RSS budget is a threshold, so it runs.

## The memory budget is a ratio

The phase pack asks for "a peak-RSS budget for a 1 GiB transfer". A single
absolute number for one dataset size is the wrong shape for this:

- it is expensive to check, so it would not be checked often;
- it says nothing about a 10 GiB transfer;
- and a regression that doubles memory use at every size still passes it, if the
  number was set with any slack at all.

What the *design* fixes is not a number of bytes. It is **how many copies of the
dataset are resident at once**, and that is a ratio. It is the same at every size
above the fixed overhead, it is what a change either preserves or breaks, and it
is cheap to measure. So the budget is a ratio, checked at 16 MiB on every gate
run, and the 1 GiB figure is derived from it below rather than measured on every
commit.

**The deviation is real and worth naming**: the gate does not run a 1 GiB
transfer, so a defect that only appears above some threshold would not be caught
by it. `scripts/rss.sh 1024` runs the real thing.

Send and receive have separate budgets because they are separate paths with
genuinely different numbers. One loose budget covering both would let the
cheaper one regress by ninety percent before anything failed.

## Measured baseline

Apple M4, macOS 26, release build, 16 MiB dataset, `-symbol-size 1320 -blocks 8
-overhead 10`. Three consecutive runs varied by less than 2%.

| Path | Peak RSS | Ratio | Budget |
|------|---------:|------:|-------:|
| `dhow send` | 166.9 MiB | **10.4x** | 12x |
| `dhow recv` | 102.2 MiB | **6.4x** | 8x |

At 64 MiB the ratios fall to 9.1x and 5.9x as the fixed overhead amortises, so
the 16 MiB figures are the conservative end.

**What this implies for 1 GiB**: roughly **9 GiB resident to send** and **6 GiB
to receive**. That is not a good number. It is the honest one, and the
components are known:

| Copy | Where | Cost |
|------|-------|-----:|
| The archive | `pack.Create` builds it into a `strings.Builder` | 1x, plus up to 1x transient while the builder grows |
| The payload | `[]byte(archive.String())` copies the builder out | 1x |
| The ciphertext | `encrypt_payload` returns a new buffer | 1x |
| The frames | `Pipeline::encode_to_bytes` holds every frame at once | ~1.15x at a 1320-byte symbol |
| Go's heap | never returned to the OS during the run | the high-water mark of all of the above |

None of that is a leak or a tuning problem. It is a design that assumes the
payload fits in memory, which is stated in `docs/BACKLOG.md` as **B-6** and is
what a streaming encoder would fix. Fixing it means an encoder that takes a
reader rather than a slice, which is an FFI change and a phase of its own.

The receive side has the same shape one copy shallower: the decoder holds the
symbols, reassembles the ciphertext, decrypts to a plaintext, and copies that
into Go for extraction. It is recorded as **B-8**.

## What was found by measuring

The benchmarks in this phase were written to establish a baseline and
immediately found a defect worth fixing. `crc32c_digest` was a byte-at-a-time
table lookup running at **513 MiB/s**, against BLAKE3's 2.1 GiB/s. A CRC whose
entire job is to be the cheap check *before* the cryptographic one, running four
times slower than the cryptographic one, is not doing that job — and it was the
single largest per-frame cost in the encoder, ahead of the keyed MAC it
precedes.

Replacing it with slicing-by-eight (no `unsafe`, no dependency, output unchanged
by construction):

| Benchmark | Before | After | Change |
|-----------|-------:|------:|-------:|
| `digest/crc32c/4194304` | 513 MiB/s | 2.28 GiB/s | −78.0% time |
| `frame/serialize/1320` | 2.63 µs | 708 ns | −73.1% time |
| `frame/parse/1024` | 2.02 µs | 532 ns | −73.8% time |

That is the argument for benchmarks in one paragraph: the defect had been in the
tree since Phase 6 and every test passed the whole time, because it was a
correctness suite and this was not a correctness defect.

## Data-path baseline

Same machine, `--measurement-time 3`. Throughput, higher is better.

| Benchmark | 4 KiB | 256 KiB | 4 MiB |
|-----------|------:|--------:|------:|
| `blake3` | 2.09 GiB/s | 2.14 GiB/s | 2.16 GiB/s |
| `blake3_streaming` | 1.95 GiB/s | 2.13 GiB/s | 2.15 GiB/s |
| `crc32c` | 2.33 GiB/s | 2.28 GiB/s | 2.28 GiB/s |

The streaming BLAKE3 matching the one-shot is what justifies `pack` hashing a
file while it writes it rather than reading the file twice.

| Benchmark | 4 KiB | 64 KiB | 512 KiB |
|-----------|------:|-------:|--------:|
| `fec/encode` | 209 MiB/s | 640 MiB/s | 691 MiB/s |
| `fec/decode` | 7.29 GiB/s | 7.75 GiB/s | 6.87 GiB/s |

RaptorQ encoding is the slowest thing in a transfer by a wide margin and is what
sets the wall-clock cost of `send`. Decoding from a complete packet set is
cheap; a lossy set costs more, and how much depends on which packets were lost,
which is why the benchmark does not try to put a number on it.

| Benchmark | 256 B | 1024 B | 1320 B |
|-----------|------:|-------:|-------:|
| `frame/serialize` | 265 ns | 598 ns | 708 ns |
| `frame/parse` | 208 ns | 532 ns | 605 ns |

Per frame, not per byte, because that is the unit that scales: a 1 GiB transfer
at a 1320-byte symbol is roughly 800,000 frames.

### Go side

| Benchmark | Throughput | Allocations |
|-----------|-----------:|------------:|
| `pack.Create` 16 MiB, 1 file | 1977 MB/s | 41 |
| `pack.Create` 1 MiB, 256 files | 258 MB/s | 4698 |
| `pack.Extract` 1 MiB, 1 file | 2027 MB/s | 26 |
| `pack.Extract` 1 MiB, 256 files | 71 MB/s | 2334 |

The many-files rows are dominated by per-file work rather than per-byte: an
open, a hasher handle across the FFI boundary, and on extraction a `MkdirAll`
and an `O_EXCL` create. A dataset of source code looks like that, and the
numbers say a transfer of ten thousand small files pays for the files, not for
the bytes.

## Comparing against the baseline

criterion saves a baseline per benchmark and reports the change on the next run,
which is where the `−78.0%` figures above came from:

```bash
cd core
cargo bench --bench data_path -- --save-baseline before
# ... make a change ...
cargo bench --bench data_path -- --baseline before
```

The numbers in this file are from one machine and are not a promise about a
receiver's hardware — which is deliberately an old machine kept off every
network, and rarely the newest one in the building. What travels between
machines is the *shape*: which operation dominates, and whether a change moved
it.
