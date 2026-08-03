# Operator UX Review

A checklist walked against the shipped binary, with the answer recorded rather
than the intention. Items marked **open** are honest gaps, not oversights.

Reviewed at Phase 26.

## Streams

| Question | Answer |
|----------|--------|
| Do results go to stdout and commentary to stderr? | Yes. `dhow send -json \| jq` works while a person still sees progress. `display` is the exception in the other direction: its summary goes to stderr so stdout carries only what a camera should see. |
| Is stdout parseable without `-json`? | No, and it is not meant to be. The human format is aligned key/value lines; scripts use `-json`. |
| Does `-json` produce exactly one JSON document? | Yes, one object, indented, newline-terminated. |
| Do errors ever land on stdout? | No. Every failure path goes through `exitError` and is written to stderr by `Run`. |

## Verbosity

| Question | Answer |
|----------|--------|
| Is there one verbosity model, or one per command? | One. `verbosityFlags` is registered by every command. |
| Does `-quiet` suppress failures? | No. It suppresses the end-of-command summary only. A failed `verify` still reports its problems. |
| Does `-quiet` suppress `-json`? | No. Asking for machine output and silence together wants the JSON; dropping it would be data loss. |
| Does `-verbose` change results? | No. Asserted by a test that compares the JSON from both. |
| What happens if both are given? | Exit 1 with an explanation. Guessing would make the tool unpredictable exactly when the operator is unsure what it is doing. |

## Progress

| Question | Answer |
|----------|--------|
| Can an operator tell a long `recv` is progressing? | Yes, under `-verbose`: a line per block completion, with running accept and reject counts. |
| Why by block and not by frame? | Frames arrive in their thousands and almost none change anything actionable. A block completing is the unit of real progress. |
| Can an operator tell a run resumed? | Yes, at normal level. Someone who does not notice will misread every count that follows. |
| Is there a progress bar or ETA? | **Open.** Neither exists. An ETA needs a frame rate the receiver does not observe, so it would be a guess presented as a number. |
| Does `send` show progress on a large dataset? | Partly. Under `-verbose` it names each stage, but a multi-gigabyte pack is still one silent step. **Open.** |

## Errors

| Question | Answer |
|----------|--------|
| Does a failure name the file it concerns? | Yes, throughout. |
| Does a failure name a next step where one exists? | For the cases that have one: missing key, permissive key, and every resume-state rejection. Others state the cause only. |
| Are error messages free of key material and payload bytes? | Yes, enforced in the Rust core and tested there. |
| Does a rejected resume state say the state is disposable? | Yes. Every message on that path says deleting the directory is safe and what it costs. |

## Exit codes

| Question | Answer |
|----------|--------|
| Are they documented? | Yes, in `dhow help`, `docs/OPERATIONS.md`, and the package comment. |
| Are they stable? | Treated as a contract. Changing one is a breaking change. |
| Is each one reachable by a test? | Five of six. `5` (internal) is deliberately unprovoked: it means a bug, and manufacturing one to test it would mean building a fault-injection path into the shipped binary. |
| Can a script tell "retry" from "do not retry"? | Yes. Only `4` is worth retrying unchanged, and the help says so. |

## Terminal safety

| Question | Answer |
|----------|--------|
| Is output safe when not a TTY? | Yes. Nothing emits colour or cursor control except `display`, whose screen-clearing is opt-out with `-no-clear`. |
| Does any command require a TTY? | No. |
| Does any command write control characters into `-json`? | No; the JSON encoder escapes them. |
| Is `display` usable over SSH or in CI? | Yes, with `-no-clear`. The drill and the display tests both run it headless. |

## Discoverability

| Question | Answer |
|----------|--------|
| Does `dhow` with no arguments help? | Yes: usage on stderr, exit 1. |
| Does every command have `-h`? | Yes, via the flag package. |
| Is every flag documented in its help string? | Yes. |
| Does the top-level help mention the common flags? | Yes: `-json`, `-quiet`, `-verbose`. |
| Is there a guide for a first-time operator? | Yes, `docs/OPERATIONS.md`, which is followed end to end by `scripts/drill.sh` on every gate run. |

## Known gaps

1. **No ETA or progress bar.** Would require observing a frame rate the
   receiver has no reason to track. Better absent than invented.
2. **`send` is silent during packing.** A multi-gigabyte dataset gives no sign
   of life until packing finishes.
3. **No `--dry-run`.** An operator cannot ask what a `send` would produce
   without producing it.
4. **No config file or environment overrides.** Every invocation repeats every
   flag. The parameters that matter — key path, symbol size, block count — are
   the same for every transfer between a given pair of machines.
