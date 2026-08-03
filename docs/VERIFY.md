# Verifying a Received Dataset

> Part of the [Operations Guide](OPERATIONS.md).

`dhow recv` will not write a dataset it could not verify: the payload digest
and the AEAD tag are both checked before a single byte is extracted. So a
dataset that exists on disk was correct when it was written.

`dhow verify` answers a different question: **is it still correct now?**

Disks rot, backups restore wrong, files get edited, sync tools helpfully add
things. The command re-reads a dataset and compares it against what was
actually sent, months later if need be, without re-running the transfer.

## Using it

```bash
dhow verify -in frames -signer sender.pub -dir received
```

`-in` is the directory holding the signed manifest written by `send`; `-signer`
is the sender's public identity; `-dir` is the extracted dataset. Add `-json`
for machine-readable output.

```
session   5a4f2099a4bb8fc90a88ee09c48ad4b3
signer    39:5b:9b:97:82:ac:20:e5
files     3
bytes     5024
result    OK
```

The `signer` line is the fingerprint of the identity whose signature was
checked. Its presence is the difference between this report and one that says
only that a dataset matches a file someone wrote.

Exit codes: **0** verified, **3** verification failed *or the manifest did not
verify*, **2** the manifest is missing or unreadable.

The manifest is checked first, and nothing else runs if it fails. That is
deliberate: every property this command compares a dataset against comes out of
the manifest, so an unverified manifest makes the rest of the run meaningless
rather than merely less trustworthy.

## What it checks

First, the manifest itself:

| Property | Why |
|----------|-----|
| Ed25519 signature | The whole manifest, file entries included. Only the holder of `sender.key` can produce one that verifies. |
| Structure and policy | Magic, version, CRC, name sanitization, bounds on counts and sizes, and coding parameters that are internally consistent. Applied only after the signature, because limits on what a legitimate sender may claim mean nothing when applied to bytes nobody authenticated. |

Then, for every file the sender packed:

| Property | Why |
|----------|-----|
| Presence | A file that vanished is the loudest possible failure. |
| Size | Checked before contents, so a truncated file is reported as truncated rather than as a digest mismatch, which says only that *something* is wrong. |
| Contents | BLAKE3 over the file, compared with the digest taken while packing. This is what catches a single flipped byte. |
| Executable bit | Part of what a file *is*. A script that arrives non-executable has not arrived. |

And, for the dataset as a whole: any file that is present but was never sent.
A directory with something extra in it is not the dataset that was
transferred, whatever else is right about it.

## Reading a failure

Every problem is reported in one run, not one per invocation:

```
session   5a4f2099a4bb8fc90a88ee09c48ad4b3
files     2 checked of 3
result    FAILED
  - a.txt: missing from the dataset
  - run.sh: is not executable but was sent executable
  - sub/blob.bin: contents differ: digest ac633003, expected e1ddb64b
  - extra.txt: is not part of the transfer
```

`files N checked of M` is worth reading. A file that is missing or the wrong
size is never opened, so `checked` counts the files whose contents were
actually hashed. If it is far below the total, most of the dataset was not
examined at all.

Digests are shown truncated to eight characters. Two full 64-character digests
on one line push the part that differs off the edge of a terminal.

## JSON output

```json
{
  "ok": false,
  "session_id": "5a4f2099a4bb8fc90a88ee09c48ad4b3",
  "signer": "39:5b:9b:97:82:ac:20:e5",
  "files": 3,
  "files_checked": 2,
  "bytes_checked": 5018,
  "problems": [
    { "file": "a.txt", "kind": "missing", "detail": "missing from the dataset" }
  ]
}
```

`kind` is stable and is what a script should branch on; `detail` is prose and
may be reworded. The kinds are:

| Kind | Meaning |
|------|---------|
| `missing` | The file was sent but is not there. |
| `unexpected` | The file is there but was not sent. |
| `size` | Present, wrong length. |
| `content` | Right length, wrong bytes. |
| `mode` | Right bytes, wrong executable bit. |
| `unreadable` | The file or directory could not be read at all. |

## What it does and does not tell you

A passing run says: **this dataset is exactly what the holder of `sender.key`
described, and nothing about it has changed since.**

Until this was wired through, it said something much weaker. `send` wrote an
unsigned `transfer.json` beside the frames, and anyone who could edit the
dataset could edit the record next to it, so verify answered "does this dataset
still match the record?" rather than "who produced it?". The signature is what
closed that gap.

What it still does not tell you:

- **That `sender.pub` is the right key.** `verify` checks a signature against
  the key you hand it. If someone substituted that file, verification succeeds
  against whoever holds the matching secret. The fingerprint comparison in the
  [key ceremony](OPERATIONS.md#2-the-senders-identity) is what establishes
  this, and nothing automatic can replace it.
- **That the sender was right.** A signature says who produced the manifest,
  not that the dataset they packed was the one they meant to send.
- **That the sender's key is still theirs.** There is no revocation. An
  identity is trusted until the receiving operator deletes its `.pub` file.

Keep `sender.pub` where the dataset's own storage cannot reach it, for the same
reason you would keep a checksum file elsewhere: an attacker who can rewrite
both the dataset and the key you check it against has not been stopped by
either.
