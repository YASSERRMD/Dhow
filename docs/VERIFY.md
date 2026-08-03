# Verifying a Received Dataset

`dhow recv` will not write a dataset it could not verify: the payload digest
and the AEAD tag are both checked before a single byte is extracted. So a
dataset that exists on disk was correct when it was written.

`dhow verify` answers a different question: **is it still correct now?**

Disks rot, backups restore wrong, files get edited, sync tools helpfully add
things. The command re-reads a dataset and compares it against what was
actually sent, months later if need be, without re-running the transfer.

## Using it

```bash
dhow verify -in frames -dir received
```

`-in` is the directory holding the transfer record written by `send`; `-dir` is
the extracted dataset. Add `-json` for machine-readable output.

```
session   5a4f2099a4bb8fc90a88ee09c48ad4b3
files     3
bytes     5024
result    OK
```

Exit codes: **0** verified, **3** verification failed, **2** the transfer
record is missing or unreadable.

## What it checks

For every file the sender packed:

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

## What it does not tell you

The transfer record is not signed. It is written by `send` next to the frames,
and anyone who can edit the dataset can usually edit the record beside it. So
verify answers "does this dataset still match the record?" — not "was this
dataset produced by someone holding the operator key?"

That second question is the signed manifest's job, and the manifest travels
inside the frame stream where an attacker on the receiving machine cannot
reach it. Until the CLI reads it from there, keep the transfer record wherever
you would keep a checksum file: somewhere the dataset's own storage cannot
reach.
