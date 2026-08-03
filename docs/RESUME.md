# Resuming an Interrupted Receive

> Part of the [Operations Guide](OPERATIONS.md).

A capture that runs for an hour will be interrupted: the operator stops it, the
machine is rebooted, the process is killed. Without saved progress, every frame
captured so far is lost and the sender has to run the whole stream again.

`dhow recv -state <dir>` keeps that progress on disk.

## Using it

```bash
dhow recv -key operator.key -signer sender.pub -in frames -out received -state .dhow-state
```

If the receive is interrupted, run exactly the same command again. It replays
what it had, reports how many frames it recovered, and carries on:

```
resumed 1840 frames from .dhow-state
```

Resume is opt-in. Without `-state`, `recv` behaves as it always has and writes
nothing outside `-out`.

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-state <dir>` | none | Directory to keep resumable progress in. |
| `-save-every <n>` | 200 | Accepted frames between rewrites of the index. |
| `-stop-after <n>` | 0 | Stop after accepting `n` frames, saving first. 0 means no limit. |
| `-keep-state` | false | Keep the state directory after the transfer verifies. |

`SIGINT` and `SIGTERM` both save before exiting, so `Ctrl-C` is a safe way to
stop a capture.

An incomplete receive exits **4**. Unusable saved state exits **2**.

## What is in the directory

```
journal.bin    every accepted frame, in acceptance order
resume.dhrs    the index over the journal (proto/resume.md)
```

Both are created mode 0600 in a directory created mode 0700. Neither contains
key material, and the frames in the journal are the same ciphertext that was on
the screen — but there is no reason for another user on the machine to read
them.

The directory is deleted once the transfer completes and verifies, unless
`-keep-state` is given. A completed state left in place would be picked up by
the next transfer pointed at the same directory and refused as belonging to a
foreign session.

## Choosing `-save-every`

The journal is appended on every accepted frame. The index is rewritten every
`-save-every` frames and once on exit, because a rewrite costs two `fsync`
calls, and paying that per frame at forty frames a second is not worth it for
state that is disposable.

The cost of a larger interval is bounded and small: a crash loses at most the
frames captured since the last index write, and those frames are still on the
sender's screen, which loops the stream until the operator stops it.

The default of 200 is roughly five seconds of capture at 40 fps. Lower it if
your receiving machine is unreliable; there is no reason to raise it.

## When it refuses to resume

Every one of these stops the receive with exit code 2 rather than starting
over silently, because a receiver that discards saved progress without saying
so is indistinguishable from one that never had it.

| What happened | What to do |
|---------------|------------|
| The index fails its integrity check | Delete the state directory and re-run the capture. |
| The index belongs to another session | Point `-state` at the right directory. |
| The journal holds a frame the decoder rejects | Delete the state directory and re-run the capture. |
| The journal is shorter than the index covers | Delete the state directory and re-run the capture. |
| The replay does not reproduce the index | Delete the state directory and re-run the capture. |

Deleting the state directory is always safe. It costs the frames captured so
far and nothing else; the transfer itself is unaffected, and the sender can
show the stream again.

## What it protects against, and what it does not

Every frame replayed from the journal is authenticated against the session key
exactly as it was when first captured: MAC, CRC, session binding, symbol
bounds. The state directory holds no key material, so someone who can rewrite
these files still cannot make the decoder accept a frame it would otherwise
reject. That is the control that matters.

The index's CRC and BLAKE3 digest catch corruption, not forgery — anyone who
can rewrite the file can recompute them. What they add is that a half-written
or bit-rotted index is never believed, and that the index cannot be paired with
a journal it does not describe.

Someone with write access to the state directory can still delete it. There is
no defence against that here, and the cost is one recapture.
