# Operations Guide

How to run a transfer across an air gap, and what to do when it does not work.

> **Current limitation.** Camera capture and QR detection are not built yet.
> Everything in this guide about coding parameters, keys, verification, and
> resume is real and in use today; the physical-setup and throughput sections
> describe the optical channel the renderer already produces frames for and the
> capture side is not yet automated. Frames currently move between the two
> halves through a directory. Sections that depend on hardware are marked.

## The shape of a transfer

```
sender                                    receiver
------                                    --------
dhow keygen        (once, shared key)
dhow send          pack, encrypt, encode
dhow display       loop frames on screen  ──▶  camera
                                               dhow recv    capture, decode, extract
                                               dhow verify  check the dataset
```

The sender has no back channel. It cannot know which frames the camera caught,
so `display` loops the whole stream until the operator stops it, and every pass
is identical. That is what lets the receiver treat any capture of a frame as
interchangeable with any other.

**The receiver decides when a transfer is done, and the sender's operator has
to be told.** Agree on a signal before you start — a phone call, a hand wave,
a light. There is no protocol for it because there is no channel for one.

## Key ceremony

Both operators need the *same* operator key. It is a symmetric secret: anyone
holding it can read any transfer made with it.

```bash
dhow keygen -out operator.key
```

The file is written mode 0600 and `dhow` refuses to load one that is readable
by anyone else. It refuses to overwrite an existing key without `-force`,
because a key cannot be regenerated: overwriting one destroys every transfer
that has not yet been received.

Getting the key to the other side is **out of scope for this tool and is the
part that matters most**. The air gap you are moving data across is also a gap
the key has to cross. Sensible options, roughly in order of preference:

1. Generate it on one machine, carry it on removable media, destroy the media.
2. Generate it in the presence of both operators, on a machine that is then
   wiped.
3. Derive it from a passphrase agreed in person — not supported by `dhow
   keygen` today, so this means generating the key file elsewhere.

Do not email it, do not put it in a ticket, and do not send it through the
optical channel. A key that crossed the gap the same way the data does gives an
observer both halves.

Rotate the key when someone who held it no longer should. There is no
revocation: a key is either current or it is not, and only the operators know
which.

## Choosing coding parameters

Three flags on `send` decide how the transfer behaves. The defaults are chosen
for the directory transport and are **not** what you want on a real optical
link.

| Flag | Default | What it controls |
|------|---------|------------------|
| `-symbol-size` | 256 | Bytes of payload per frame. Must fit the QR version you will display. |
| `-blocks` | 1 | How the payload is split for error correction. |
| `-overhead` | 50 | Percent of repair symbols above the minimum. |

### Symbol size follows the QR version

A frame is a 46-byte header plus a 4-byte RaptorQ identifier plus the symbol,
so the symbol must be at least 50 bytes smaller than the QR code's capacity.
`proto/qr-capacity.md` has the measured table; the relevant rows:

| QR version | Modules | Symbol size at ECC L | at M | at Q | at H |
|-----------:|--------:|---------------------:|-----:|-----:|-----:|
| 20 | 97 | 808 | 616 | 432 | 332 |
| 25 | 117 | 1223 | 947 | 665 | 485 |
| 30 | 137 | 1682 | 1320 | 932 | 692 |
| 33 | 149 | 2018 | 1578 | 1118 | 848 |
| 40 | 177 | 2903 | 2281 | 1613 | 1223 |

Higher version means more modules in the same physical area, so each module is
smaller and needs a better camera, closer distance, or a bigger screen. Higher
ECC means fewer payload bytes but more tolerance for a partially obscured or
blurred code.

**Do not use QR error correction as your error correction.** ECC recovers a
damaged *code*; RaptorQ recovers a missing *frame*. A camera that misses frames
entirely — which is the normal failure — is helped only by RaptorQ. Prefer ECC
M and spend the bytes on payload, unless the codes are visibly marginal.

### Throughput is capacity times frame rate

Payload throughput is `symbol size × frames per second`, minus whatever
fraction of frames the camera misses. At ECC M:

| QR version | 15 fps | 30 fps | 60 fps |
|-----------:|-------:|-------:|-------:|
| 20 | ~9 KiB/s | ~18 KiB/s | ~36 KiB/s |
| 25 | ~14 KiB/s | ~28 KiB/s | ~55 KiB/s |
| 30 | ~19 KiB/s | ~39 KiB/s | ~77 KiB/s |
| 40 | ~33 KiB/s | ~67 KiB/s | ~134 KiB/s |

These are arithmetic from the measured capacity table, not measurements of a
real camera. Treat them as a ceiling. Expect to lose frames — plan on the
repair overhead you configured, and remember the whole stream loops, so a
transfer that misses 30% of frames simply takes longer rather than failing.

A 1 GiB dataset at version 30 and 30 fps is about seven and a half hours of
clean capture, before any loss. Consider whether you actually need to move a
gigabyte optically.

## Block count and the loss pattern — read this one

This is the parameter operators get wrong, and the failure is confusing.

RaptorQ repairs **within** a block and never across blocks. A block that never
received enough symbols is unrecoverable at any overhead, no matter how much
repair the rest of the transfer had to spare.

Frames are emitted interleaved round-robin across blocks, so any *contiguous*
run of loss — an operator stepping in front of the screen, a camera refocusing,
a light flickering — is spread evenly over every block, where the repair
symbols can absorb it. Without interleaving, a contiguous outage would fall
entirely inside one block and kill the transfer. (Phase 23 found this the hard
way; see the phase log.)

**Interleaving moves the pathological case rather than removing it.** Loss on a
period *equal to the block count* now lands on the same block every time and
concentrates there. With 4 blocks, losing every 4th frame destroys block 0 and
leaves the others untouched.

So the rule is:

> **Do not let your block count share a factor with anything periodic in your
> physical setup.**

Periodic loss is real, and it comes from beat frequencies:

| Source | Typical period |
|--------|----------------|
| Screen refresh against camera frame rate | the difference between the two |
| Mains flicker in artificial light (50/60 Hz) against frame rate | often small integers |
| Camera autofocus hunting on a cycle | seconds, so tens of frames |
| A rolling shutter tearing every *n*th capture | small integers |

Practical guidance:

- **Prefer a prime block count.** 7, 11, 13, 17 are all safe against small
  integer periods in a way 8, 12, or 16 are not.
- **Never use a power of two** if your frame rate and refresh rate are also
  powers of two or simple multiples, which they usually are.
- **More blocks is not safer.** Each block needs its own repair overhead, and
  a block is only as recoverable as the symbols it received. Fewer, larger
  blocks tolerate scattered loss better; more blocks bound the memory the
  decoder needs at once.
- If a transfer stalls with *some* blocks complete and one stuck, you are
  almost certainly hitting this. Change the block count to a nearby prime and
  re-send. Do not just raise the overhead: periodic loss on the block period
  is not a quantity problem.

The receiver reports per-block progress with `-verbose`, which is how you see
this happening rather than guessing:

```
$ dhow recv -verbose ...
6 of 7 blocks decoded (4210 frames accepted, 91 rejected)
```

Seven blocks and one stuck at six while the frame count climbs is the
signature.

## Physical setup *(hardware; not yet automated)*

- **Distance and framing.** The QR code should fill most of the camera frame
  with a visible quiet zone around it. Too far and modules blur together; too
  close and the edges leave frame.
- **Screen brightness.** High, but not so high that the screen blooms in the
  camera. A matte screen beats a glossy one.
- **Ambient light.** Dim and *steady*. Artificial light flickers at mains
  frequency, which is exactly the periodic loss the block-count section is
  about. Daylight or a DC-driven lamp is better than a fluorescent tube.
- **Stability.** Mount both. A handheld camera drifts, and autofocus hunting
  costs whole runs of frames.
- **Focus.** Fix it manually if you can. Autofocus will hunt on a
  high-contrast pattern that changes every frame.

`dhow display` opens with a calibration pattern: a QR code holding a fixed
public string, held for `-calibration` seconds. Scan it with any phone before
committing to a transfer. If a phone cannot read it at your distance and
lighting, your camera will not read the real frames either — and it costs
seconds to find out rather than hours.

The display also shows a session fingerprint. Both operators should read it
aloud and confirm they match. No protocol can do this for you across an air
gap.

## Running a transfer

```bash
# sender
dhow send -key operator.key -in ./dataset -out ./frames \
    -symbol-size 1320 -blocks 11 -overhead 60
dhow display -in ./frames -fps 30 -qr-version 30

# receiver
dhow recv -key operator.key -in ./frames -out ./received \
    -state ./.dhow-state -verbose
dhow verify -in ./frames -dir ./received
```

Always pass `-state`. A receive that runs for hours will be interrupted, and
without it every captured frame is lost. See [RESUME.md](RESUME.md).

Always run `verify` afterwards, and again later if the dataset matters. See
[VERIFY.md](VERIFY.md).

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `recv` exits 4, zero blocks complete, high rejection count | Frames are being read but not authenticated — wrong key. | Confirm both sides used the same `operator.key`. The rejection count climbing while blocks stay at zero is the signature. |
| `recv` exits 4, zero frames accepted at all | Nothing is being captured. | Check framing and focus. Scan the calibration pattern with a phone. |
| `recv` exits 4, most blocks complete, one stuck | Periodic loss landing on the block period. | Change `-blocks` to a nearby prime and re-send. Raising `-overhead` will not help. |
| `recv` exits 4, all blocks climbing slowly | Ordinary loss; the transfer is just slow. | Let it run. The stream loops. Consider a lower QR version or better lighting. |
| Many rejected frames, blocks still completing | Partial captures and blur. Normal. | Ignore unless the accept rate is unusably low. |
| `recv` exits 2 naming the state directory | Saved progress is unusable or from another session. | Follow the message. Deleting the state directory is always safe; it costs the frames captured so far. |
| `recv` exits 3 | The payload digest or AEAD tag failed. | This should not happen after a successful decode. Re-run the transfer; if it recurs, file it as a bug with the session id. |
| `verify` exits 3 with `content` problems | The dataset changed after extraction. | The transfer was fine; the storage was not. Re-extract from a fresh receive. |
| `verify` exits 3 with `unexpected` problems | Something added files to the output directory. | Extract into an empty directory. |
| `send` refuses a QR version | The symbol size does not fit. | Consult the capacity table above, or drop `-symbol-size`. |
| `dhow` refuses to load the key | The key file is readable by others. | `chmod 600 operator.key`. |

## Exit codes

| Code | Meaning | Retry unchanged? |
|-----:|---------|------------------|
| 0 | Success | — |
| 1 | Usage: a flag or argument was wrong | No |
| 2 | Input: a file missing, unreadable, or malformed | No |
| 3 | Verification failed | No |
| 4 | Incomplete: not enough frames arrived | **Yes** — show the stream again |
| 5 | Internal error, i.e. a bug | No; report it |

Only 4 is worth retrying unchanged. 2 and 3 mean something on disk is wrong and
repeating the command will reproduce them.
