# Dhow Wire-Format Specification

> **Format suite 2.0.** Frozen: the formats below will not change
> incompatibly without a suite version bump and an entry in
> [`migration.md`](migration.md).

This directory is the single source of truth for every Dhow wire format. It is
written so a third party can implement a conforming receiver without reading the
Rust, and [`vectors.json`](vectors.json) plus
[`../scripts/conformance_test.py`](../scripts/conformance_test.py) is how they
check that they have.

## Formats

| Format | File | Version | Fixed size | Crosses the optical channel |
|--------|------|---------|-----------:|------|
| Frame header | [`frame.md`](frame.md) | v1 | 46 bytes | yes |
| Session header | [`session.md`](session.md) | v1 | 126 bytes | yes |
| Manifest | [`manifest.md`](manifest.md) | **v2** | 228 bytes | yes |
| Block & symbol | [`block.md`](block.md) | v1 | n/a | yes |
| Resume file | [`resume.md`](resume.md) | **v2** | 128 bytes | no, local state |

The last column is the one that decides how much a version bump costs. A change
to a format that crosses the channel means both operators upgrade together and a
captured stream from before the change cannot be received after it. A change to
the resume file costs a receiver the frames it had captured, and nothing else.

Two supporting documents carry no format of their own:
[`endianness.md`](endianness.md) states the byte-order and packing rules every
format follows, and [`qr-capacity.md`](qr-capacity.md) is a measured table of how
large a symbol fits each QR version.

## Conventions

- **Endianness.** Every multi-byte integer is little-endian. There are no
  exceptions; a format that needed one would be a format that had gone wrong.
- **Alignment.** No padding. Fields are packed and every offset in these
  documents is exact.
- **Version bytes.** Every format begins with a 4-byte magic and a 1-byte
  version, in that order, so a parser can identify and reject a structure before
  reading anything whose meaning depends on the version.
- **CRC.** CRC32C (Castagnoli, reflected polynomial `0x82F63B78`), for fast
  rejection of corruption. It is not a security control: an attacker who can
  change a byte can change the CRC.
- **Digests.** BLAKE3, 32-byte output, for everything that is a security
  control.
- **Signatures.** Ed25519 over a canonical byte string, defined per format.

### Reserved fields are rejected, not ignored

A sender writes zero. **A receiver rejects a non-zero reserved field** rather
than ignoring it.

This is the opposite of the usual convention and it is deliberate. In a signed
structure, ignoring an unknown bit means an old receiver can act on a manifest
it did not fully understand while reporting that it verified all of it. In
unsigned framing, a value the parser cannot interpret is a value it cannot act
on safely. Neither case is improved by tolerance.

The cost is that a reserved field cannot be quietly repurposed: giving one a
meaning requires a version bump, because every existing receiver will reject a
non-zero value. That is the intended trade.

## Compatibility policy

A version number is only useful if it says what to *do*. This is that.

### What a conforming receiver must do

| It is handed | It must |
|--------------|---------|
| A structure with the current version byte | Parse it, then apply every check this document requires |
| A structure with a **lower** version byte | **Reject** it, naming the version it found |
| A structure with a **higher** version byte | **Reject** it, naming the version it found |
| Wrong magic | Reject, naming the magic it found |
| A non-zero reserved field | Reject |
| A field whose declared length exceeds the buffer | Reject, without indexing past the end |
| A declared count larger than this document's bound | Reject, before the count drives an allocation |

**There is no forward compatibility and no backward compatibility within the
suite, and that is a decision rather than an omission.** A receiver that
half-understands a structure it was handed is a receiver making a guess about
data it cannot re-request — there is no back channel across an air gap, so there
is no way to ask. Rejecting and telling the operator to re-send is the only
answer that cannot be wrong.

### What "reject" means

An error that names the problem and the value that caused it, and **no output**.
A receiver that writes a partial dataset and then reports a failure has produced
something an operator can mistake for a result. Extraction in this
implementation is atomic for that reason; a conforming one must be too.

### What may change without a suite version bump

- Anything in [`qr-capacity.md`](qr-capacity.md). It is measurement, not format.
- New *documents*, describing formats that did not exist.
- Corrections to prose that do not change a byte.

### What requires a suite version bump

- Any field width, offset, or ordering.
- Any change to what a value means.
- Any new field, including one carved out of a reserved region.
- Any change to what is covered by a CRC, a digest, or a signature.

## Checking an implementation

[`vectors.json`](vectors.json) holds golden byte strings for every structure,
generated by [`../scripts/gen_vectors.py`](../scripts/gen_vectors.py) rather
than written by hand. Two scripts use them, and they check different things:

```bash
python3 scripts/check_spec.py          # the documents agree with themselves
python3 scripts/conformance_test.py    # the vectors agree with the documents
python3 scripts/conformance_cli.py     # a built dhow agrees with both
```

The third is the one that matters to a third party, and it is the one that was
missing until the spec freeze. The first two compare a generated file against
the document that describes it — worth having, and neither of them would notice
if the *implementation* had drifted from both.

`conformance_cli.py` runs a real transfer with a built `dhow`, then reads the
bytes it produced at the offsets these documents declare. If the manifest's
version byte is not at offset 4, or its CRC does not cover exactly bytes 0..160,
or a frame's payload length does not sit at offset 40, it fails — against the
binary, not against a description of it.

## Implementing a receiver

The minimum a receiver must do, in order:

1. **Read the manifest** and verify its Ed25519 signature against a public
   identity obtained out of band. Read nothing else from it first: the session
   id, salt, nonce, and every coding parameter come from this structure, so an
   unverified manifest configures the whole transfer.
2. **Parse each frame**: magic, version, session id, MAC, CRC. Reject anything
   that fails, and keep going — on an optical channel most captures are noise
   and a receiver that stops at the first bad frame never finishes.
3. **Feed accepted symbols** to a RaptorQ decoder per block, using the
   `PayloadId` carried in the frame payload rather than the header's
   `symbol_index`, which is transmission bookkeeping.
4. **On completion**, reassemble, check the whole-payload BLAKE3 against the
   manifest, then decrypt with XChaCha20-Poly1305.
5. **Extract**, re-validating every file name against the traversal rules in
   [`manifest.md`](manifest.md) even though the manifest was signed. A signature
   says who produced the names, not that they are safe.
6. **Reconcile** what was extracted against the manifest's inventory.

Steps 5 and 6 are the ones an implementer is most likely to skip, and they are
the ones that decide whether a signed manifest from a mistaken sender can write
outside the destination directory.
