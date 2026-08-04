package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// The pre-filter: everything that can be decided about a frame on the Go side,
// decided there.
//
// `proto/frame.md` puts a CRC32C of the payload in the header for exactly this
// purpose, and the original phase pack asks for it to be checked before the
// FFI crossing. The reason is arithmetic. A capture at ten frames a second
// over a transfer of an hour is thirty-six thousand crossings, most of them
// carrying a frame that is a repeat of one already held or a symbol misread
// under a bad exposure. Each crossing pins an OS thread, copies the frame into
// the Rust side, and runs a keyed hash over it before anything can reject it.
// A four-byte comparison in front of that is free.
//
// It is a filter and not a check. Passing it means only that the bytes are
// shaped like a frame of this session and are internally consistent; the
// session MAC on the other side is what says they are genuine, and nothing
// here is trusted by anything downstream.

// Frame header layout, from `proto/frame.md`. Duplicated here rather than
// crossing the FFI to ask, because the whole point is to answer without
// crossing it; `scripts/conformance_cli.py` checks the real binary's output
// against the same document, so a drift between the two is caught by a gate
// rather than by a receiver that silently rejects every frame.
const (
	HeaderSize = 46

	offsetMagic       = 0
	offsetVersion     = 4
	offsetSessionID   = 8
	offsetBlockIndex  = 32
	offsetSymbolIndex = 36
	offsetPayloadLen  = 40
	offsetCRC         = 42
)

// FrameVersion is the wire-format version this build reads.
const FrameVersion = 1

var frameMagic = [4]byte{'D', 'H', 'O', 'W'}

// castagnoli is the CRC32C polynomial the frame header uses.
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Errors the pre-filter returns, each naming what was wrong so a receiver can
// tell "this is not a dhow frame" from "this is a dhow frame from a different
// transfer" from "this frame arrived damaged".
var (
	ErrNotAFrame      = errors.New("capture: not a dhow frame")
	ErrWrongSession   = errors.New("capture: frame belongs to another session")
	ErrFrameDamaged   = errors.New("capture: frame failed its CRC")
	ErrWrongVersion   = errors.New("capture: unsupported frame version")
	ErrLengthMismatch = errors.New("capture: frame length disagrees with its header")
)

// Prefilter rejects frames that cannot be genuine, without crossing the FFI.
type Prefilter struct {
	// SessionID is the transfer the receiver is decoding. A frame carrying
	// any other is from a different transfer, or a replay of an old one.
	SessionID [16]byte
}

// Accept reports whether a frame is worth handing to the decoder.
func (p Prefilter) Accept(frame []byte) error {
	if len(frame) < HeaderSize {
		return fmt.Errorf("%w: %d bytes is shorter than a header", ErrNotAFrame, len(frame))
	}
	if [4]byte(frame[offsetMagic:offsetMagic+4]) != frameMagic {
		return ErrNotAFrame
	}
	if frame[offsetVersion] != FrameVersion {
		return fmt.Errorf("%w: version %d", ErrWrongVersion, frame[offsetVersion])
	}
	if [16]byte(frame[offsetSessionID:offsetSessionID+16]) != p.SessionID {
		return ErrWrongSession
	}

	declared := int(binary.LittleEndian.Uint16(frame[offsetPayloadLen:]))
	if len(frame)-HeaderSize != declared {
		return fmt.Errorf("%w: header declares %d payload bytes, frame carries %d",
			ErrLengthMismatch, declared, len(frame)-HeaderSize)
	}

	want := binary.LittleEndian.Uint32(frame[offsetCRC:])
	if got := crc32.Checksum(frame[HeaderSize:], castagnoli); got != want {
		return ErrFrameDamaged
	}
	return nil
}

// Position returns the block and symbol a frame carries.
//
// Used to recognise a frame already held. The sender loops the stream until
// the operator stops it, so after the first pass most of what a camera sees is
// a repeat, and a repeat costs an FFI crossing and a full decode attempt to
// discover.
//
// A caller must record a position only after the decoder has *accepted* the
// frame at it, never merely on having seen one. These two fields are inside
// the frame's session MAC but the pre-filter does not check that MAC - it
// cannot, the key is on the other side of the FFI - so a position taken from
// an unauthenticated frame is attacker-chosen. Recording it on sight would let
// anyone who can put an image in front of the camera name a position, have it
// marked held, and cause the genuine frame for it to be skipped for the rest
// of the transfer.
func Position(frame []byte) (block, symbol uint32, ok bool) {
	if len(frame) < HeaderSize {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(frame[offsetBlockIndex:]),
		binary.LittleEndian.Uint32(frame[offsetSymbolIndex:]),
		true
}
