// Package ffi wraps the Rust core's C ABI in a Go-idiomatic API.
//
// # Memory ownership
//
// Every handle returned by the Rust core is owned by exactly one Go value and
// released by its Close method. Callers must Close what they open; the types
// here do not rely on finalizers, because a finalizer's timing is not
// guaranteed and key material should be zeroized promptly rather than
// eventually.
//
// Buffers cross the boundary in one direction only: Go allocates, Rust fills.
// The Rust side never returns a pointer Go must free, so there is no question
// of which allocator owns a block.
//
// # Key material
//
// Go never sees a secret key. Operator keys are held as opaque handles, and
// the session key derived for a transfer stays inside Rust. That is deliberate:
// Go's garbage collector may copy a value while moving it, so a secret held in
// a Go slice could survive in memory after the slice was overwritten.
//
// # Errors
//
// A failing call returns an error carrying both the status code and the Rust
// side's description. The Rust core is written so those descriptions never
// contain payload bytes or key material, which is what makes them safe to log.
package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/../../../core/include
#cgo LDFLAGS: -L${SRCDIR}/../../../core/target/release -L${SRCDIR}/../../../core/target/debug -ldhow_ffi
#include <stdlib.h>
#include <string.h>
#include "dhow.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Status mirrors the C DhowStatus enum.
type Status int

// Status values returned by the Rust core.
const (
	StatusOK                Status = 0
	StatusNullArgument      Status = -1
	StatusInvalidArgument   Status = -2
	StatusBufferTooSmall    Status = -3
	StatusInvalidParameters Status = -4
	StatusFrameRejected     Status = -5
	StatusIncomplete        Status = -6
	StatusVerificationFail  Status = -7
	StatusCryptoFailed      Status = -8
	StatusKeyFailed         Status = -9
	StatusInternal          Status = -10
	StatusPanic             Status = -11
	StatusResumeRejected    Status = -12
)

// ErrIncomplete reports that a transfer needs more frames before it can finish.
//
// This is the one status callers routinely branch on rather than treat as a
// failure: a receiver polls until the transfer completes.
var ErrIncomplete = errors.New("dhow: transfer incomplete")

// ErrFrameRejected reports that a frame failed parsing, authentication, or its
// integrity checks.
//
// A receiver watching a screen should keep going rather than abort. Most
// rejections are ordinary capture noise: a blurred or half-drawn frame.
var ErrFrameRejected = errors.New("dhow: frame rejected")

// ErrResumeRejected reports that saved progress could not be used.
//
// Distinct from a verification failure, which says the transfer itself is bad.
// This says only that the state on disk is unusable, so the caller's choice is
// between restarting the transfer and investigating why.
var ErrResumeRejected = errors.New("dhow: resume state rejected")

// Error is a failure reported by the Rust core.
type Error struct {
	// Status is the code the core returned.
	Status Status
	// Detail is the core's description of the failure.
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("dhow: %s", statusString(e.Status))
	}
	return fmt.Sprintf("dhow: %s: %s", statusString(e.Status), e.Detail)
}

// Is lets callers match the sentinel errors with errors.Is.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrIncomplete:
		return e.Status == StatusIncomplete
	case ErrFrameRejected:
		return e.Status == StatusFrameRejected
	case ErrResumeRejected:
		return e.Status == StatusResumeRejected
	}
	return false
}

// statusString returns the core's static description of a status code.
func statusString(s Status) string {
	return C.GoString(C.dhow_status_string(C.int(s)))
}

// lastError reads the calling thread's last error description.
//
// The description is thread-local in Rust, so the goroutine must stay on the
// OS thread that made the failing call. Callers lock the thread around any
// sequence whose error they intend to read.
func lastError() string {
	needed := C.dhow_last_error_message(nil, 0)
	if needed <= 1 {
		return ""
	}
	buf := make([]C.char, int(needed))
	if got := C.dhow_last_error_message(&buf[0], C.size_t(len(buf))); got < 0 {
		return ""
	}
	return C.GoString(&buf[0])
}

// wrap converts a status code into an error, attaching the core's description.
func wrap(s Status) error {
	if s == StatusOK {
		return nil
	}
	return &Error{Status: s, Detail: lastError()}
}

// ABIVersion returns the ABI version the linked library was built with.
//
// A caller linking against a mismatched version should refuse to run rather
// than guess at the layout of a handle.
func ABIVersion() uint32 {
	return uint32(C.dhow_abi_version())
}

// Version returns the linked library's crate version.
func Version() string {
	return C.GoString(C.dhow_version_string())
}

// SessionParams describes the coding layout of a transfer.
//
// A receiver takes these from the signed manifest. They are public: nothing
// here is secret, and an observer learns only the payload's approximate size.
type SessionParams struct {
	// PayloadSize is the size of the encrypted payload in bytes.
	PayloadSize uint64
	// BlockCount is the number of source blocks.
	BlockCount uint32
	// SymbolSize is the size of each symbol in bytes.
	SymbolSize uint32
	// SourceSymbolsPerBlock is the count of source symbols per block.
	SourceSymbolsPerBlock uint32
	// TotalSymbolsPerBlock includes repair symbols.
	TotalSymbolsPerBlock uint32
	// PayloadDigest is the BLAKE3 digest of the encrypted payload.
	PayloadDigest [32]byte
}

func (p SessionParams) toC() C.DhowSessionParams {
	var c C.DhowSessionParams
	c.payload_size = C.uint64_t(p.PayloadSize)
	c.block_count = C.uint32_t(p.BlockCount)
	c.symbol_size = C.uint32_t(p.SymbolSize)
	c.source_symbols_per_block = C.uint32_t(p.SourceSymbolsPerBlock)
	c.total_symbols_per_block = C.uint32_t(p.TotalSymbolsPerBlock)
	for i, b := range p.PayloadDigest {
		c.payload_digest[i] = C.uint8_t(b)
	}
	return c
}

func paramsFromC(c C.DhowSessionParams) SessionParams {
	p := SessionParams{
		PayloadSize:           uint64(c.payload_size),
		BlockCount:            uint32(c.block_count),
		SymbolSize:            uint32(c.symbol_size),
		SourceSymbolsPerBlock: uint32(c.source_symbols_per_block),
		TotalSymbolsPerBlock:  uint32(c.total_symbols_per_block),
	}
	for i := range p.PayloadDigest {
		p.PayloadDigest[i] = byte(c.payload_digest[i])
	}
	return p
}

// Key is an operator key held by the Rust core.
//
// The key material never enters Go's address space.
type Key struct {
	ptr *C.DhowKey
}

// GenerateKey draws a new operator key from the system CSPRNG.
func GenerateKey() (*Key, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ptr := C.dhow_key_generate()
	if ptr == nil {
		return nil, &Error{Status: StatusKeyFailed, Detail: lastError()}
	}
	return &Key{ptr: ptr}, nil
}

// LoadKey reads an operator key from a key file.
//
// Fails if the file is missing, malformed, or readable by anyone but its owner.
func LoadKey(path string) (*Key, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	ptr := C.dhow_key_load(cPath)
	if ptr == nil {
		return nil, &Error{Status: StatusKeyFailed, Detail: lastError()}
	}
	return &Key{ptr: ptr}, nil
}

// Save writes the key to path with owner-only permissions.
func (k *Key) Save(path string) error {
	if k == nil || k.ptr == nil {
		return errors.New("dhow: key is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	return wrap(Status(C.dhow_key_save(k.ptr, cPath)))
}

// Close releases the key, zeroizing its material.
//
// Safe to call more than once and on a nil receiver, so cleanup paths need no
// guard. It returns nothing because freeing a handle cannot fail: an error
// return would imply a failure mode that does not exist and would force every
// deferred call to discard a value.
func (k *Key) Close() {
	if k == nil || k.ptr == nil {
		return
	}
	C.dhow_key_free(k.ptr)
	k.ptr = nil
}

// Encoder holds the full frame stream for one transfer.
type Encoder struct {
	ptr *C.DhowEncoder
}

// NewEncoder encrypts payload and builds every frame for the session.
//
// The encoder retains all frames so a display loop can serve them repeatedly
// and in any order, which is what an unacknowledged optical channel requires:
// the sender cannot know which frames the camera caught.
func NewEncoder(
	key *Key,
	sessionID [16]byte,
	salt [32]byte,
	nonce [24]byte,
	params SessionParams,
	payload []byte,
) (*Encoder, error) {
	if key == nil || key.ptr == nil {
		return nil, errors.New("dhow: key is closed")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// An empty payload still needs a non-nil pointer, since the core treats a
	// null pointer as a missing argument rather than an empty slice.
	payloadPtr := (*C.uint8_t)(nil)
	if len(payload) > 0 {
		payloadPtr = (*C.uint8_t)(unsafe.Pointer(&payload[0]))
	} else {
		var empty [1]byte
		payloadPtr = (*C.uint8_t)(unsafe.Pointer(&empty[0]))
	}

	ptr := C.dhow_encoder_new(
		key.ptr,
		(*C.uint8_t)(unsafe.Pointer(&sessionID[0])),
		(*C.uint8_t)(unsafe.Pointer(&salt[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		params.toC(),
		payloadPtr,
		C.size_t(len(payload)),
	)
	// Keep the Go buffers alive across the call; cgo does not extend their
	// lifetime past the argument evaluation on its own.
	runtime.KeepAlive(payload)
	runtime.KeepAlive(key)

	if ptr == nil {
		return nil, &Error{Status: StatusInvalidParameters, Detail: lastError()}
	}
	return &Encoder{ptr: ptr}, nil
}

// FrameCount returns how many frames the encoder holds.
func (e *Encoder) FrameCount() (int, error) {
	if e == nil || e.ptr == nil {
		return 0, errors.New("dhow: encoder is closed")
	}
	n := C.dhow_encoder_frame_count(e.ptr)
	if n < 0 {
		return 0, wrap(Status(n))
	}
	return int(n), nil
}

// Frame returns frame i.
//
// The returned slice is freshly allocated by Go and owned by the caller.
func (e *Encoder) Frame(i int) ([]byte, error) {
	if e == nil || e.ptr == nil {
		return nil, errors.New("dhow: encoder is closed")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var needed C.size_t
	if st := Status(C.dhow_encoder_frame(e.ptr, C.size_t(i), nil, 0, &needed)); st != StatusOK {
		return nil, wrap(st)
	}
	if needed == 0 {
		return nil, nil
	}

	buf := make([]byte, int(needed))
	var written C.size_t
	st := Status(C.dhow_encoder_frame(
		e.ptr,
		C.size_t(i),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		&written,
	))
	runtime.KeepAlive(buf)
	if st != StatusOK {
		return nil, wrap(st)
	}
	return buf[:int(written)], nil
}

// Frames returns every frame in order.
func (e *Encoder) Frames() ([][]byte, error) {
	n, err := e.FrameCount()
	if err != nil {
		return nil, err
	}
	frames := make([][]byte, 0, n)
	for i := range n {
		frame, err := e.Frame(i)
		if err != nil {
			return nil, fmt.Errorf("reading frame %d: %w", i, err)
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

// Params returns the session parameters the encoder actually used.
//
// The caller describes the plaintext, but framing operates on ciphertext,
// which is longer by the AEAD tag. These are the values that belong in the
// signed manifest.
func (e *Encoder) Params() (SessionParams, error) {
	if e == nil || e.ptr == nil {
		return SessionParams{}, errors.New("dhow: encoder is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var out C.DhowSessionParams
	if st := Status(C.dhow_encoder_params(e.ptr, &out)); st != StatusOK {
		return SessionParams{}, wrap(st)
	}
	return paramsFromC(out), nil
}

// Close releases the encoder.
//
// Safe to call more than once and on a nil receiver. Returns nothing for the
// same reason as [Key.Close].
func (e *Encoder) Close() {
	if e == nil || e.ptr == nil {
		return
	}
	C.dhow_encoder_free(e.ptr)
	e.ptr = nil
}

// Decoder reassembles a payload from frames arriving in any order.
type Decoder struct {
	ptr *C.DhowDecoder
}

// NewDecoder creates a decoder for a session.
func NewDecoder(
	key *Key,
	sessionID [16]byte,
	salt [32]byte,
	params SessionParams,
) (*Decoder, error) {
	if key == nil || key.ptr == nil {
		return nil, errors.New("dhow: key is closed")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ptr := C.dhow_decoder_new(
		key.ptr,
		(*C.uint8_t)(unsafe.Pointer(&sessionID[0])),
		(*C.uint8_t)(unsafe.Pointer(&salt[0])),
		params.toC(),
	)
	runtime.KeepAlive(key)

	if ptr == nil {
		return nil, &Error{Status: StatusInvalidParameters, Detail: lastError()}
	}
	return &Decoder{ptr: ptr}, nil
}

// Accept feeds one captured frame to the decoder.
//
// A rejected frame returns an error matching ErrFrameRejected and leaves the
// decoder unchanged. A receiver should keep watching rather than abort: most
// rejections are ordinary capture noise.
func (d *Decoder) Accept(frame []byte) error {
	if d == nil || d.ptr == nil {
		return errors.New("dhow: decoder is closed")
	}
	if len(frame) == 0 {
		return &Error{Status: StatusFrameRejected, Detail: "empty frame"}
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	st := Status(C.dhow_decoder_accept(
		d.ptr,
		(*C.uint8_t)(unsafe.Pointer(&frame[0])),
		C.size_t(len(frame)),
	))
	runtime.KeepAlive(frame)
	return wrap(st)
}

// IsComplete reports whether every block has decoded.
func (d *Decoder) IsComplete() (bool, error) {
	if d == nil || d.ptr == nil {
		return false, errors.New("dhow: decoder is closed")
	}
	n := C.dhow_decoder_is_complete(d.ptr)
	if n < 0 {
		return false, wrap(Status(n))
	}
	return n == 1, nil
}

// BlocksComplete reports how many blocks have decoded.
func (d *Decoder) BlocksComplete() (int, error) {
	if d == nil || d.ptr == nil {
		return 0, errors.New("dhow: decoder is closed")
	}
	n := C.dhow_decoder_blocks_complete(d.ptr)
	if n < 0 {
		return 0, wrap(Status(n))
	}
	return int(n), nil
}

// Finish reassembles, verifies, and decrypts the payload.
//
// Returns an error matching ErrIncomplete while blocks are outstanding.
// Plaintext is returned only after both the payload digest and the AEAD tag
// have been checked, so a caller never sees unverified bytes.
func (d *Decoder) Finish(
	key *Key,
	sessionID [16]byte,
	salt [32]byte,
	nonce [24]byte,
) ([]byte, error) {
	if d == nil || d.ptr == nil {
		return nil, errors.New("dhow: decoder is closed")
	}
	if key == nil || key.ptr == nil {
		return nil, errors.New("dhow: key is closed")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sid := (*C.uint8_t)(unsafe.Pointer(&sessionID[0]))
	saltPtr := (*C.uint8_t)(unsafe.Pointer(&salt[0]))
	noncePtr := (*C.uint8_t)(unsafe.Pointer(&nonce[0]))

	var needed C.size_t
	st := Status(C.dhow_decoder_finish(d.ptr, key.ptr, sid, saltPtr, noncePtr, nil, 0, &needed))
	if st != StatusOK {
		return nil, wrap(st)
	}
	if needed == 0 {
		return []byte{}, nil
	}

	buf := make([]byte, int(needed))
	var written C.size_t
	st = Status(C.dhow_decoder_finish(
		d.ptr,
		key.ptr,
		sid,
		saltPtr,
		noncePtr,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		&written,
	))
	runtime.KeepAlive(buf)
	runtime.KeepAlive(key)
	if st != StatusOK {
		return nil, wrap(st)
	}
	return buf[:int(written)], nil
}

// ResumeState serializes the decoder's progress so a restart can replay it.
//
// journalBytes is the length of the caller's journal at this moment. The
// caller owns the journal, so only it knows how long the file is; the decoder
// knows only which frames were in it. The two must be captured together, or
// the state will describe a journal that no longer exists.
func (d *Decoder) ResumeState(journalBytes uint64) ([]byte, error) {
	if d == nil || d.ptr == nil {
		return nil, errors.New("dhow: decoder is closed")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var needed C.size_t
	if st := Status(C.dhow_decoder_resume_state(
		d.ptr, C.uint64_t(journalBytes), nil, 0, &needed,
	)); st != StatusOK {
		return nil, wrap(st)
	}
	if needed == 0 {
		return nil, nil
	}

	buf := make([]byte, int(needed))
	var written C.size_t
	st := Status(C.dhow_decoder_resume_state(
		d.ptr,
		C.uint64_t(journalBytes),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		&written,
	))
	runtime.KeepAlive(buf)
	if st != StatusOK {
		return nil, wrap(st)
	}
	return buf[:int(written)], nil
}

// VerifyResume checks saved progress against what this decoder holds.
//
// Call it after replaying a journal. An error matching ErrResumeRejected means
// the state and the journal describe different things, which is a reason to
// stop rather than to guess which one is right.
func (d *Decoder) VerifyResume(state []byte) error {
	if d == nil || d.ptr == nil {
		return errors.New("dhow: decoder is closed")
	}
	if len(state) == 0 {
		return &Error{Status: StatusResumeRejected, Detail: "resume state is empty"}
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	st := Status(C.dhow_decoder_resume_verify(
		d.ptr,
		(*C.uint8_t)(unsafe.Pointer(&state[0])),
		C.size_t(len(state)),
	))
	runtime.KeepAlive(state)
	return wrap(st)
}

// ResumeInfo is what a resume file says about itself.
type ResumeInfo struct {
	// SessionID is the transfer the state belongs to.
	SessionID [16]byte
	// JournalBytes is the length of the journal prefix the state covers.
	//
	// A receiver appends to its journal continuously and rewrites the state
	// periodically, so a crash routinely leaves the journal longer than this.
	// Bytes past it were never durably recorded and must be discarded.
	JournalBytes uint64
	// BlockCount is the number of blocks the state describes.
	BlockCount uint32
}

// ReadResumeState parses and integrity-checks a resume file.
//
// A restarting receiver needs this before it can build a decoder: the session
// ID says whether the state belongs to the transfer in hand, and the journal
// length says how much of the journal to replay.
func ReadResumeState(state []byte) (ResumeInfo, error) {
	var info ResumeInfo
	if len(state) == 0 {
		return info, &Error{Status: StatusResumeRejected, Detail: "resume state is empty"}
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var journalBytes C.uint64_t
	var blockCount C.uint32_t
	st := Status(C.dhow_resume_state_read(
		(*C.uint8_t)(unsafe.Pointer(&state[0])),
		C.size_t(len(state)),
		(*C.uint8_t)(unsafe.Pointer(&info.SessionID[0])),
		&journalBytes,
		&blockCount,
	))
	runtime.KeepAlive(state)
	if st != StatusOK {
		return ResumeInfo{}, wrap(st)
	}

	info.JournalBytes = uint64(journalBytes)
	info.BlockCount = uint32(blockCount)
	return info, nil
}

// Close releases the decoder.
//
// Safe to call more than once and on a nil receiver. Returns nothing for the
// same reason as [Key.Close].
func (d *Decoder) Close() {
	if d == nil || d.ptr == nil {
		return
	}
	C.dhow_decoder_free(d.ptr)
	d.ptr = nil
}

// QRCode is one frame rendered as a QR module grid.
//
// Modules is one byte per module, row-major, 1 for dark, so the grid is
// Size*Size bytes.
type QRCode struct {
	// Size is the number of modules per side.
	Size int
	// Modules holds the grid, row-major, 1 for dark.
	Modules []byte
}

// Dark reports whether the module at (x, y) is dark.
//
// Coordinates outside the grid read as light, so a renderer walking a quiet
// zone needs no bounds check.
func (q *QRCode) Dark(x, y int) bool {
	if x < 0 || y < 0 || x >= q.Size || y >= q.Size {
		return false
	}
	return q.Modules[y*q.Size+x] == 1
}

// QRCapacity reports how many bytes one QR code holds at a version and level.
//
// ecc is 'L', 'M', 'Q', or 'H'.
func QRCapacity(version int, ecc byte) (int, error) {
	n := C.dhow_qr_capacity(C.uint8_t(version), C.char(ecc))
	if n < 0 {
		return 0, wrap(Status(n))
	}
	return int(n), nil
}

// QRMaxSymbolSize reports the largest codec symbol size that fits one QR code.
//
// Returns 0 when the version is too small to hold even a frame header. A
// caller uses this to choose a symbol size the optical layer can carry, rather
// than picking one and discovering at render time that frames do not fit.
func QRMaxSymbolSize(version int, ecc byte) (int, error) {
	n := C.dhow_qr_max_symbol_size(C.uint8_t(version), C.char(ecc))
	if n < 0 {
		return 0, wrap(Status(n))
	}
	return int(n), nil
}

// EncodeQR renders one frame as a QR code.
//
// Pass version 0 to let the encoder choose the smallest version that fits.
func EncodeQR(frame []byte, version int, ecc byte) (*QRCode, error) {
	if len(frame) == 0 {
		return nil, errors.New("dhow: cannot encode an empty frame")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	framePtr := (*C.uint8_t)(unsafe.Pointer(&frame[0]))

	var size C.uint32_t
	var needed C.size_t
	st := Status(C.dhow_qr_encode_frame(
		framePtr, C.size_t(len(frame)),
		C.uint8_t(version), C.char(ecc),
		nil, 0, &size, &needed,
	))
	if st != StatusOK {
		return nil, wrap(st)
	}

	modules := make([]byte, int(needed))
	var written C.size_t
	st = Status(C.dhow_qr_encode_frame(
		framePtr, C.size_t(len(frame)),
		C.uint8_t(version), C.char(ecc),
		(*C.uint8_t)(unsafe.Pointer(&modules[0])), C.size_t(len(modules)),
		&size, &written,
	))
	runtime.KeepAlive(frame)
	runtime.KeepAlive(modules)
	if st != StatusOK {
		return nil, wrap(st)
	}

	return &QRCode{Size: int(size), Modules: modules[:int(written)]}, nil
}
