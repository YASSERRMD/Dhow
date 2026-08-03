package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/../../../core/include
#include <stdlib.h>
#include "dhow.h"
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

// Identity is an Ed25519 signing identity.
//
// It is a different secret from an operator key and follows the opposite
// distribution rule: both operators hold the same operator key, and only the
// sender holds the identity's secret half. A signature made with a key the
// receiver also holds proves nothing the receiver could not have produced
// itself, which is why the two are separate handles rather than one.
//
// Close it when finished. The secret half never crosses into Go.
type Identity struct {
	ptr *C.DhowIdentity
}

// PublicIdentity is the half a receiver holds in order to verify signatures.
//
// It carries no secret and may be copied, published, or printed.
type PublicIdentity struct {
	ptr *C.DhowPublicIdentity
}

// GenerateIdentity draws a new signing identity from the system CSPRNG.
func GenerateIdentity() (*Identity, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ptr := C.dhow_identity_generate()
	if ptr == nil {
		return nil, &Error{Status: StatusKeyFailed, Detail: lastError()}
	}
	return &Identity{ptr: ptr}, nil
}

// LoadIdentity reads a signing identity from a key file.
//
// Fails if the file is missing, malformed, readable by anyone but its owner, or
// holds an operator key rather than an identity.
func LoadIdentity(path string) (*Identity, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	ptr := C.dhow_identity_load(cPath)
	if ptr == nil {
		return nil, &Error{Status: StatusKeyFailed, Detail: lastError()}
	}
	return &Identity{ptr: ptr}, nil
}

// Save writes the identity to path with owner-only permissions.
func (i *Identity) Save(path string) error {
	if i == nil || i.ptr == nil {
		return errors.New("dhow: identity is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	return wrap(Status(C.dhow_identity_save(i.ptr, cPath)))
}

// Public returns the public half as a handle the caller owns and must Close.
func (i *Identity) Public() (*PublicIdentity, error) {
	if i == nil || i.ptr == nil {
		return nil, errors.New("dhow: identity is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ptr := C.dhow_identity_public(i.ptr)
	if ptr == nil {
		return nil, &Error{Status: StatusKeyFailed, Detail: lastError()}
	}
	return &PublicIdentity{ptr: ptr}, nil
}

// Close releases the identity, zeroizing its secret half.
//
// Safe to call more than once and on a nil receiver, for the same reason as
// [Key.Close].
func (i *Identity) Close() {
	if i == nil || i.ptr == nil {
		return
	}
	C.dhow_identity_free(i.ptr)
	i.ptr = nil
}

// LoadPublicIdentity reads a 32-byte public identity file.
func LoadPublicIdentity(path string) (*PublicIdentity, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	ptr := C.dhow_public_load(cPath)
	if ptr == nil {
		return nil, &Error{Status: StatusKeyFailed, Detail: lastError()}
	}
	return &PublicIdentity{ptr: ptr}, nil
}

// Save writes the public identity to path.
func (p *PublicIdentity) Save(path string) error {
	if p == nil || p.ptr == nil {
		return errors.New("dhow: public identity is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	return wrap(Status(C.dhow_public_save(p.ptr, cPath)))
}

// Bytes returns the 32-byte encoding of the public identity.
func (p *PublicIdentity) Bytes() ([32]byte, error) {
	var out [32]byte
	if p == nil || p.ptr == nil {
		return out, errors.New("dhow: public identity is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if st := Status(C.dhow_public_bytes(p.ptr, (*C.uint8_t)(unsafe.Pointer(&out[0])))); st != StatusOK {
		return [32]byte{}, wrap(st)
	}
	return out, nil
}

// Fingerprint returns a short colon-separated digest for an operator to compare
// two machines by eye.
//
// It is truncated and must not be used as an identifier in any security check;
// the verification that matters is the signature.
func (p *PublicIdentity) Fingerprint() (string, error) {
	if p == nil || p.ptr == nil {
		return "", errors.New("dhow: public identity is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var needed C.size_t
	if st := Status(C.dhow_public_fingerprint(p.ptr, nil, 0, &needed)); st != StatusOK {
		return "", wrap(st)
	}
	if needed == 0 {
		return "", nil
	}
	buf := make([]byte, int(needed))
	st := Status(C.dhow_public_fingerprint(
		p.ptr,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		nil,
	))
	if st != StatusOK {
		return "", wrap(st)
	}
	return string(buf), nil
}

// Close releases the public identity.
func (p *PublicIdentity) Close() {
	if p == nil || p.ptr == nil {
		return
	}
	C.dhow_public_free(p.ptr)
	p.ptr = nil
}
