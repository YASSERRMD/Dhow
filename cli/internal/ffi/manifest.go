package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/../../../core/include
#include <stdlib.h>
#include "dhow.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// FileEntry is one file's line in a manifest's inventory.
//
// Everything here is authenticated: a receiver that verifies the manifest knows
// the sender stated exactly these names, sizes, digests, and modes.
type FileEntry struct {
	// Name is the file's path within the dataset, relative and
	// slash-separated.
	Name string
	// Size is its length in bytes.
	Size uint64
	// Digest is the BLAKE3 digest of the file's contents.
	Digest [32]byte
	// Executable records whether the owner execute bit was set on the sender.
	Executable bool
}

// Manifest is a signed description of a transfer.
//
// A value of this type can only be obtained by building one from an [Identity]
// or by verifying one against a [PublicIdentity], so holding one means the
// signature was checked. There is no way to parse into it.
//
// Close it when finished.
type Manifest struct {
	ptr *C.DhowManifest
}

// BuildManifest signs a description of a transfer.
//
// The total size is summed from the entries by the core rather than declared
// here, so a sender cannot state a total that disagrees with its own inventory.
func BuildManifest(
	identity *Identity,
	sessionID [16]byte,
	salt [32]byte,
	nonce [24]byte,
	params SessionParams,
	entries []FileEntry,
) (*Manifest, error) {
	if identity == nil || identity.ptr == nil {
		return nil, errors.New("dhow: identity is closed")
	}

	// The C entries borrow their names, so every CString must outlive the call.
	// They are freed together after it returns rather than with individual
	// defers, which would free the first name before the last was allocated in
	// an error path.
	names := make([]*C.char, len(entries))
	defer func() {
		for _, n := range names {
			C.free(unsafe.Pointer(n))
		}
	}()

	cEntries := make([]C.DhowFileEntry, len(entries))
	for i, e := range entries {
		names[i] = C.CString(e.Name)
		cEntries[i].name = names[i]
		cEntries[i].size = C.uint64_t(e.Size)
		for j, b := range e.Digest {
			cEntries[i].digest[j] = C.uint8_t(b)
		}
		if e.Executable {
			cEntries[i].executable = 1
		}
	}

	// A dataset of no files is unusual and not malformed, and the core reads a
	// null array only when the count is zero.
	entryPtr := (*C.DhowFileEntry)(nil)
	if len(cEntries) > 0 {
		entryPtr = &cEntries[0]
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ptr := C.dhow_manifest_build(
		identity.ptr,
		(*C.uint8_t)(unsafe.Pointer(&sessionID[0])),
		(*C.uint8_t)(unsafe.Pointer(&salt[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		params.toC(),
		entryPtr,
		C.size_t(len(cEntries)),
	)
	runtime.KeepAlive(cEntries)
	if ptr == nil {
		return nil, &Error{Status: StatusVerificationFail, Detail: lastError()}
	}
	return &Manifest{ptr: ptr}, nil
}

// VerifyManifest checks a manifest's signature against a public identity.
//
// expectSession may be nil, meaning the caller has nothing to bind the manifest
// to yet: the manifest is what tells a receiver which session this is. Pass a
// session identifier when one is already in hand - resumed state, or a session
// header read off the wire - so a correctly signed manifest from a different
// transfer between the same operators is rejected.
func VerifyManifest(public *PublicIdentity, bytes []byte, expectSession *[16]byte) (*Manifest, error) {
	if public == nil || public.ptr == nil {
		return nil, errors.New("dhow: public identity is closed")
	}
	if len(bytes) == 0 {
		return nil, errors.New("dhow: manifest is empty")
	}

	sessionPtr := (*C.uint8_t)(nil)
	if expectSession != nil {
		sessionPtr = (*C.uint8_t)(unsafe.Pointer(&expectSession[0]))
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ptr := C.dhow_manifest_verify(
		public.ptr,
		(*C.uint8_t)(unsafe.Pointer(&bytes[0])),
		C.size_t(len(bytes)),
		sessionPtr,
	)
	runtime.KeepAlive(bytes)
	if ptr == nil {
		return nil, &Error{Status: StatusVerificationFail, Detail: lastError()}
	}
	return &Manifest{ptr: ptr}, nil
}

// Bytes returns the manifest's wire encoding, signature included.
func (m *Manifest) Bytes() ([]byte, error) {
	if m == nil || m.ptr == nil {
		return nil, errors.New("dhow: manifest is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var needed C.size_t
	if st := Status(C.dhow_manifest_bytes(m.ptr, nil, 0, &needed)); st != StatusOK {
		return nil, wrap(st)
	}
	buf := make([]byte, int(needed))
	st := Status(C.dhow_manifest_bytes(
		m.ptr,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		nil,
	))
	if st != StatusOK {
		return nil, wrap(st)
	}
	return buf, nil
}

// SessionID returns the transfer's 16-byte session identifier.
func (m *Manifest) SessionID() ([16]byte, error) {
	var out [16]byte
	if m == nil || m.ptr == nil {
		return out, errors.New("dhow: manifest is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if st := Status(C.dhow_manifest_session_id(m.ptr, (*C.uint8_t)(unsafe.Pointer(&out[0])))); st != StatusOK {
		return [16]byte{}, wrap(st)
	}
	return out, nil
}

// Salt returns the transfer's 32-byte HKDF salt.
func (m *Manifest) Salt() ([32]byte, error) {
	var out [32]byte
	if m == nil || m.ptr == nil {
		return out, errors.New("dhow: manifest is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if st := Status(C.dhow_manifest_salt(m.ptr, (*C.uint8_t)(unsafe.Pointer(&out[0])))); st != StatusOK {
		return [32]byte{}, wrap(st)
	}
	return out, nil
}

// Nonce returns the transfer's 24-byte AEAD nonce.
func (m *Manifest) Nonce() ([24]byte, error) {
	var out [24]byte
	if m == nil || m.ptr == nil {
		return out, errors.New("dhow: manifest is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if st := Status(C.dhow_manifest_nonce(m.ptr, (*C.uint8_t)(unsafe.Pointer(&out[0])))); st != StatusOK {
		return [24]byte{}, wrap(st)
	}
	return out, nil
}

// Params returns the coding parameters the sender used.
func (m *Manifest) Params() (SessionParams, error) {
	if m == nil || m.ptr == nil {
		return SessionParams{}, errors.New("dhow: manifest is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var c C.DhowSessionParams
	if st := Status(C.dhow_manifest_params(m.ptr, &c)); st != StatusOK {
		return SessionParams{}, wrap(st)
	}
	return paramsFromC(c), nil
}

// Files returns the whole inventory, read one entry at a time through the
// core's indexed accessors.
func (m *Manifest) Files() ([]FileEntry, error) {
	if m == nil || m.ptr == nil {
		return nil, errors.New("dhow: manifest is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	count := int(C.dhow_manifest_file_count(m.ptr))
	if count < 0 {
		return nil, wrap(Status(count))
	}

	entries := make([]FileEntry, 0, count)
	for i := range count {
		entry, err := m.fileAt(C.size_t(i))
		if err != nil {
			return nil, fmt.Errorf("reading manifest entry %d: %w", i, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// fileAt reads one entry. The caller holds the OS thread lock.
func (m *Manifest) fileAt(i C.size_t) (FileEntry, error) {
	var needed C.size_t
	if st := Status(C.dhow_manifest_file_name(m.ptr, i, nil, 0, &needed)); st != StatusOK {
		return FileEntry{}, wrap(st)
	}

	// An entry with an empty name cannot exist - the core rejects it at parse
	// time - but taking &buf[0] of an empty slice would panic, so the buffer is
	// never zero-length.
	buf := make([]byte, int(needed)+1)
	st := Status(C.dhow_manifest_file_name(
		m.ptr,
		i,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(needed),
		nil,
	))
	if st != StatusOK {
		return FileEntry{}, wrap(st)
	}

	var size C.uint64_t
	if st := Status(C.dhow_manifest_file_size(m.ptr, i, &size)); st != StatusOK {
		return FileEntry{}, wrap(st)
	}

	var digest [32]byte
	if st := Status(C.dhow_manifest_file_digest(m.ptr, i, (*C.uint8_t)(unsafe.Pointer(&digest[0])))); st != StatusOK {
		return FileEntry{}, wrap(st)
	}

	executable := C.dhow_manifest_file_executable(m.ptr, i)
	if executable < 0 {
		return FileEntry{}, wrap(Status(executable))
	}

	return FileEntry{
		Name:       string(buf[:needed]),
		Size:       uint64(size),
		Digest:     digest,
		Executable: executable == 1,
	}, nil
}

// Close releases the manifest.
func (m *Manifest) Close() {
	if m == nil || m.ptr == nil {
		return
	}
	C.dhow_manifest_free(m.ptr)
	m.ptr = nil
}
