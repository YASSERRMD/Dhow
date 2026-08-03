package ffi

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var (
	testSession = [16]byte{0x5A, 0x5A, 0x5A, 0x5A}
	testSalt    = [32]byte{0x11, 0x22, 0x33}
	testNonce   = [24]byte{0x44, 0x55, 0x66}
)

// paramsFor builds session parameters sized for a plaintext of the given
// length. The ciphertext is longer by the 16-byte AEAD tag.
func paramsFor(plaintextLen int) SessionParams {
	const symbolSize = 256
	ciphertextLen := uint64(plaintextLen + 16)

	source := (ciphertextLen + symbolSize - 1) / symbolSize
	if source == 0 {
		source = 1
	}

	return SessionParams{
		PayloadSize:           ciphertextLen,
		BlockCount:            1,
		SymbolSize:            symbolSize,
		SourceSymbolsPerBlock: uint32(source),
		// Half again as many symbols as strictly needed, so a receiver that
		// misses frames can still recover.
		TotalSymbolsPerBlock: uint32(source + source/2 + 4),
	}
}

// transfer runs a full send and receive cycle, optionally dropping frames.
func transfer(t *testing.T, plaintext []byte, keep func(i int) bool) ([]byte, error) {
	t.Helper()

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer key.Close()

	enc, err := NewEncoder(key, testSession, testSalt, testNonce, paramsFor(len(plaintext)), plaintext)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	defer enc.Close()

	frames, err := enc.Frames()
	if err != nil {
		t.Fatalf("Frames: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("encoder produced no frames")
	}

	// The encoder resolves payload size and digest from the ciphertext; a real
	// sender puts these in the signed manifest.
	params, err := enc.Params()
	if err != nil {
		t.Fatalf("Params: %v", err)
	}

	dec, err := NewDecoder(key, testSession, testSalt, params)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	defer dec.Close()

	for i, frame := range frames {
		if keep != nil && !keep(i) {
			continue
		}
		if err := dec.Accept(frame); err != nil {
			t.Fatalf("Accept frame %d: %v", i, err)
		}
	}

	return dec.Finish(key, testSession, testSalt, testNonce)
}

func TestABIVersionMatches(t *testing.T) {
	// A mismatch means Go and Rust disagree about handle layout, which must be
	// caught at startup rather than surfacing as memory corruption.
	if got := ABIVersion(); got != 2 {
		t.Errorf("ABIVersion() = %d, want 2", got)
	}
}

func TestVersionIsReported(t *testing.T) {
	if Version() == "" {
		t.Error("Version() returned an empty string")
	}
}

func TestRoundTrip(t *testing.T) {
	plaintext := []byte("payload crossing cgo into the Rust core")

	got, err := transfer(t, plaintext, nil)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip mismatch:\n got %q\nwant %q", got, plaintext)
	}
}

func TestRoundTripAcrossSizes(t *testing.T) {
	for _, size := range []int{1, 100, 255, 256, 1024, 8192, 65536} {
		plaintext := make([]byte, size)
		for i := range plaintext {
			plaintext[i] = byte(i % 251)
		}

		got, err := transfer(t, plaintext, nil)
		if err != nil {
			t.Fatalf("size %d: Finish: %v", size, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("size %d: round trip mismatch", size)
		}
	}
}

func TestRoundTripSurvivesDroppedFrames(t *testing.T) {
	plaintext := make([]byte, 16384)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}

	// Drop every fourth frame, as a camera missing captures would.
	got, err := transfer(t, plaintext, func(i int) bool { return i%4 != 0 })
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("transfer did not survive dropped frames")
	}
}

func TestFramesCarryNoPlaintext(t *testing.T) {
	// The optical channel is public, so a recognizable run must not appear.
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer key.Close()

	plaintext := bytes.Repeat([]byte{0xC3}, 4096)
	enc, err := NewEncoder(key, testSession, testSalt, testNonce, paramsFor(len(plaintext)), plaintext)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	defer enc.Close()

	frames, err := enc.Frames()
	if err != nil {
		t.Fatalf("Frames: %v", err)
	}

	needle := bytes.Repeat([]byte{0xC3}, 32)
	for i, frame := range frames {
		if bytes.Contains(frame, needle) {
			t.Fatalf("frame %d carried a recognizable run of plaintext", i)
		}
	}
}

func TestGarbageFramesAreRejected(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer key.Close()

	dec, err := NewDecoder(key, testSession, testSalt, paramsFor(1024))
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	defer dec.Close()

	for _, garbage := range [][]byte{
		{},
		{0x00},
		make([]byte, 45),
		bytes.Repeat([]byte{0xFF}, 46),
		bytes.Repeat([]byte{0xAB}, 512),
	} {
		err := dec.Accept(garbage)
		if err == nil {
			t.Errorf("garbage of %d bytes was accepted", len(garbage))
			continue
		}
		if !errors.Is(err, ErrFrameRejected) {
			t.Errorf("garbage of %d bytes: got %v, want ErrFrameRejected", len(garbage), err)
		}
	}
}

func TestFinishBeforeCompletionReportsIncomplete(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer key.Close()

	dec, err := NewDecoder(key, testSession, testSalt, paramsFor(65536))
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	defer dec.Close()

	_, err = dec.Finish(key, testSession, testSalt, testNonce)
	if !errors.Is(err, ErrIncomplete) {
		t.Errorf("got %v, want ErrIncomplete", err)
	}
}

func TestInvalidParametersAreRejected(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer key.Close()

	params := paramsFor(1024)
	params.SymbolSize = 8 // below the FEC minimum

	if _, err := NewDecoder(key, testSession, testSalt, params); err == nil {
		t.Error("invalid parameters produced a decoder")
	}
}

func TestClosedHandlesAreRefusedNotDereferenced(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	enc, err := NewEncoder(key, testSession, testSalt, testNonce, paramsFor(64), []byte("data for a closed handle test"))
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}

	dec, err := NewDecoder(key, testSession, testSalt, paramsFor(64))
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}

	// Close everything, then confirm each method reports rather than crashes.
	enc.Close()
	dec.Close()
	key.Close()

	if _, err := enc.FrameCount(); err == nil {
		t.Error("FrameCount on a closed encoder returned no error")
	}
	if _, err := enc.Frame(0); err == nil {
		t.Error("Frame on a closed encoder returned no error")
	}
	if _, err := enc.Params(); err == nil {
		t.Error("Params on a closed encoder returned no error")
	}
	if err := dec.Accept([]byte{1, 2, 3}); err == nil {
		t.Error("Accept on a closed decoder returned no error")
	}
	if _, err := dec.IsComplete(); err == nil {
		t.Error("IsComplete on a closed decoder returned no error")
	}
	if err := key.Save("/tmp/should-not-be-written"); err == nil {
		t.Error("Save on a closed key returned no error")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	// Cleanup paths and deferred Close calls must not double-free.
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// Repeated Close must not double-free.
	for range 3 {
		key.Close()
	}

	// A nil receiver must be safe, so cleanup paths need no guard.
	var nilKey *Key
	nilKey.Close()
	var nilEnc *Encoder
	nilEnc.Close()
	var nilDec *Decoder
	nilDec.Close()
}

func TestKeySaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer key.Close()

	if err := key.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}

	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	defer loaded.Close()
}

func TestLoadKeyRejectsPermissiveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer key.Close()

	if err := key.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	// A secret that was world-readable must be treated as disclosed.
	if _, err := LoadKey(path); err == nil {
		t.Error("a world-readable key file was accepted")
	}
}

func TestLoadKeyOfMissingFileFails(t *testing.T) {
	if _, err := LoadKey(filepath.Join(t.TempDir(), "absent.key")); err == nil {
		t.Error("loading a missing key file returned no error")
	}
}

func TestErrorCarriesStatusAndDetail(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer key.Close()

	dec, err := NewDecoder(key, testSession, testSalt, paramsFor(1024))
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	defer dec.Close()

	err = dec.Accept(make([]byte, 46))
	if err == nil {
		t.Fatal("a malformed frame was accepted")
	}

	var ffiErr *Error
	if !errors.As(err, &ffiErr) {
		t.Fatalf("got %T, want *ffi.Error", err)
	}
	if ffiErr.Status != StatusFrameRejected {
		t.Errorf("Status = %d, want %d", ffiErr.Status, StatusFrameRejected)
	}
	if ffiErr.Detail == "" {
		t.Error("Detail was empty; the Rust description did not cross the boundary")
	}
	if msg := err.Error(); msg == "" {
		t.Error("Error() returned an empty string")
	}
}

func TestErrorMessagesCarryNoKeyMaterial(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer key.Close()

	dec, err := NewDecoder(key, testSession, testSalt, paramsFor(1024))
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	defer dec.Close()

	err = dec.Accept(bytes.Repeat([]byte{0x5A}, 46))
	if err == nil {
		t.Fatal("a malformed frame was accepted")
	}

	msg := err.Error()
	for _, forbidden := range []string{"operator key", "session key", "payload key", "seed"} {
		if bytes.Contains(bytes.ToLower([]byte(msg)), []byte(forbidden)) {
			t.Errorf("error message mentioned %q: %s", forbidden, msg)
		}
	}
}

func TestStatusStringsAreAvailable(t *testing.T) {
	for _, s := range []Status{
		StatusOK, StatusNullArgument, StatusInvalidArgument, StatusBufferTooSmall,
		StatusInvalidParameters, StatusFrameRejected, StatusIncomplete,
		StatusVerificationFail, StatusCryptoFailed, StatusKeyFailed,
		StatusInternal, StatusPanic, StatusResumeRejected,
	} {
		if got := statusString(s); got == "" || got == "unknown status" {
			t.Errorf("status %d has no description (got %q)", s, got)
		}
	}
}

func TestConcurrentTransfersDoNotInterfere(t *testing.T) {
	// The last-error channel is thread-local in Rust. Concurrent callers must
	// not see each other's failures.
	const workers = 8
	errCh := make(chan error, workers)

	for range workers {
		go func() {
			plaintext := bytes.Repeat([]byte{0x7E}, 2048)
			key, err := GenerateKey()
			if err != nil {
				errCh <- err
				return
			}
			defer key.Close()

			enc, err := NewEncoder(key, testSession, testSalt, testNonce, paramsFor(len(plaintext)), plaintext)
			if err != nil {
				errCh <- err
				return
			}
			defer enc.Close()

			frames, err := enc.Frames()
			if err != nil {
				errCh <- err
				return
			}
			params, err := enc.Params()
			if err != nil {
				errCh <- err
				return
			}

			dec, err := NewDecoder(key, testSession, testSalt, params)
			if err != nil {
				errCh <- err
				return
			}
			defer dec.Close()

			for _, f := range frames {
				if err := dec.Accept(f); err != nil {
					errCh <- err
					return
				}
			}
			got, err := dec.Finish(key, testSession, testSalt, testNonce)
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(got, plaintext) {
				errCh <- errors.New("concurrent round trip mismatch")
				return
			}
			errCh <- nil
		}()
	}

	for range workers {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent transfer failed: %v", err)
		}
	}
}

// --- Resume ---

// encodeSession builds the frames for a transfer and the parameters a decoder
// needs to read them back.
func encodeSession(t *testing.T, plaintext []byte) (*Key, [][]byte, SessionParams) {
	t.Helper()

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Cleanup(key.Close)

	enc, err := NewEncoder(key, testSession, testSalt, testNonce, paramsFor(len(plaintext)), plaintext)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	defer enc.Close()

	frames, err := enc.Frames()
	if err != nil {
		t.Fatalf("Frames: %v", err)
	}
	params, err := enc.Params()
	if err != nil {
		t.Fatalf("Params: %v", err)
	}
	return key, frames, params
}

// fedDecoder returns a decoder that has accepted every frame in stream.
func fedDecoder(t *testing.T, key *Key, params SessionParams, stream [][]byte) *Decoder {
	t.Helper()

	dec, err := NewDecoder(key, testSession, testSalt, params)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	t.Cleanup(dec.Close)

	for i, frame := range stream {
		if err := dec.Accept(frame); err != nil {
			t.Fatalf("Accept(%d): %v", i, err)
		}
	}
	return dec
}

func TestResumeStateCompletesAnInterruptedTransfer(t *testing.T) {
	plaintext := make([]byte, 8192)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}

	key, frames, params := encodeSession(t, plaintext)

	// Stop a third of the way through, as a killed receiver would.
	taken := frames[:len(frames)/3]
	var journalBytes uint64
	for _, f := range taken {
		journalBytes += uint64(len(f))
	}

	first := fedDecoder(t, key, params, taken)
	if complete, err := first.IsComplete(); err != nil || complete {
		t.Fatalf("the test needs an unfinished transfer (complete=%v err=%v)", complete, err)
	}
	state, err := first.ResumeState(journalBytes)
	if err != nil {
		t.Fatalf("ResumeState: %v", err)
	}

	info, err := ReadResumeState(state)
	if err != nil {
		t.Fatalf("ReadResumeState: %v", err)
	}
	if info.SessionID != testSession {
		t.Errorf("session = %x, want %x", info.SessionID, testSession)
	}
	if info.JournalBytes != journalBytes {
		t.Errorf("journal bytes = %d, want %d", info.JournalBytes, journalBytes)
	}
	if info.BlockCount != params.BlockCount {
		t.Errorf("block count = %d, want %d", info.BlockCount, params.BlockCount)
	}

	// Replay, verify, and finish from what was still to come.
	second := fedDecoder(t, key, params, taken)
	if err := second.VerifyResume(state); err != nil {
		t.Fatalf("VerifyResume on a faithful replay: %v", err)
	}
	for i, frame := range frames[len(taken):] {
		if err := second.Accept(frame); err != nil {
			t.Fatalf("Accept after resume (%d): %v", i, err)
		}
	}

	out, err := second.Finish(key, testSession, testSalt, testNonce)
	if err != nil {
		t.Fatalf("Finish after resume: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Errorf("resumed transfer recovered %d bytes, want %d", len(out), len(plaintext))
	}
}

func TestVerifyResumeRejectsADivergentReplay(t *testing.T) {
	plaintext := make([]byte, 4096)
	key, frames, params := encodeSession(t, plaintext)

	taken := frames[:10]
	state, err := fedDecoder(t, key, params, taken).ResumeState(1000)
	if err != nil {
		t.Fatalf("ResumeState: %v", err)
	}

	for name, stream := range map[string][][]byte{
		"one frame short":  taken[:len(taken)-1],
		"nothing replayed": {},
		"one frame extra":  frames[:11],
	} {
		err := fedDecoder(t, key, params, stream).VerifyResume(state)
		if !errors.Is(err, ErrResumeRejected) {
			t.Errorf("%s: err = %v, want ErrResumeRejected", name, err)
		}
	}
}

func TestResumeStateRejectsCorruptionAndTruncation(t *testing.T) {
	plaintext := make([]byte, 2048)
	key, frames, params := encodeSession(t, plaintext)
	dec := fedDecoder(t, key, params, frames[:6])

	good, err := dec.ResumeState(700)
	if err != nil {
		t.Fatalf("ResumeState: %v", err)
	}

	for _, offset := range []int{0, 4, 8, 30, 40, 92, 100, len(good) - 1} {
		bad := bytes.Clone(good)
		bad[offset] ^= 0x01
		if _, err := ReadResumeState(bad); !errors.Is(err, ErrResumeRejected) {
			t.Errorf("ReadResumeState accepted a flip at %d: %v", offset, err)
		}
		if err := dec.VerifyResume(bad); !errors.Is(err, ErrResumeRejected) {
			t.Errorf("VerifyResume accepted a flip at %d: %v", offset, err)
		}
	}

	for _, n := range []int{0, 1, 64, 127, len(good) - 1} {
		if _, err := ReadResumeState(good[:n]); !errors.Is(err, ErrResumeRejected) {
			t.Errorf("ReadResumeState accepted %d bytes: %v", n, err)
		}
	}
}

func TestResumeStateRejectsAnotherSession(t *testing.T) {
	plaintext := make([]byte, 2048)
	key, frames, params := encodeSession(t, plaintext)

	other := [16]byte{0x99, 0x88}
	enc, err := NewEncoder(key, other, testSalt, testNonce, paramsFor(len(plaintext)), plaintext)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	defer enc.Close()
	otherFrames, err := enc.Frames()
	if err != nil {
		t.Fatalf("Frames: %v", err)
	}

	otherDec, err := NewDecoder(key, other, testSalt, params)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	defer otherDec.Close()
	for _, f := range otherFrames[:6] {
		if err := otherDec.Accept(f); err != nil {
			t.Fatalf("Accept: %v", err)
		}
	}
	state, err := otherDec.ResumeState(500)
	if err != nil {
		t.Fatalf("ResumeState: %v", err)
	}

	// The state announces its own session, so a caller can refuse it before
	// replaying anything.
	info, err := ReadResumeState(state)
	if err != nil {
		t.Fatalf("ReadResumeState: %v", err)
	}
	if info.SessionID != other {
		t.Errorf("session = %x, want %x", info.SessionID, other)
	}

	err = fedDecoder(t, key, params, frames[:6]).VerifyResume(state)
	if !errors.Is(err, ErrResumeRejected) {
		t.Errorf("VerifyResume across sessions: err = %v, want ErrResumeRejected", err)
	}
}

func TestResumeCallsOnClosedHandlesAreRefused(t *testing.T) {
	plaintext := make([]byte, 1024)
	key, frames, params := encodeSession(t, plaintext)

	dec, err := NewDecoder(key, testSession, testSalt, params)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	if err := dec.Accept(frames[0]); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	state, err := dec.ResumeState(100)
	if err != nil {
		t.Fatalf("ResumeState: %v", err)
	}
	dec.Close()

	if _, err := dec.ResumeState(100); err == nil {
		t.Error("ResumeState on a closed decoder returned no error")
	}
	if err := dec.VerifyResume(state); err == nil {
		t.Error("VerifyResume on a closed decoder returned no error")
	}
	var nilDec *Decoder
	if _, err := nilDec.ResumeState(0); err == nil {
		t.Error("ResumeState on a nil decoder returned no error")
	}
}
