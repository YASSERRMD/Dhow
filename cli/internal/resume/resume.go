// Package resume persists a receiver's progress so a restart continues a
// transfer rather than beginning it again.
//
// # Why a journal
//
// The decoder's internal state cannot be serialized: RaptorQ's decoder is
// opaque and holds partially-solved linear systems, not a set of symbols. So
// progress is preserved the only way it can be, by keeping the frames that
// were accepted and replaying them into a fresh decoder on restart.
//
// A state directory holds two files:
//
//	journal.bin    every accepted frame, in acceptance order
//	resume.dhrs    the index over the journal, in the format proto/resume.md
//
// The journal is appended to on every accepted frame; the index is rewritten
// on an interval and on shutdown. Writing the index on every frame would cost
// a rewrite and two fsyncs per frame, which at forty frames a second is not a
// trade worth making for state that is disposable.
//
// # The two files can disagree, and that is expected
//
// Because the journal is written continuously and the index periodically, a
// crash routinely leaves a journal longer than the index describes. The index
// records the journal length it covers; the tail past that point is progress
// that was never durably recorded, and it is discarded. Treating it as
// corruption would throw away the whole transfer over an ordinary crash.
//
// The reverse - an index covering more journal than exists - is not expected
// and is not tolerated: [Store.Replay] refuses rather than replaying a prefix
// and hoping.
//
// # What this package does not protect against
//
// Nothing here is a security boundary. A resume file's digests catch
// corruption, not forgery, because anyone who can rewrite the file can
// recompute them. What keeps a doctored journal out is that every replayed
// frame is re-authenticated against the session key by the decoder, exactly as
// it was when first captured, and the state directory holds no key material.
package resume

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// File names within a state directory.
const (
	JournalName = "journal.bin"
	StateName   = "resume.dhrs"
)

// maxRecord bounds a journal record's declared length.
//
// A frame is a 46-byte header plus at most 65535 bytes of payload. The cap is
// generous rather than exact so a future frame size does not silently break
// resume, but it is a cap: without one, a corrupt length prefix would ask for
// an arbitrary allocation.
const maxRecord = 1 << 20

// recordPrefix is the byte length of a record's little-endian length prefix.
const recordPrefix = 4

// ErrNoState reports that a directory holds no saved progress.
//
// Not a failure: it is what an operator sees the first time they point a
// receiver at a fresh state directory.
var ErrNoState = errors.New("resume: no saved state")

// Store is a state directory.
type Store struct {
	dir     string
	state   []byte
	journal *os.File
	written uint64
}

// Open reads a state directory, creating it if it does not exist.
//
// The journal is not opened for writing yet. A caller that found saved state
// must replay it first, because [Store.Begin] truncates the journal to the
// length the state covers and appending before that would write into a region
// about to be discarded.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("resume: state directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state directory %s: %w", dir, err)
	}

	s := &Store{dir: dir}

	state, err := os.ReadFile(filepath.Join(dir, StateName))
	switch {
	case err == nil:
		s.state = state
	case errors.Is(err, os.ErrNotExist):
		// Nothing saved yet.
	default:
		return nil, fmt.Errorf("reading %s: %w", filepath.Join(dir, StateName), err)
	}

	return s, nil
}

// State returns the saved resume state, or ErrNoState if there is none.
func (s *Store) State() ([]byte, error) {
	if len(s.state) == 0 {
		return nil, ErrNoState
	}
	return s.state, nil
}

// Replay calls fn with each frame in the journal's first limit bytes.
//
// Frames are handed over in the order they were accepted, which is what makes
// a replay reproduce the decoder state that was saved. A record that runs past
// limit, or a journal shorter than limit, is a mismatch between the two files
// and is reported rather than worked around.
func (s *Store) Replay(limit uint64, fn func(frame []byte) error) (int, error) {
	path := filepath.Join(s.dir, JournalName)

	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("reading journal %s: %w", path, err)
	}
	if uint64(info.Size()) < limit {
		return 0, fmt.Errorf(
			"journal %s is %d bytes but the saved state covers %d; the pair is inconsistent",
			path, info.Size(), limit)
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening journal %s: %w", path, err)
	}
	// Read-only: a failing Close reports nothing the reads did not already.
	defer func() { _ = f.Close() }()

	var offset uint64
	count := 0
	prefix := make([]byte, recordPrefix)

	for offset < limit {
		if limit-offset < recordPrefix {
			return count, fmt.Errorf("journal record at offset %d is cut short by the covered length", offset)
		}
		if _, err := io.ReadFull(f, prefix); err != nil {
			return count, fmt.Errorf("reading journal record header at %d: %w", offset, err)
		}
		length := uint64(binary.LittleEndian.Uint32(prefix))
		if length == 0 || length > maxRecord {
			return count, fmt.Errorf("journal record at offset %d declares %d bytes", offset, length)
		}
		if limit-offset-recordPrefix < length {
			return count, fmt.Errorf("journal record at offset %d runs past the covered length", offset)
		}

		frame := make([]byte, length)
		if _, err := io.ReadFull(f, frame); err != nil {
			return count, fmt.Errorf("reading journal record at %d: %w", offset, err)
		}
		if err := fn(frame); err != nil {
			return count, fmt.Errorf("replaying journal record at %d: %w", offset, err)
		}

		offset += recordPrefix + length
		count++
	}

	return count, nil
}

// Begin opens the journal for appending, discarding anything past covered.
//
// covered is the journal length the saved state describes, or zero when there
// is none. The tail beyond it is progress that was never durably recorded;
// keeping it would leave a journal the next index could not describe.
func (s *Store) Begin(covered uint64) error {
	path := filepath.Join(s.dir, JournalName)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("opening journal %s: %w", path, err)
	}
	if err := f.Truncate(int64(covered)); err != nil {
		_ = f.Close()
		return fmt.Errorf("truncating journal %s to %d bytes: %w", path, covered, err)
	}
	if _, err := f.Seek(int64(covered), io.SeekStart); err != nil {
		_ = f.Close()
		return fmt.Errorf("seeking journal %s: %w", path, err)
	}

	s.journal = f
	s.written = covered
	return nil
}

// Append records one accepted frame.
//
// Only frames the decoder accepted belong here. A rejected frame never entered
// the decoder's state, so replaying it would produce a different one.
func (s *Store) Append(frame []byte) error {
	if s.journal == nil {
		return errors.New("resume: journal is not open; call Begin first")
	}
	if len(frame) == 0 || len(frame) > maxRecord {
		return fmt.Errorf("resume: refusing to journal a %d-byte frame", len(frame))
	}

	record := make([]byte, recordPrefix+len(frame))
	binary.LittleEndian.PutUint32(record, uint32(len(frame)))
	copy(record[recordPrefix:], frame)

	n, err := s.journal.Write(record)
	// Count what actually reached the file. A short write leaves a partial
	// record behind, and the next index must not claim to cover it.
	s.written += uint64(n)
	if err != nil {
		return fmt.Errorf("appending to journal: %w", err)
	}
	return nil
}

// Written returns the journal's current length in bytes.
func (s *Store) Written() uint64 {
	return s.written
}

// Save writes the resume state, durably and atomically.
//
// The journal is flushed first: an index that referenced bytes still sitting
// in the page cache would, after a power loss, describe a journal longer than
// the one on disk, which is the one inconsistency [Store.Replay] refuses to
// tolerate.
//
// The index itself is written to a temporary file and renamed, so a crash
// during the write leaves either the previous state or the new one, never a
// half-written file that fails its own digest.
func (s *Store) Save(state []byte) error {
	if len(state) == 0 {
		return errors.New("resume: refusing to save an empty state")
	}
	if s.journal != nil {
		if err := s.journal.Sync(); err != nil {
			return fmt.Errorf("flushing journal: %w", err)
		}
	}

	final := filepath.Join(s.dir, StateName)
	tmp := final + ".tmp"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tmp, err)
	}
	if _, err := f.Write(state); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("flushing %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmp, final, err)
	}

	s.state = state
	return nil
}

// Close flushes and releases the journal.
func (s *Store) Close() error {
	if s.journal == nil {
		return nil
	}
	f := s.journal
	s.journal = nil

	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("flushing journal: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing journal: %w", err)
	}
	return nil
}

// Discard removes the journal and the index.
//
// Called once a transfer has completed and verified, when the state has done
// its job. Left behind, it would be picked up by the next transfer pointed at
// the same directory and rejected as belonging to a foreign session, which is
// a confusing way to learn that a stale file exists.
//
// Only the two files this package writes are removed; the directory itself and
// anything an operator put in it are left alone.
func (s *Store) Discard() error {
	if err := s.Close(); err != nil {
		return err
	}
	for _, name := range []string{JournalName, StateName} {
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing %s: %w", filepath.Join(s.dir, name), err)
		}
	}
	s.state = nil
	s.written = 0
	return nil
}

// Dir returns the state directory's path.
func (s *Store) Dir() string {
	return s.dir
}
