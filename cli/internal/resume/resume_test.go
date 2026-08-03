package resume

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// frames builds n distinguishable frames of varying length, so a replay that
// returns them in the wrong order or drops one is visible.
func frames(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		frame := make([]byte, 8+i%5)
		for j := range frame {
			frame[j] = byte(i)
		}
		out[i] = frame
	}
	return out
}

// collect replays a store and returns every frame it handed back.
func collect(t *testing.T, s *Store, limit uint64) [][]byte {
	t.Helper()
	var got [][]byte
	n, err := s.Replay(limit, func(frame []byte) error {
		got = append(got, bytes.Clone(frame))
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if n != len(got) {
		t.Errorf("Replay reported %d records but delivered %d", n, len(got))
	}
	return got
}

func TestOpenOnAFreshDirectoryReportsNoState(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.State(); !errors.Is(err, ErrNoState) {
		t.Errorf("State() err = %v, want ErrNoState", err)
	}
}

func TestOpenCreatesTheDirectoryOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if _, err := Open(dir); err != nil {
		t.Fatalf("Open: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// The journal holds captured frames. They are ciphertext, but there is no
	// reason for another user on the machine to read them.
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("state directory mode = %o, want 700", perm)
	}
}

func TestAppendAndReplayRoundTripInOrder(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Begin(0); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	want := frames(12)
	for i, frame := range want {
		if err := s.Append(frame); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}
	covered := s.Written()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := collect(t, s, covered)
	if len(got) != len(want) {
		t.Fatalf("replayed %d frames, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("frame %d = %x, want %x", i, got[i], want[i])
		}
	}
}

func TestWrittenTracksTheFileLength(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Begin(0); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	for _, frame := range frames(7) {
		if err := s.Append(frame); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, JournalName))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if uint64(info.Size()) != s.Written() {
		t.Errorf("Written() = %d but the journal is %d bytes", s.Written(), info.Size())
	}
}

func TestReplayStopsAtTheCoveredLength(t *testing.T) {
	// The case a crash produces: the journal was appended to after the last
	// index was written, so it holds frames the index does not describe.
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Begin(0); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	all := frames(10)
	for _, frame := range all[:6] {
		if err := s.Append(frame); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	covered := s.Written()
	for _, frame := range all[6:] {
		if err := s.Append(frame); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := collect(t, s, covered); len(got) != 6 {
		t.Errorf("replayed %d frames past the covered length, want 6", len(got))
	}
}

func TestBeginDiscardsTheUncoveredTail(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Begin(0); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	all := frames(10)
	for _, frame := range all[:6] {
		if err := s.Append(frame); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	covered := s.Written()
	for _, frame := range all[6:] {
		if err := s.Append(frame); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A restart replays the covered prefix and resumes writing at its end, so
	// the frames the index never described are gone.
	restarted, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := restarted.Begin(covered); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if restarted.Written() != covered {
		t.Errorf("Written() = %d after Begin(%d)", restarted.Written(), covered)
	}
	if err := restarted.Append(all[9]); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := collect(t, restarted, restarted.Written())
	if len(got) != 7 {
		t.Fatalf("replayed %d frames, want 7", len(got))
	}
	if !bytes.Equal(got[6], all[9]) {
		t.Errorf("last frame = %x, want %x", got[6], all[9])
	}
}

func TestReplayRefusesAJournalShorterThanTheState(t *testing.T) {
	// The inconsistency a crash does not produce: an index describing more
	// journal than exists. Replaying a prefix would silently resume from less
	// progress than the state claims, and the mismatch would only surface
	// later as a failed verification.
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Begin(0); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for _, frame := range frames(4) {
		if err := s.Append(frame); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	covered := s.Written()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := s.Replay(covered+1, func([]byte) error { return nil }); err == nil {
		t.Error("Replay accepted a state covering more than the journal holds")
	}
}

func TestReplayRejectsCorruptRecordHeaders(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Begin(0); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for _, frame := range frames(4) {
		if err := s.Append(frame); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	covered := s.Written()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	path := filepath.Join(dir, JournalName)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	cases := map[string]uint32{
		"zero length":        0,
		"absurd length":      0xFFFFFFFF,
		"runs past the tail": uint32(covered),
	}
	for name, length := range cases {
		bad := bytes.Clone(good)
		binary.LittleEndian.PutUint32(bad, length)
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := s.Replay(covered, func([]byte) error { return nil }); err == nil {
			t.Errorf("%s: Replay accepted a corrupt record header", name)
		}
	}
}

func TestReplayPropagatesTheCallbackError(t *testing.T) {
	// The decoder rejecting a replayed frame is how a doctored journal is
	// caught, so that error must reach the caller rather than be swallowed.
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Begin(0); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for _, frame := range frames(4) {
		if err := s.Append(frame); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	covered := s.Written()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sentinel := errors.New("decoder said no")
	seen := 0
	_, err := s.Replay(covered, func([]byte) error {
		seen++
		if seen == 3 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("Replay err = %v, want it to wrap the callback error", err)
	}
	if seen != 3 {
		t.Errorf("Replay kept going after the callback failed (%d records)", seen)
	}
}

func TestSaveIsAtomicAndLeavesNoTemporary(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Begin(0); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	first := bytes.Repeat([]byte{0xAA}, 128)
	if err := s.Save(first); err != nil {
		t.Fatalf("Save: %v", err)
	}
	second := bytes.Repeat([]byte{0xBB}, 160)
	if err := s.Save(second); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("Save left a temporary file behind: %s", e.Name())
		}
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := reopened.State()
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Errorf("reopened state is not the most recent one")
	}
}

func TestSaveRefusesAnEmptyState(t *testing.T) {
	s, _ := Open(t.TempDir())
	if err := s.Save(nil); err == nil {
		t.Error("Save accepted an empty state")
	}
}

func TestAppendBeforeBeginIsRefused(t *testing.T) {
	// Appending before Begin would write into a region Begin is about to
	// truncate, losing the frame with no error anywhere.
	s, _ := Open(t.TempDir())
	if err := s.Append([]byte{1, 2, 3}); err == nil {
		t.Error("Append before Begin returned no error")
	}
}

func TestAppendRefusesAnEmptyFrame(t *testing.T) {
	s, _ := Open(t.TempDir())
	if err := s.Begin(0); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.Append(nil); err == nil {
		t.Error("Append accepted an empty frame")
	}
}

func TestOpenRejectsAnEmptyDirectory(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Error("Open accepted an empty path")
	}
}
