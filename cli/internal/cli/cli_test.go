package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// run invokes the CLI and returns its exit code, stdout, and stderr.
func run(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(Env{Stdout: &out, Stderr: &errOut, Args: args})
	return code, out.String(), errOut.String()
}

// fixture builds a small dataset and returns its directory.
func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"readme.md":    "hello from the air gap",
		"src/main.go":  "package main\n\nfunc main() {}\n",
		"a/b/deep.txt": strings.Repeat("x", 2000),
		"empty.txt":    "",
	}
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	return root
}

// keygen produces an operator key and returns its path.
func keygen(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "operator.key")
	if code, _, errOut := run("keygen", "-out", path); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}
	return path
}

// listFiles returns every regular file under root, relative and sorted.
func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var names []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	sort.Strings(names)
	return names
}

func TestUsageWithNoArguments(t *testing.T) {
	code, _, errOut := run()
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, "Usage:") {
		t.Error("usage was not printed")
	}
}

func TestHelpExitsZero(t *testing.T) {
	code, out, _ := run("help")
	if code != ExitOK {
		t.Errorf("exit = %d, want 0", code)
	}
	for _, cmd := range []string{"keygen", "send", "recv", "verify"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("help did not mention %q", cmd)
		}
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	code, _, errOut := run("frobnicate")
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, "unknown command") {
		t.Error("error did not name the problem")
	}
}

func TestVersionReportsABI(t *testing.T) {
	code, out, _ := run("version")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "ABI") {
		t.Errorf("version output lacked ABI information: %q", out)
	}
}

func TestVersionJSON(t *testing.T) {
	code, out, _ := run("version", "-json")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	var v versionResult
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("output was not valid JSON: %v", err)
	}
	if v.ABIVersion == 0 {
		t.Error("abi_version was zero")
	}
}

func TestKeygenWritesOwnerOnlyKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	code, _, errOut := run("keygen", "-out", path)
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, errOut)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %o, want 600", perm)
	}
}

func TestKeygenRefusesToClobber(t *testing.T) {
	// Overwriting a key silently would destroy the only copy of a secret that
	// cannot be regenerated.
	dir := t.TempDir()
	path := keygen(t, dir)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	code, _, errOut := run("keygen", "-out", path)
	if code != ExitInput {
		t.Errorf("exit = %d, want %d", code, ExitInput)
	}
	if !strings.Contains(errOut, "-force") {
		t.Error("error did not mention how to proceed")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the existing key was overwritten")
	}
}

func TestKeygenForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := keygen(t, dir)
	before, _ := os.ReadFile(path)

	if code, _, errOut := run("keygen", "-out", path, "-force"); code != ExitOK {
		t.Fatalf("exit = %d: %s", code, errOut)
	}
	after, _ := os.ReadFile(path)
	if bytes.Equal(before, after) {
		t.Error("-force did not replace the key")
	}
}

func TestSendRecvRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")
	dest := filepath.Join(dir, "received")

	if code, _, errOut := run("send", "-key", key, "-in", src, "-out", frames); code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}
	if code, _, errOut := run("recv", "-key", key, "-in", frames, "-out", dest); code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}

	want := listFiles(t, src)
	got := listFiles(t, dest)
	if len(got) != len(want) {
		t.Fatalf("received %d files, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("file %d: got %q, want %q", i, got[i], want[i])
		}
		a, _ := os.ReadFile(filepath.Join(src, filepath.FromSlash(want[i])))
		b, _ := os.ReadFile(filepath.Join(dest, filepath.FromSlash(got[i])))
		if !bytes.Equal(a, b) {
			t.Errorf("%s: contents differ", want[i])
		}
	}
}

func TestSendRecvSurvivesDroppedFrames(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")
	dest := filepath.Join(dir, "received")

	if code, _, errOut := run("send", "-key", key, "-in", src, "-out", frames); code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}

	// Delete a fifth of the frames, as a camera missing captures would.
	names, err := filepath.Glob(filepath.Join(frames, "frame-*.bin"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	sort.Strings(names)
	for i, n := range names {
		if i%5 == 0 {
			if err := os.Remove(n); err != nil {
				t.Fatalf("Remove: %v", err)
			}
		}
	}

	if code, _, errOut := run("recv", "-key", key, "-in", frames, "-out", dest); code != ExitOK {
		t.Fatalf("recv exited %d after frame loss: %s", code, errOut)
	}
	if len(listFiles(t, dest)) != len(listFiles(t, src)) {
		t.Error("not every file survived frame loss")
	}
}

func TestRecvWithWrongKeyIsIncompleteNotCorrupt(t *testing.T) {
	// Frames are bound to a session key derived from the operator key, so a
	// receiver with the wrong key authenticates none of them. It must fail
	// closed rather than emit anything.
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")

	if code, _, errOut := run("send", "-key", key, "-in", src, "-out", frames); code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}

	wrong := filepath.Join(dir, "wrong.key")
	if code, _, errOut := run("keygen", "-out", wrong); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}

	dest := filepath.Join(dir, "received")
	code, _, _ := run("recv", "-key", wrong, "-in", frames, "-out", dest)
	if code != ExitIncomplete {
		t.Errorf("exit = %d, want %d", code, ExitIncomplete)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Error("a failed transfer still wrote an output directory")
	}
}

func TestRecvRejectsTamperedFrames(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")

	if code, _, errOut := run("send", "-key", key, "-in", src, "-out", frames); code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}

	// Corrupt every frame. None should authenticate.
	names, _ := filepath.Glob(filepath.Join(frames, "frame-*.bin"))
	for _, n := range names {
		data, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		data[len(data)-1] ^= 0xFF
		if err := os.WriteFile(n, data, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	code, _, _ := run("recv", "-key", key, "-in", frames, "-out", filepath.Join(dir, "received"))
	if code != ExitIncomplete {
		t.Errorf("exit = %d, want %d", code, ExitIncomplete)
	}
}

func TestSendJSONOutputIsParseable(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)

	code, out, errOut := run("send", "-key", key, "-in", src,
		"-out", filepath.Join(dir, "frames"), "-json")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, errOut)
	}

	var r sendResult
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("output was not valid JSON: %v\n%s", err, out)
	}
	if r.Frames == 0 {
		t.Error("frames was zero")
	}
	if len(r.SessionID) != 32 {
		t.Errorf("session_id = %q, want 32 hex characters", r.SessionID)
	}
}

func TestVerifySucceedsOnGoodOutput(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")
	dest := filepath.Join(dir, "received")

	run("send", "-key", key, "-in", src, "-out", frames)
	run("recv", "-key", key, "-in", frames, "-out", dest)

	code, out, errOut := run("verify", "-in", frames, "-dir", dest)
	if code != ExitOK {
		t.Fatalf("verify exited %d: %s", code, errOut)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("verify did not report success: %q", out)
	}
}

func TestVerifyFailsOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")
	dest := filepath.Join(dir, "received")

	run("send", "-key", key, "-in", src, "-out", frames)
	run("recv", "-key", key, "-in", frames, "-out", dest)

	if err := os.Remove(filepath.Join(dest, "readme.md")); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	code, _, _ := run("verify", "-in", frames, "-dir", dest)
	if code != ExitVerifyFailed {
		t.Errorf("exit = %d, want %d", code, ExitVerifyFailed)
	}
}

func TestVerifyJSONReportsProblems(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")

	run("send", "-key", key, "-in", src, "-out", frames)

	code, out, _ := run("verify", "-in", frames, "-dir", filepath.Join(dir, "absent"), "-json")
	if code != ExitVerifyFailed {
		t.Errorf("exit = %d, want %d", code, ExitVerifyFailed)
	}
	var r verifyResult
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("output was not valid JSON: %v", err)
	}
	if r.OK {
		t.Error("ok was true for a missing directory")
	}
	if len(r.Problems) == 0 {
		t.Error("no problems were reported")
	}
}

func TestExitCodesForBadInput(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"send without -in", []string{"send", "-key", key}, ExitUsage},
		{"send from a missing directory", []string{"send", "-key", key, "-in", filepath.Join(dir, "absent")}, ExitInput},
		{"send with a missing key", []string{"send", "-key", filepath.Join(dir, "absent.key"), "-in", dir}, ExitInput},
		{"recv from a missing directory", []string{"recv", "-key", key, "-in", filepath.Join(dir, "absent")}, ExitInput},
		{"verify without a record", []string{"verify", "-in", filepath.Join(dir, "absent")}, ExitInput},
		{"unknown flag", []string{"send", "-nonsense"}, ExitUsage},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, _ := run(tc.args...); code != tc.want {
				t.Errorf("exit = %d, want %d", code, tc.want)
			}
		})
	}
}

func TestSendRejectsInvalidCodingParameters(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)

	for _, args := range [][]string{
		{"send", "-key", key, "-in", src, "-symbol-size", "8"},
		{"send", "-key", key, "-in", src, "-symbol-size", "70000"},
		{"send", "-key", key, "-in", src, "-blocks", "0"},
		{"send", "-key", key, "-in", src, "-blocks", "99999"},
	} {
		if code, _, _ := run(args...); code != ExitUsage {
			t.Errorf("%v: exit = %d, want %d", args[4:], code, ExitUsage)
		}
	}
}

func TestTransferRecordCarriesNoSecret(t *testing.T) {
	// The record travels beside the frames, so it must contain nothing that
	// would let an observer read the payload.
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")

	run("send", "-key", key, "-in", src, "-out", frames)

	data, err := os.ReadFile(filepath.Join(frames, recordName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	keyBytes, err := os.ReadFile(key)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// The key file's material sits after its 8-byte header.
	if bytes.Contains(data, keyBytes[8:40]) {
		t.Error("the transfer record contained operator key material")
	}
	for _, forbidden := range []string{"operator_key", "session_key", "payload_key"} {
		if bytes.Contains(bytes.ToLower(data), []byte(forbidden)) {
			t.Errorf("the transfer record mentioned %q", forbidden)
		}
	}
}

// --- Resume ---

// sendFixture packs a dataset and returns the key, frame, and dataset dirs.
//
// The dataset is deliberately larger than the one the other tests use: a
// resume test needs a stream long enough that stopping partway through it
// really does leave work undone.
func sendFixture(t *testing.T, blocks string) (key, frameDir, dataDir string) {
	t.Helper()
	work := t.TempDir()
	dataDir = fixture(t)
	key = keygen(t, work)

	bulk := make([]byte, 64*1024)
	for i := range bulk {
		bulk[i] = byte(i % 251)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "bulk.bin"), bulk, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	frameDir = filepath.Join(work, "frames")

	code, _, errOut := run("send", "-key", key, "-in", dataDir,
		"-out", frameDir, "-blocks", blocks, "-symbol-size", "256")
	if code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}
	return key, frameDir, dataDir
}

// sameTree reports whether two directories hold identical files.
func sameTree(t *testing.T, want, got string) {
	t.Helper()
	wantNames, gotNames := listFiles(t, want), listFiles(t, got)
	if len(wantNames) != len(gotNames) {
		t.Fatalf("received %v, want %v", gotNames, wantNames)
	}
	for i, name := range wantNames {
		if gotNames[i] != name {
			t.Fatalf("received %v, want %v", gotNames, wantNames)
		}
		a, err := os.ReadFile(filepath.Join(want, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		b, err := os.ReadFile(filepath.Join(got, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs after the transfer", name)
		}
	}
}

func TestRecvResumesAfterAnInterruption(t *testing.T) {
	key, frameDir, dataDir := sendFixture(t, "4")
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	outDir := filepath.Join(work, "received")

	// Stop partway. The run must fail as incomplete and say where the
	// progress went, because an operator who does not know that has lost it.
	code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir,
		"-state", stateDir, "-stop-after", "30", "-save-every", "10")
	if code != ExitIncomplete {
		t.Fatalf("interrupted recv exited %d, want %d: %s", code, ExitIncomplete, errOut)
	}
	if !strings.Contains(errOut, stateDir) {
		t.Errorf("the incomplete message does not name the state directory: %s", errOut)
	}

	for _, name := range []string{"journal.bin", "resume.dhrs"} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	// Resume. The transfer must complete and the dataset must come back whole.
	code, out, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir,
		"-state", stateDir)
	if code != ExitOK {
		t.Fatalf("resumed recv exited %d: %s", code, errOut)
	}
	if !strings.Contains(out, "resumed") {
		t.Errorf("a resumed transfer did not report what it resumed: %s", out)
	}
	sameTree(t, dataDir, outDir)

	// The state has done its job and must not be left to confuse the next run.
	for _, name := range []string{"journal.bin", "resume.dhrs"} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); !os.IsNotExist(err) {
			t.Errorf("%s survived a completed transfer", name)
		}
	}
}

func TestRecvResumesAcrossSeveralInterruptions(t *testing.T) {
	// One stop could be recovered by luck. Repeated stops exercise a journal
	// that is replayed, extended, and replayed again.
	key, frameDir, dataDir := sendFixture(t, "3")
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	outDir := filepath.Join(work, "received")

	for _, limit := range []string{"20", "40", "60"} {
		code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir,
			"-state", stateDir, "-stop-after", limit, "-save-every", "7")
		if code != ExitIncomplete {
			t.Fatalf("recv with -stop-after %s exited %d: %s", limit, code, errOut)
		}
	}

	code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir, "-state", stateDir)
	if code != ExitOK {
		t.Fatalf("final recv exited %d: %s", code, errOut)
	}
	sameTree(t, dataDir, outDir)
}

func TestRecvWithoutStateDoesNotPersistAnything(t *testing.T) {
	// Resume is opt-in. Without -state the receiver must behave exactly as it
	// did before and leave nothing behind.
	key, frameDir, dataDir := sendFixture(t, "2")
	work := t.TempDir()
	outDir := filepath.Join(work, "received")

	code, out, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir)
	if code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}
	if strings.Contains(out, "resumed") {
		t.Errorf("a fresh transfer reported resuming: %s", out)
	}
	sameTree(t, dataDir, outDir)

	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "received" {
			t.Errorf("recv left %s behind without -state", e.Name())
		}
	}
}

// interrupted runs recv far enough to leave saved state, and returns the dirs.
func interrupted(t *testing.T, key, frameDir string) (stateDir, outDir string) {
	t.Helper()
	work := t.TempDir()
	stateDir = filepath.Join(work, "state")
	outDir = filepath.Join(work, "received")

	code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir,
		"-state", stateDir, "-stop-after", "25", "-save-every", "5")
	if code != ExitIncomplete {
		t.Fatalf("interrupted recv exited %d: %s", code, errOut)
	}
	return stateDir, outDir
}

// flipByte corrupts one byte of a file in place.
func flipByte(t *testing.T, path string, offset int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if offset >= len(data) {
		t.Fatalf("offset %d is past the end of %s (%d bytes)", offset, path, len(data))
	}
	data[offset] ^= 0x01
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestRecvRejectsATamperedIndex(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")
	stateDir, outDir := interrupted(t, key, frameDir)

	// Offset 40 is inside the journal digest, the field an attacker would have
	// to rewrite to make a doctored journal look expected.
	flipByte(t, filepath.Join(stateDir, "resume.dhrs"), 40)

	code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir, "-state", stateDir)
	if code != ExitInput {
		t.Fatalf("recv with a tampered index exited %d, want %d: %s", code, ExitInput, errOut)
	}
	if !strings.Contains(errOut, "unusable") {
		t.Errorf("the error does not say the state is unusable: %s", errOut)
	}
	if !strings.Contains(errOut, "delete") {
		t.Errorf("the error does not say what to do about it: %s", errOut)
	}
}

func TestRecvRejectsATamperedJournal(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")
	stateDir, outDir := interrupted(t, key, frameDir)

	// A frame body, past the record's length prefix. The decoder must refuse
	// it on the way back in exactly as it would a corrupt capture.
	flipByte(t, filepath.Join(stateDir, "journal.bin"), 60)

	code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir, "-state", stateDir)
	if code != ExitInput {
		t.Fatalf("recv with a tampered journal exited %d, want %d: %s", code, ExitInput, errOut)
	}
	if !strings.Contains(errOut, "replaying saved progress") {
		t.Errorf("the error does not name the replay as the problem: %s", errOut)
	}
}

func TestRecvRejectsATruncatedJournal(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")
	stateDir, outDir := interrupted(t, key, frameDir)

	path := filepath.Join(stateDir, "journal.bin")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// Shorter than the index says. A crash cannot produce this, because the
	// journal is flushed before the index that describes it is written.
	if err := os.Truncate(path, info.Size()/2); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir, "-state", stateDir)
	if code != ExitInput {
		t.Fatalf("recv with a truncated journal exited %d, want %d: %s", code, ExitInput, errOut)
	}
}

func TestRecvRejectsStateFromAnotherSession(t *testing.T) {
	// Two transfers, one operator pointing the second at the first's state.
	key, frameDir, _ := sendFixture(t, "2")
	stateDir, _ := interrupted(t, key, frameDir)

	work := t.TempDir()
	otherFrames := filepath.Join(work, "frames")
	code, _, errOut := run("send", "-key", key, "-in", fixture(t),
		"-out", otherFrames, "-blocks", "2", "-symbol-size", "256")
	if code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}

	code, _, errOut = run("recv", "-key", key, "-in", otherFrames,
		"-out", filepath.Join(work, "received"), "-state", stateDir)
	if code != ExitInput {
		t.Fatalf("recv with foreign state exited %d, want %d: %s", code, ExitInput, errOut)
	}
	if !strings.Contains(errOut, "belongs to session") {
		t.Errorf("the error does not name the session mismatch: %s", errOut)
	}
}

func TestRecvKeepStateLeavesTheDirectoryPopulated(t *testing.T) {
	key, frameDir, dataDir := sendFixture(t, "2")
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	outDir := filepath.Join(work, "received")

	code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir,
		"-state", stateDir, "-keep-state")
	if code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}
	sameTree(t, dataDir, outDir)

	for _, name := range []string{"journal.bin", "resume.dhrs"} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); err != nil {
			t.Errorf("-keep-state did not keep %s: %v", name, err)
		}
	}
}

func TestRecvRejectsAZeroSaveInterval(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()

	code, _, errOut := run("recv", "-key", key, "-in", frameDir,
		"-out", filepath.Join(work, "received"),
		"-state", filepath.Join(work, "state"), "-save-every", "0")
	if code != ExitUsage {
		t.Fatalf("recv with -save-every 0 exited %d, want %d: %s", code, ExitUsage, errOut)
	}
}

func TestRecvJSONReportsResumeCounts(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")
	stateDir, outDir := interrupted(t, key, frameDir)

	code, out, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir,
		"-state", stateDir, "-json")
	if code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}

	var result struct {
		Resumed  int    `json:"frames_resumed"`
		Accepted int    `json:"frames_accepted"`
		StateDir string `json:"state_dir"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parsing JSON output: %v\n%s", err, out)
	}
	if result.Resumed != 25 {
		t.Errorf("frames_resumed = %d, want 25", result.Resumed)
	}
	if result.Accepted == 0 {
		t.Error("frames_accepted = 0 after a resume")
	}
	if result.StateDir != stateDir {
		t.Errorf("state_dir = %q, want %q", result.StateDir, stateDir)
	}
}

// --- verify ---

// verified runs verify and returns its exit code and parsed JSON result.
func verified(t *testing.T, frameDir, dir string) (int, verifyResult) {
	t.Helper()
	code, out, errOut := run("verify", "-in", frameDir, "-dir", dir, "-json")
	var result verifyResult
	if out != "" {
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatalf("parsing verify JSON: %v\n%s\n%s", err, out, errOut)
		}
	}
	return code, result
}

// problemFor returns the problem reported for a file, or a zero value.
func problemFor(result verifyResult, name string) Problem {
	for _, p := range result.Problems {
		if p.File == name {
			return p
		}
	}
	return Problem{}
}

// received sends a dataset and receives it, returning the frame and output
// directories along with the dataset that was sent.
func received(t *testing.T) (frameDir, outDir, dataDir string) {
	t.Helper()
	key, frameDir, dataDir := sendFixture(t, "2")
	outDir = filepath.Join(t.TempDir(), "received")

	code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir)
	if code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}
	return frameDir, outDir, dataDir
}

func TestVerifyAcceptsTheDatasetThatWasSent(t *testing.T) {
	frameDir, outDir, dataDir := received(t)

	code, result := verified(t, frameDir, outDir)
	if code != ExitOK {
		t.Fatalf("verify exited %d with problems %+v", code, result.Problems)
	}
	if !result.OK {
		t.Error("verify reported not-OK on a good dataset")
	}
	if len(result.Problems) != 0 {
		t.Errorf("verify found problems in a good dataset: %+v", result.Problems)
	}

	// Every file must have actually been read, not merely counted.
	wantFiles := len(listFiles(t, dataDir))
	if result.Files != wantFiles || result.Checked != wantFiles {
		t.Errorf("files = %d, checked = %d, want %d of each", result.Files, result.Checked, wantFiles)
	}
	if result.Bytes == 0 {
		t.Error("verify read no bytes, so it cannot have checked any contents")
	}
}

func TestVerifyCatchesASingleFlippedByte(t *testing.T) {
	// The case the old file count could never catch: the dataset has the right
	// shape and one wrong bit.
	frameDir, outDir, _ := received(t)

	target := filepath.Join(outDir, "bulk.bin")
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	data[len(data)/2] ^= 0x01
	if err := os.WriteFile(target, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	code, result := verified(t, frameDir, outDir)
	if code != ExitVerifyFailed {
		t.Fatalf("verify exited %d, want %d", code, ExitVerifyFailed)
	}
	p := problemFor(result, "bulk.bin")
	if p.Kind != ProblemContent {
		t.Errorf("problem kind = %q, want %q (problems: %+v)", p.Kind, ProblemContent, result.Problems)
	}
	if len(result.Problems) != 1 {
		t.Errorf("one flipped byte produced %d problems: %+v", len(result.Problems), result.Problems)
	}
}

func TestVerifyReportsATruncatedFileAsTruncated(t *testing.T) {
	// A truncated file would also fail its digest. Reporting it as a size
	// mismatch says what happened; a digest mismatch says only that something
	// did.
	frameDir, outDir, _ := received(t)

	target := filepath.Join(outDir, "bulk.bin")
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if err := os.Truncate(target, info.Size()-100); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	code, result := verified(t, frameDir, outDir)
	if code != ExitVerifyFailed {
		t.Fatalf("verify exited %d, want %d", code, ExitVerifyFailed)
	}
	if p := problemFor(result, "bulk.bin"); p.Kind != ProblemSize {
		t.Errorf("problem kind = %q, want %q", p.Kind, ProblemSize)
	}
}

func TestVerifyReportsAMissingFile(t *testing.T) {
	frameDir, outDir, _ := received(t)
	if err := os.Remove(filepath.Join(outDir, "readme.md")); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	code, result := verified(t, frameDir, outDir)
	if code != ExitVerifyFailed {
		t.Fatalf("verify exited %d, want %d", code, ExitVerifyFailed)
	}
	if p := problemFor(result, "readme.md"); p.Kind != ProblemMissing {
		t.Errorf("problem kind = %q, want %q", p.Kind, ProblemMissing)
	}
}

func TestVerifyReportsAFileNobodySent(t *testing.T) {
	// A dataset with something extra in it is not the dataset that was
	// transferred, whatever else is right about it.
	frameDir, outDir, _ := received(t)
	if err := os.WriteFile(filepath.Join(outDir, "planted.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	code, result := verified(t, frameDir, outDir)
	if code != ExitVerifyFailed {
		t.Fatalf("verify exited %d, want %d", code, ExitVerifyFailed)
	}
	if p := problemFor(result, "planted.txt"); p.Kind != ProblemUnexpected {
		t.Errorf("problem kind = %q, want %q", p.Kind, ProblemUnexpected)
	}
}

func TestVerifyReportsALostExecutableBit(t *testing.T) {
	// sendFixture's frames predate the script, so they are discarded and the
	// dataset is sent again once the inventory can know it is executable.
	key, _, dataDir := sendFixture(t, "2")
	script := filepath.Join(dataDir, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	frameDir := filepath.Join(t.TempDir(), "frames")
	code, _, errOut := run("send", "-key", key, "-in", dataDir, "-out", frameDir,
		"-blocks", "2", "-symbol-size", "256")
	if code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}

	outDir := filepath.Join(t.TempDir(), "received")
	if code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir); code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}
	if code, result := verified(t, frameDir, outDir); code != ExitOK {
		t.Fatalf("verify of a good dataset exited %d: %+v", code, result.Problems)
	}

	if err := os.Chmod(filepath.Join(outDir, "run.sh"), 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	code, result := verified(t, frameDir, outDir)
	if code != ExitVerifyFailed {
		t.Fatalf("verify exited %d, want %d", code, ExitVerifyFailed)
	}
	if p := problemFor(result, "run.sh"); p.Kind != ProblemMode {
		t.Errorf("problem kind = %q, want %q (problems: %+v)", p.Kind, ProblemMode, result.Problems)
	}
}

func TestVerifyReportsEveryProblemAtOnce(t *testing.T) {
	// An operator staring at a dataset that came back wrong needs the whole
	// picture. Stopping at the first problem would mean one run per problem.
	frameDir, outDir, _ := received(t)

	if err := os.Remove(filepath.Join(outDir, "readme.md")); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "planted.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	target := filepath.Join(outDir, "bulk.bin")
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	data[0] ^= 0xFF
	if err := os.WriteFile(target, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	code, result := verified(t, frameDir, outDir)
	if code != ExitVerifyFailed {
		t.Fatalf("verify exited %d, want %d", code, ExitVerifyFailed)
	}

	kinds := map[string]bool{}
	for _, p := range result.Problems {
		kinds[p.Kind] = true
	}
	for _, want := range []string{ProblemMissing, ProblemUnexpected, ProblemContent} {
		if !kinds[want] {
			t.Errorf("verify did not report a %q problem: %+v", want, result.Problems)
		}
	}
}

func TestVerifyReportsAnUnreadableDataset(t *testing.T) {
	frameDir, _, _ := received(t)

	code, result := verified(t, frameDir, filepath.Join(t.TempDir(), "nothing-here"))
	if code != ExitVerifyFailed {
		t.Fatalf("verify exited %d, want %d", code, ExitVerifyFailed)
	}
	if len(result.Problems) != 1 || result.Problems[0].Kind != ProblemUnreadable {
		t.Errorf("problems = %+v, want a single unreadable problem", result.Problems)
	}
}

func TestVerifyRejectsAnOlderTransferRecord(t *testing.T) {
	// A version 1 record has no inventory, so verifying against it would be
	// the file count again. Refusing is the honest answer.
	frameDir, outDir, _ := received(t)

	path := filepath.Join(frameDir, recordName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	raw["version"] = 1
	patched, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, patched, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	code, _, errOut := run("verify", "-in", frameDir, "-dir", outDir)
	if code != ExitInput {
		t.Fatalf("verify with a v1 record exited %d, want %d: %s", code, ExitInput, errOut)
	}
	if !strings.Contains(errOut, "version 2") {
		t.Errorf("the error does not say which version this build reads: %s", errOut)
	}
}

// --- Exit-code contract ---

func TestEveryDocumentedExitCodeIsProducedBySomething(t *testing.T) {
	// The help text promises these codes. A promise nothing provokes is a
	// promise nobody has checked.
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()
	outDir := filepath.Join(work, "received")
	missing := filepath.Join(work, "nowhere")

	// Set up a good receive, so the verify cases have something to damage.
	if code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir); code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}

	cases := []struct {
		name string
		want int
		args []string
	}{
		{"success", ExitOK, []string{"verify", "-in", frameDir, "-dir", outDir}},
		{"no command", ExitUsage, nil},
		{"unknown command", ExitUsage, []string{"transmogrify"}},
		{"unknown flag", ExitUsage, []string{"send", "-nonsense"}},
		{"missing required flag", ExitUsage, []string{"send", "-key", key}},
		{"contradictory verbosity", ExitUsage, []string{"verify", "-in", frameDir, "-dir", outDir, "-quiet", "-verbose"}},
		{"missing key file", ExitInput, []string{"recv", "-key", filepath.Join(missing, "k"), "-in", frameDir, "-out", filepath.Join(work, "a")}},
		{"missing frame directory", ExitInput, []string{"recv", "-key", key, "-in", missing, "-out", filepath.Join(work, "b")}},
		{"missing dataset", ExitVerifyFailed, []string{"verify", "-in", frameDir, "-dir", missing}},
	}

	for _, tc := range cases {
		if code, _, errOut := run(tc.args...); code != tc.want {
			t.Errorf("%s: exited %d, want %d (%s)", tc.name, code, tc.want, strings.TrimSpace(errOut))
		}
	}
}

func TestIncompleteTransferExitsFour(t *testing.T) {
	// Four is the one code worth retrying, so it must be reachable and must
	// not be confused with a verification failure.
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()

	code, _, errOut := run("recv", "-key", key, "-in", frameDir,
		"-out", filepath.Join(work, "received"),
		"-state", filepath.Join(work, "state"), "-stop-after", "5")
	if code != ExitIncomplete {
		t.Fatalf("an interrupted receive exited %d, want %d: %s", code, ExitIncomplete, errOut)
	}
}

func TestFailureAlwaysReachesStderrEvenWhenQuiet(t *testing.T) {
	// -quiet is a display preference. Silencing a failure would turn it into a
	// correctness hazard.
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()
	outDir := filepath.Join(work, "received")
	if code, _, errOut := run("recv", "-key", key, "-in", frameDir, "-out", outDir); code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}
	if err := os.Remove(filepath.Join(outDir, "readme.md")); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	code, out, errOut := run("verify", "-in", frameDir, "-dir", outDir, "-quiet")
	if code != ExitVerifyFailed {
		t.Fatalf("verify exited %d, want %d", code, ExitVerifyFailed)
	}
	if errOut == "" {
		t.Error("-quiet silenced a verification failure entirely")
	}
	if !strings.Contains(out, "readme.md") && !strings.Contains(errOut, "verification failed") {
		t.Errorf("a quiet failure said nothing useful:\nstdout %q\nstderr %q", out, errOut)
	}
}

// --- Verbosity ---

func TestQuietSuppressesTheSummaryButNotTheResult(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()

	code, out, _ := run("recv", "-key", key, "-in", frameDir,
		"-out", filepath.Join(work, "received"), "-quiet")
	if code != ExitOK {
		t.Fatalf("recv -quiet exited %d", code)
	}
	if out != "" {
		t.Errorf("-quiet printed to stdout: %q", out)
	}

	// The dataset must still be there: -quiet changes what is said, not what
	// is done.
	if names := listFiles(t, filepath.Join(work, "received")); len(names) == 0 {
		t.Error("-quiet suppressed the extraction as well as the summary")
	}
}

func TestQuietDoesNotSuppressJSON(t *testing.T) {
	// A caller asking for machine output and silence at once wants the JSON.
	// Dropping it would be data loss dressed up as a preference.
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()

	code, out, errOut := run("recv", "-key", key, "-in", frameDir,
		"-out", filepath.Join(work, "received"), "-quiet", "-json")
	if code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}
	var result recvResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("-quiet -json produced no parseable JSON: %v\n%q", err, out)
	}
	if result.Files == 0 {
		t.Error("the JSON reported no files")
	}
}

func TestVerboseAddsCommentaryWithoutChangingTheResult(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()

	plainCode, plainOut, plainErr := run("recv", "-key", key, "-in", frameDir,
		"-out", filepath.Join(work, "a"), "-json")
	loudCode, loudOut, loudErr := run("recv", "-key", key, "-in", frameDir,
		"-out", filepath.Join(work, "b"), "-json", "-verbose")

	if plainCode != ExitOK || loudCode != ExitOK {
		t.Fatalf("exit codes %d and %d", plainCode, loudCode)
	}

	// Commentary belongs on stderr so a pipe on stdout is unaffected by it.
	var a, b recvResult
	if err := json.Unmarshal([]byte(plainOut), &a); err != nil {
		t.Fatalf("plain JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(loudOut), &b); err != nil {
		t.Fatalf("verbose JSON: %v", err)
	}
	if a.Frames != b.Frames || a.Files != b.Files {
		t.Errorf("-verbose changed the result: %+v vs %+v", a, b)
	}

	if len(loudErr) <= len(plainErr) {
		t.Errorf("-verbose added no commentary (plain %q, verbose %q)", plainErr, loudErr)
	}
	if !strings.Contains(loudErr, "blocks decoded") {
		t.Errorf("-verbose did not report block progress: %q", loudErr)
	}
}

func TestContradictoryVerbosityIsRefusedNotGuessed(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")

	for _, cmd := range [][]string{
		{"keygen", "-out", filepath.Join(t.TempDir(), "k"), "-quiet", "-verbose"},
		{"send", "-key", key, "-in", frameDir, "-out", filepath.Join(t.TempDir(), "f"), "-quiet", "-verbose"},
		{"recv", "-key", key, "-in", frameDir, "-out", filepath.Join(t.TempDir(), "r"), "-quiet", "-verbose"},
		{"verify", "-in", frameDir, "-dir", frameDir, "-quiet", "-verbose"},
	} {
		code, _, errOut := run(cmd...)
		if code != ExitUsage {
			t.Errorf("%s: exited %d, want %d", cmd[0], code, ExitUsage)
		}
		if !strings.Contains(errOut, "contradict") {
			t.Errorf("%s: the error does not explain the conflict: %s", cmd[0], errOut)
		}
	}
}

func TestHelpDocumentsEveryExitCodeTheCodeDefines(t *testing.T) {
	// Help text drifts from the code silently. This fails when a code is added
	// without being explained.
	_, out, _ := run("help")
	for _, code := range []int{ExitOK, ExitUsage, ExitInput, ExitVerifyFailed, ExitIncomplete, ExitInternal} {
		if !strings.Contains(out, fmt.Sprintf("%d", code)) {
			t.Errorf("the help text does not mention exit code %d", code)
		}
	}
	for _, flag := range []string{"-json", "-quiet", "-verbose"} {
		if !strings.Contains(out, flag) {
			t.Errorf("the help text does not mention %s", flag)
		}
	}
}
