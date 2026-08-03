package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"dhow/cli/internal/ffi"
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

// keygen produces the two keys a transfer needs and returns the operator key's
// path.
//
// The signing identity goes in the same directory under the standard names, so
// identityBeside and signerBeside can find it from any sibling path. Almost
// every test here needs both keys and cares about neither, and threading two
// more paths through every call would bury what each test is actually about.
func keygen(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "operator.key")
	if code, _, errOut := run("keygen", "-out", path); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}
	if code, _, errOut := run("keygen", "-kind", "identity", "-out", identityBeside(path)); code != ExitOK {
		t.Fatalf("keygen -kind identity exited %d: %s", code, errOut)
	}
	return path
}

// identityBeside names the signing identity sitting beside a path.
func identityBeside(path string) string {
	return filepath.Join(filepath.Dir(path), "sender.key")
}

// signerBeside names the public identity sitting beside a path.
func signerBeside(path string) string {
	return filepath.Join(filepath.Dir(path), "sender.pub")
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

	if code, _, errOut := run("send", "-key", key, "-identity", identityBeside(key), "-in", src, "-out", frames); code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}
	if code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frames, "-out", dest); code != ExitOK {
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

	if code, _, errOut := run("send", "-key", key, "-identity", identityBeside(key), "-in", src, "-out", frames); code != ExitOK {
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

	if code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frames, "-out", dest); code != ExitOK {
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

	if code, _, errOut := run("send", "-key", key, "-identity", identityBeside(key), "-in", src, "-out", frames); code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}

	wrong := filepath.Join(dir, "wrong.key")
	if code, _, errOut := run("keygen", "-out", wrong); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}

	dest := filepath.Join(dir, "received")
	code, _, _ := run("recv", "-key", wrong, "-signer", signerBeside(wrong), "-in", frames, "-out", dest)
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

	if code, _, errOut := run("send", "-key", key, "-identity", identityBeside(key), "-in", src, "-out", frames); code != ExitOK {
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

	code, _, _ := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frames, "-out", filepath.Join(dir, "received"))
	if code != ExitIncomplete {
		t.Errorf("exit = %d, want %d", code, ExitIncomplete)
	}
}

func TestSendJSONOutputIsParseable(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)

	code, out, errOut := run("send", "-key", key, "-identity", identityBeside(key), "-in", src,
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

	run("send", "-key", key, "-identity", identityBeside(key), "-in", src, "-out", frames)
	run("recv", "-key", key, "-signer", signerBeside(key), "-in", frames, "-out", dest)

	code, out, errOut := run("verify", "-in", frames, "-signer", signerBeside(frames), "-dir", dest)
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

	run("send", "-key", key, "-identity", identityBeside(key), "-in", src, "-out", frames)
	run("recv", "-key", key, "-signer", signerBeside(key), "-in", frames, "-out", dest)

	if err := os.Remove(filepath.Join(dest, "readme.md")); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	code, _, _ := run("verify", "-in", frames, "-signer", signerBeside(frames), "-dir", dest)
	if code != ExitVerifyFailed {
		t.Errorf("exit = %d, want %d", code, ExitVerifyFailed)
	}
}

func TestVerifyJSONReportsProblems(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")

	run("send", "-key", key, "-identity", identityBeside(key), "-in", src, "-out", frames)

	code, out, _ := run("verify", "-in", frames, "-signer", signerBeside(frames), "-dir", filepath.Join(dir, "absent"), "-json")
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
		{"send", "-key", key, "-identity", identityBeside(key), "-in", src, "-symbol-size", "8"},
		{"send", "-key", key, "-identity", identityBeside(key), "-in", src, "-symbol-size", "70000"},
		{"send", "-key", key, "-identity", identityBeside(key), "-in", src, "-blocks", "0"},
		{"send", "-key", key, "-identity", identityBeside(key), "-in", src, "-blocks", "99999"},
	} {
		if code, _, _ := run(args...); code != ExitUsage {
			t.Errorf("%v: exit = %d, want %d", args[4:], code, ExitUsage)
		}
	}
}

func TestManifestCarriesNoSecret(t *testing.T) {
	// The manifest travels beside the frames and is not encrypted - the salt
	// and nonce in it are public by design - so it must contain nothing that
	// would let an observer read the payload or forge a transfer.
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")

	run("send", "-key", key, "-identity", identityBeside(key), "-in", src, "-out", frames)

	data, err := os.ReadFile(filepath.Join(frames, manifestName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// The key files' material sits after an 8-byte header. Neither the
	// operator key nor the identity's seed may appear.
	for _, secret := range []string{key, identityBeside(key)} {
		keyBytes, err := os.ReadFile(secret)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if bytes.Contains(data, keyBytes[8:40]) {
			t.Errorf("the manifest contained the key material from %s", filepath.Base(secret))
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

	code, _, errOut := run("send", "-key", key, "-identity", identityBeside(key), "-in", dataDir,
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
	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir,
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
	code, out, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir,
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
		code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir,
			"-state", stateDir, "-stop-after", limit, "-save-every", "7")
		if code != ExitIncomplete {
			t.Fatalf("recv with -stop-after %s exited %d: %s", limit, code, errOut)
		}
	}

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir, "-state", stateDir)
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

	code, out, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir)
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

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir,
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

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir, "-state", stateDir)
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

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir, "-state", stateDir)
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

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir, "-state", stateDir)
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
	code, _, errOut := run("send", "-key", key, "-identity", identityBeside(key), "-in", fixture(t),
		"-out", otherFrames, "-blocks", "2", "-symbol-size", "256")
	if code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}

	code, _, errOut = run("recv", "-key", key, "-signer", signerBeside(key), "-in", otherFrames,
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

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir,
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

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir,
		"-out", filepath.Join(work, "received"),
		"-state", filepath.Join(work, "state"), "-save-every", "0")
	if code != ExitUsage {
		t.Fatalf("recv with -save-every 0 exited %d, want %d: %s", code, ExitUsage, errOut)
	}
}

func TestRecvJSONReportsResumeCounts(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")
	stateDir, outDir := interrupted(t, key, frameDir)

	code, out, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir,
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
	code, out, errOut := run("verify", "-in", frameDir, "-signer", signerBeside(frameDir), "-dir", dir, "-json")
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

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir)
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

	frameDir := filepath.Join(filepath.Dir(key), "frames-with-script")
	code, _, errOut := run("send", "-key", key, "-identity", identityBeside(key), "-in", dataDir, "-out", frameDir,
		"-blocks", "2", "-symbol-size", "256")
	if code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}

	outDir := filepath.Join(t.TempDir(), "received")
	if code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir); code != ExitOK {
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

func TestVerifyRejectsAnOlderManifestVersion(t *testing.T) {
	// A v1 manifest carries no salt, no nonce, no coding parameters, and a
	// payload digest computed over different bytes. There is nothing to
	// convert, so refusing is the honest answer.
	frameDir, outDir, _ := received(t)

	path := filepath.Join(frameDir, manifestName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	data[4] = 1
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	code, _, errOut := run("verify", "-in", frameDir, "-signer", signerBeside(frameDir), "-dir", outDir)
	if code != ExitVerifyFailed {
		t.Fatalf("verify with a v1 manifest exited %d, want %d: %s", code, ExitVerifyFailed, errOut)
	}
	if !strings.Contains(errOut, "unsupported manifest version: 1") {
		t.Errorf("the error does not name the version it refused: %s", errOut)
	}
}

func TestFramesWithoutAManifestAreRefused(t *testing.T) {
	frameDir, outDir, _ := received(t)
	if err := os.Remove(filepath.Join(frameDir, manifestName)); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	code, _, errOut := run("verify", "-in", frameDir, "-signer", signerBeside(frameDir), "-dir", outDir)
	if code != ExitInput {
		t.Fatalf("verify without a manifest exited %d, want %d: %s", code, ExitInput, errOut)
	}
	if !strings.Contains(errOut, manifestName) {
		t.Errorf("the error does not name the missing file: %s", errOut)
	}
}

func TestALegacyTransferRecordIsNamedInTheError(t *testing.T) {
	// A frames directory from a build that wrote transfer.json cannot be
	// received. Saying so beats letting the operator wonder where it went.
	frameDir, outDir, _ := received(t)
	if err := os.Remove(filepath.Join(frameDir, manifestName)); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.WriteFile(filepath.Join(frameDir, "transfer.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	code, _, errOut := run("verify", "-in", frameDir, "-signer", signerBeside(frameDir), "-dir", outDir)
	if code != ExitInput {
		t.Fatalf("verify exited %d, want %d: %s", code, ExitInput, errOut)
	}
	if !strings.Contains(errOut, "dhow send") {
		t.Errorf("the error does not say what to do about it: %s", errOut)
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

	signer := signerBeside(key)

	// A second identity, so exit 3 has a cause that is not a damaged file.
	stranger := filepath.Join(work, "stranger.pub")
	if code, _, errOut := run("keygen", "-kind", "identity",
		"-out", filepath.Join(work, "stranger.key")); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}

	// Set up a good receive, so the verify cases have something to damage.
	if code, _, errOut := run("recv", "-key", key, "-signer", signer, "-in", frameDir, "-out", outDir); code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}

	cases := []struct {
		name string
		want int
		args []string
	}{
		{"success", ExitOK, []string{"verify", "-in", frameDir, "-signer", signer, "-dir", outDir}},
		{"no command", ExitUsage, nil},
		{"unknown command", ExitUsage, []string{"transmogrify"}},
		{"unknown flag", ExitUsage, []string{"send", "-nonsense"}},
		{"missing required flag", ExitUsage, []string{"send", "-key", key}},
		{"contradictory verbosity", ExitUsage, []string{"verify", "-in", frameDir, "-signer", signer, "-dir", outDir, "-quiet", "-verbose"}},
		{"missing key file", ExitInput, []string{"recv", "-key", filepath.Join(missing, "k"), "-signer", signer, "-in", frameDir, "-out", filepath.Join(work, "a")}},
		{"missing frame directory", ExitInput, []string{"recv", "-key", key, "-signer", signer, "-in", missing, "-out", filepath.Join(work, "b")}},
		{"missing signer", ExitInput, []string{"recv", "-key", key, "-signer", filepath.Join(missing, "s.pub"), "-in", frameDir, "-out", filepath.Join(work, "c")}},
		{"unverifiable manifest", ExitVerifyFailed, []string{"recv", "-key", key, "-signer", stranger, "-in", frameDir, "-out", filepath.Join(work, "d")}},
		{"missing dataset", ExitVerifyFailed, []string{"verify", "-in", frameDir, "-signer", signer, "-dir", missing}},
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

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir,
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
	if code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir); code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}
	if err := os.Remove(filepath.Join(outDir, "readme.md")); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	code, out, errOut := run("verify", "-in", frameDir, "-signer", signerBeside(frameDir), "-dir", outDir, "-quiet")
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

	code, out, _ := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir,
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

	code, out, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir,
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

	plainCode, plainOut, plainErr := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir,
		"-out", filepath.Join(work, "a"), "-json")
	loudCode, loudOut, loudErr := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir,
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

func TestKeyErrorsNameTheirFix(t *testing.T) {
	// The signer stays correct throughout: this is about the operator key's
	// diagnostics, and a wrong signer would fail earlier and hide them.
	good, frameDir, _ := sendFixture(t, "2")
	signer := signerBeside(good)
	work := t.TempDir()

	missing := filepath.Join(work, "absent.key")
	code, _, errOut := run("recv", "-key", missing, "-signer", signer, "-in", frameDir, "-out", filepath.Join(work, "a"))
	if code != ExitInput {
		t.Fatalf("missing key exited %d, want %d", code, ExitInput)
	}
	// The message must contain a command the operator can run, not only a
	// description of what went wrong.
	if !strings.Contains(errOut, "dhow keygen") {
		t.Errorf("the missing-key error does not say how to make one: %s", errOut)
	}

	permissive := filepath.Join(work, "loose.key")
	if code, _, errOut := run("keygen", "-out", permissive); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}
	if err := os.Chmod(permissive, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	code, _, errOut = run("recv", "-key", permissive, "-signer", signer, "-in", frameDir, "-out", filepath.Join(work, "b"))
	if code != ExitInput {
		t.Fatalf("permissive key exited %d, want %d", code, ExitInput)
	}
	if !strings.Contains(errOut, "chmod 600") {
		t.Errorf("the permissive-key error does not say how to fix it: %s", errOut)
	}
	if !strings.Contains(errOut, "compromised") {
		t.Errorf("the permissive-key error does not warn that the key may have been read: %s", errOut)
	}
}

func TestVerboseWarnsEarlyWhenNothingAuthenticates(t *testing.T) {
	// The wrong key looks exactly like a bad camera angle until the stream
	// ends, which on a real capture is hours. Saying so at fifty rejections
	// turns a wasted afternoon into a wasted minute.
	good, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()

	other := filepath.Join(work, "other.key")
	if code, _, errOut := run("keygen", "-out", other); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}

	// The manifest still verifies; only the operator key is wrong. That is the
	// case this warning exists for, and it is not the same as an unverifiable
	// manifest, which fails before a frame is read.
	code, _, errOut := run("recv", "-key", other, "-signer", signerBeside(good), "-in", frameDir,
		"-out", filepath.Join(work, "received"), "-verbose")
	if code != ExitIncomplete {
		t.Fatalf("recv with the wrong key exited %d, want %d", code, ExitIncomplete)
	}
	if !strings.Contains(errOut, "wrong key") {
		t.Errorf("-verbose did not name the wrong key as the likely cause: %s", errOut)
	}
}

func TestNoWrongKeyWarningOnAGoodTransfer(t *testing.T) {
	// A warning that fires on a healthy run is noise, and noise gets ignored
	// on the run where it matters.
	key, frameDir, _ := sendFixture(t, "2")

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir,
		"-out", filepath.Join(t.TempDir(), "received"), "-verbose")
	if code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}
	if strings.Contains(errOut, "wrong key") {
		t.Errorf("a healthy transfer warned about the key: %s", errOut)
	}
}

func TestRecvRefusesAnExistingOutputDirectory(t *testing.T) {
	// Extracting into a directory that already holds something would blend two
	// datasets, and every file that happened to match would still verify.
	key, frameDir, _ := sendFixture(t, "2")
	outDir := filepath.Join(t.TempDir(), "received")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir)
	if code != ExitInput {
		t.Fatalf("recv into an existing directory exited %d, want %d: %s", code, ExitInput, errOut)
	}
	if !strings.Contains(errOut, "already exists") {
		t.Errorf("the error does not say why: %s", errOut)
	}
}

func TestFailedExtractionLeavesNothingBehind(t *testing.T) {
	// A transfer that decodes and then fails to unpack must leave nothing. An
	// operator rerunning a script and finding a populated directory has been
	// handed something that looks like output and is not.
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()

	// A path whose parent is a regular file, so the staging directory cannot
	// be created and the failure happens during extraction.
	blocker := filepath.Join(work, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	outDir := filepath.Join(blocker, "received")

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir)
	if code == ExitOK {
		t.Fatalf("recv succeeded into an impossible path: %s", errOut)
	}
	if info, err := os.Stat(outDir); err == nil && info.IsDir() {
		t.Error("a failed extraction left an output directory behind")
	}
}

func TestSuccessfulExtractionLeavesNoStagingDirectory(t *testing.T) {
	key, frameDir, dataDir := sendFixture(t, "2")
	work := t.TempDir()
	outDir := filepath.Join(work, "received")

	if code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir); code != ExitOK {
		t.Fatalf("recv exited %d: %s", code, errOut)
	}
	sameTree(t, dataDir, outDir)

	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "received" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("recv left %v beside its output, want only \"received\"", names)
	}
}

// --- The signed manifest ---
//
// These are the cases the signature exists for. Everything above this point
// would pass just as well against the unsigned transfer record the manifest
// replaced, which is exactly why they are not enough on their own.

func TestKeygenIdentityWritesBothHalves(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sender.key")

	code, stdout, errOut := run("keygen", "-kind", "identity", "-out", out)
	if code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("the secret half was not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("the identity was written mode %04o; it must not be readable by others", perm)
	}

	// sender.key, not sender.key.pub: the receiving side's -signer default is
	// sender.pub, and a mismatch here turns a first transfer into a debugging
	// session.
	pub := filepath.Join(dir, "sender.pub")
	if _, err := os.Stat(pub); err != nil {
		t.Fatalf("the public half was not written to %s: %v", pub, err)
	}

	if !strings.Contains(stdout, "fingerprint ") {
		t.Errorf("keygen did not print the fingerprint operators are told to compare: %s", stdout)
	}
	if !strings.Contains(stdout, "never leaves the sending machine") {
		t.Errorf("keygen did not say the secret half stays put: %s", stdout)
	}
}

func TestKeygenIdentityJSONNamesBothPaths(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sender.key")

	code, stdout, errOut := run("keygen", "-kind", "identity", "-out", out, "-json")
	if code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}

	var result keygenResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parsing keygen JSON: %v\n%s", err, stdout)
	}
	if result.Kind != kindIdentity {
		t.Errorf("kind = %q, want %q", result.Kind, kindIdentity)
	}
	if result.PublicPath != filepath.Join(dir, "sender.pub") {
		t.Errorf("public_path = %q", result.PublicPath)
	}
	if result.Fingerprint == "" {
		t.Error("the JSON result carries no fingerprint")
	}
}

func TestKeygenRejectsAnUnknownKind(t *testing.T) {
	code, _, errOut := run("keygen", "-kind", "wizard", "-out", filepath.Join(t.TempDir(), "k"))
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, kindOperator) || !strings.Contains(errOut, kindIdentity) {
		t.Errorf("the error does not name the kinds that are accepted: %s", errOut)
	}
}

func TestKeygenIdentityRefusesToClobber(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sender.key")
	if code, _, errOut := run("keygen", "-kind", "identity", "-out", out); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}
	if code, _, _ := run("keygen", "-kind", "identity", "-out", out); code != ExitInput {
		t.Errorf("keygen overwrote an identity without -force: exit %d", code)
	}
	if code, _, errOut := run("keygen", "-kind", "identity", "-out", out, "-force"); code != ExitOK {
		t.Errorf("keygen -force exited %d: %s", code, errOut)
	}
}

func TestSendRefusesAnOperatorKeyAsAnIdentity(t *testing.T) {
	// The two kinds are recorded in the key file. Signing with a key both
	// operators hold would prove nothing about who produced the transfer, so
	// the confusion has to be caught rather than tolerated.
	dir := t.TempDir()
	key := keygen(t, dir)

	code, _, errOut := run("send", "-key", key, "-identity", key,
		"-in", fixture(t), "-out", filepath.Join(dir, "frames"))
	if code != ExitInput {
		t.Fatalf("send with an operator key as the identity exited %d, want %d", code, ExitInput)
	}
	if !strings.Contains(errOut, "identity") {
		t.Errorf("the error does not say which argument was wrong: %s", errOut)
	}
}

func TestSendReportsTheSignerFingerprint(t *testing.T) {
	// The sending operator reads this out so the receiving one can confirm
	// they hold the matching public half. It has to be there to be read.
	dir := t.TempDir()
	key := keygen(t, dir)

	code, stdout, errOut := run("send", "-key", key, "-identity", identityBeside(key),
		"-in", fixture(t), "-out", filepath.Join(dir, "frames"), "-json")
	if code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}
	var result sendResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parsing send JSON: %v\n%s", err, stdout)
	}
	if !regexp.MustCompile(`^([0-9a-f]{2}:){7}[0-9a-f]{2}$`).MatchString(result.Signer) {
		t.Errorf("signer = %q, want a colon-separated fingerprint", result.Signer)
	}
}

func TestRecvRejectsAManifestSignedByAnotherIdentity(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()

	if code, _, errOut := run("keygen", "-kind", "identity",
		"-out", filepath.Join(work, "stranger.key")); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}

	outDir := filepath.Join(work, "received")
	code, _, errOut := run("recv", "-key", key, "-signer", filepath.Join(work, "stranger.pub"),
		"-in", frameDir, "-out", outDir)
	if code != ExitVerifyFailed {
		t.Fatalf("exit = %d, want %d: %s", code, ExitVerifyFailed, errOut)
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Error("a receive with an unverifiable manifest wrote a dataset")
	}
	// Both readings are possible and they need different responses, so the
	// message must not commit to one.
	if !strings.Contains(errOut, "altered") {
		t.Errorf("the error does not offer tampering as an explanation: %s", errOut)
	}
}

func TestEveryManifestByteIsUnderTheSignature(t *testing.T) {
	// Not a sample: the point of folding the salt, nonce, and coding
	// parameters into the manifest is that none of them can be changed without
	// breaking the signature, and a sample would not show that.
	key, frameDir, _ := sendFixture(t, "2")
	path := filepath.Join(frameDir, manifestName)

	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	t.Cleanup(func() { _ = os.WriteFile(path, good, 0o644) })

	work := t.TempDir()
	for i := range good {
		altered := bytes.Clone(good)
		altered[i]++
		if err := os.WriteFile(path, altered, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		outDir := filepath.Join(work, fmt.Sprintf("out-%d", i))
		code, _, _ := run("recv", "-key", key, "-signer", signerBeside(key), "-in", frameDir, "-out", outDir)
		if code == ExitOK {
			t.Fatalf("a manifest with byte %d altered was accepted", i)
		}
		if _, err := os.Stat(outDir); !os.IsNotExist(err) {
			t.Fatalf("a manifest with byte %d altered still produced a dataset", i)
		}
	}
}

func TestVerifyReportsTheSignerItChecked(t *testing.T) {
	// A verify report that does not say whose signature it checked is the
	// unsigned record again: it says the dataset matches something, without
	// saying who wrote the something.
	frameDir, outDir, _ := received(t)

	code, result := verified(t, frameDir, outDir)
	if code != ExitOK {
		t.Fatalf("verify exited %d: %+v", code, result.Problems)
	}
	if !regexp.MustCompile(`^([0-9a-f]{2}:){7}[0-9a-f]{2}$`).MatchString(result.Signer) {
		t.Errorf("signer = %q, want a colon-separated fingerprint", result.Signer)
	}
}

func TestVerifyRejectsADatasetSignedByAnotherIdentity(t *testing.T) {
	// The case the unsigned record could not catch: the dataset is intact and
	// matches its record exactly, and the record was written by the wrong
	// person.
	frameDir, outDir, _ := received(t)
	work := t.TempDir()

	if code, _, errOut := run("keygen", "-kind", "identity",
		"-out", filepath.Join(work, "stranger.key")); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}

	code, _, errOut := run("verify", "-in", frameDir,
		"-signer", filepath.Join(work, "stranger.pub"), "-dir", outDir)
	if code != ExitVerifyFailed {
		t.Fatalf("exit = %d, want %d: %s", code, ExitVerifyFailed, errOut)
	}
}

func TestMissingSignerNamesTheFix(t *testing.T) {
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()

	code, _, errOut := run("recv", "-key", key, "-signer", filepath.Join(work, "absent.pub"),
		"-in", frameDir, "-out", filepath.Join(work, "received"))
	if code != ExitInput {
		t.Fatalf("exit = %d, want %d", code, ExitInput)
	}
	if !strings.Contains(errOut, "dhow keygen -kind identity") {
		t.Errorf("the error does not say how to produce one: %s", errOut)
	}
}

func TestDisplayRequiresAVerifiableManifest(t *testing.T) {
	// display takes no action on the manifest's content, but a frames
	// directory damaged since it was written should be caught before an
	// operator spends twenty minutes in front of a screen.
	key, frameDir, _ := sendFixture(t, "2")
	work := t.TempDir()

	if code, _, errOut := run("keygen", "-kind", "identity",
		"-out", filepath.Join(work, "stranger.key")); code != ExitOK {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}

	code, _, _ := run("display", "-in", frameDir, "-signer", filepath.Join(work, "stranger.pub"),
		"-loops", "1", "-fps", "60", "-calibration", "0", "-no-clear", "-quiet")
	if code != ExitVerifyFailed {
		t.Errorf("display with an unverifiable manifest exited %d, want %d", code, ExitVerifyFailed)
	}
	_ = key
}

func TestManifestInventoryMatchesWhatWasPacked(t *testing.T) {
	// The signed inventory is what verify checks a dataset against months
	// later. If it does not describe what send actually packed, every later
	// verification is measuring the wrong thing.
	dir := t.TempDir()
	key := keygen(t, dir)

	src := t.TempDir()
	for name, content := range map[string]string{
		"a.txt":            "alpha",
		"nested/b.txt":     "bravo",
		"nested/deep/c.md": "charlie",
	} {
		full := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	script := filepath.Join(src, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	frameDir := filepath.Join(dir, "frames")
	if code, _, errOut := run("send", "-key", key, "-identity", identityBeside(key),
		"-in", src, "-out", frameDir); code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}

	raw, err := os.ReadFile(filepath.Join(frameDir, manifestName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	public, err := ffi.LoadPublicIdentity(signerBeside(key))
	if err != nil {
		t.Fatalf("LoadPublicIdentity: %v", err)
	}
	defer public.Close()

	manifest, err := ffi.VerifyManifest(public, raw, nil)
	if err != nil {
		t.Fatalf("the manifest send just wrote does not verify: %v", err)
	}
	defer manifest.Close()

	files, err := manifest.Files()
	if err != nil {
		t.Fatalf("Files: %v", err)
	}

	want := map[string]struct {
		size       uint64
		executable bool
	}{
		"a.txt":            {5, false},
		"nested/b.txt":     {5, false},
		"nested/deep/c.md": {7, false},
		"run.sh":           {17, true},
	}
	if len(files) != len(want) {
		t.Fatalf("the manifest names %d files, want %d", len(files), len(want))
	}
	for _, got := range files {
		expected, ok := want[got.Name]
		if !ok {
			t.Errorf("the manifest names %q, which was not sent", got.Name)
			continue
		}
		if got.Size != expected.size {
			t.Errorf("%s: size = %d, want %d", got.Name, got.Size, expected.size)
		}
		if got.Executable != expected.executable {
			t.Errorf("%s: executable = %v, want %v", got.Name, got.Executable, expected.executable)
		}
		if got.Digest == ([32]byte{}) {
			t.Errorf("%s: the manifest carries a zero digest", got.Name)
		}
	}

	// The parameters the receiver will decode with are in here too, and they
	// are the ones send actually resolved rather than the ones it was asked
	// for.
	params, err := manifest.Params()
	if err != nil {
		t.Fatalf("Params: %v", err)
	}
	if params.BlockCount == 0 || params.SymbolSize == 0 || params.PayloadSize == 0 {
		t.Errorf("the manifest carries unusable session parameters: %+v", params)
	}
}
