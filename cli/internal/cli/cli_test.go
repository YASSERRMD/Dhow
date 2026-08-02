package cli

import (
	"bytes"
	"encoding/json"
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
