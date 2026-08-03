package pack

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dhow/cli/internal/ffi"
)

// writeTree creates files under a fresh directory and returns its path.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
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

func TestRoundTrip(t *testing.T) {
	files := map[string]string{
		"readme.md":      "hello",
		"src/main.go":    "package main",
		"a/b/c/deep.txt": "nested",
		"empty.txt":      "",
	}
	root := writeTree(t, files)

	var buf bytes.Buffer
	entries, err := Create(&buf, root)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(entries) != len(files) {
		t.Fatalf("packed %d entries, want %d", len(entries), len(files))
	}

	dest := t.TempDir()
	got, err := Extract(buf.Bytes(), dest)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(got) != len(files) {
		t.Fatalf("extracted %d entries, want %d", len(got), len(files))
	}

	for name, want := range files {
		data, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(name)))
		if err != nil {
			t.Errorf("reading %s: %v", name, err)
			continue
		}
		if string(data) != want {
			t.Errorf("%s = %q, want %q", name, data, want)
		}
	}
}

func TestArchiveIsDeterministic(t *testing.T) {
	// The whole transfer must be reproducible, so packing the same tree twice
	// has to produce identical bytes regardless of directory iteration order.
	root := writeTree(t, map[string]string{
		"z.txt":     "last",
		"a.txt":     "first",
		"m/n.txt":   "middle",
		"b/c/d.txt": "deep",
	})

	var first, second bytes.Buffer
	if _, err := Create(&first, root); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := Create(&second, root); err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Error("two packs of the same tree produced different bytes")
	}
}

func TestArchiveIgnoresTimestamps(t *testing.T) {
	// Touching a file must not change the archive: a timestamp in the output
	// would make the transfer unreproducible.
	root := writeTree(t, map[string]string{"a.txt": "content"})

	var before bytes.Buffer
	if _, err := Create(&before, root); err != nil {
		t.Fatalf("Create: %v", err)
	}

	path := filepath.Join(root, "a.txt")
	past := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	var after bytes.Buffer
	if _, err := Create(&after, root); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Error("archive changed after touching a file")
	}
}

func TestEntriesAreSortedByName(t *testing.T) {
	root := writeTree(t, map[string]string{
		"c.txt": "3", "a.txt": "1", "b.txt": "2",
	})
	var buf bytes.Buffer
	entries, err := Create(&buf, root)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Name >= entries[i].Name {
			t.Fatalf("entries not sorted: %q before %q", entries[i-1].Name, entries[i].Name)
		}
	}
}

func TestExecutableBitSurvives(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "run.sh")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	plain := filepath.Join(root, "data.txt")
	if err := os.WriteFile(plain, []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	if _, err := Create(&buf, root); err != nil {
		t.Fatalf("Create: %v", err)
	}

	dest := t.TempDir()
	if _, err := Extract(buf.Bytes(), dest); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	info, err := os.Stat(filepath.Join(dest, "run.sh"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Error("executable bit was lost")
	}

	info, err = os.Stat(filepath.Join(dest, "data.txt"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm()&0o100 != 0 {
		t.Error("a plain file was extracted as executable")
	}
}

func TestSymlinksAreSkipped(t *testing.T) {
	// Following a symlink could pull in a file from outside the tree, and
	// recording one would let a receiver create a link pointing anywhere.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "real.txt"), []byte("real"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	var buf bytes.Buffer
	entries, err := Create(&buf, root)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, e := range entries {
		if e.Name == "link" {
			t.Error("a symlink was packed")
		}
	}
	if len(entries) != 1 {
		t.Errorf("packed %d entries, want 1", len(entries))
	}
}

func TestValidateNameRejectsTraversal(t *testing.T) {
	for _, name := range []string{
		"",
		"/etc/passwd",
		"../secret",
		"a/../../etc/passwd",
		"docs/../../root/.ssh/id_ed25519",
		"a/b/..",
		"C:/Windows",
		"C:evil",
		"back\\slash",
		"nul\x00byte",
		strings.Repeat("a", MaxNameLen+1),
	} {
		if err := ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) accepted a hostile name", name)
		}
	}
}

func TestValidateNameAcceptsOrdinaryNames(t *testing.T) {
	for _, name := range []string{
		"a.txt", "dir/a.txt", "a/b/c/d.bin", "..hidden", "a..b", ".gitignore",
	} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) rejected a legitimate name: %v", name, err)
		}
	}
}

func TestExtractRejectsTraversalEntry(t *testing.T) {
	// Hand-build an archive naming a file outside the destination.
	var buf bytes.Buffer
	buf.Write(Magic[:])
	buf.WriteByte(Version)
	buf.Write([]byte{0, 0, 0})
	buf.Write([]byte{1, 0, 0, 0}) // one entry

	name := "../escaped.txt"
	buf.Write([]byte{byte(len(name)), 0})
	buf.WriteString(name)
	buf.WriteByte(0)
	buf.Write(make([]byte, 8)) // size 0

	dest := t.TempDir()
	if _, err := Extract(buf.Bytes(), dest); !errors.Is(err, ErrPathTraversal) {
		t.Errorf("got %v, want ErrPathTraversal", err)
	}

	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escaped.txt")); err == nil {
		t.Fatal("traversal entry escaped the destination directory")
	}
}

func TestExtractRejectsBadHeader(t *testing.T) {
	dest := t.TempDir()

	if _, err := Extract(nil, dest); !errors.Is(err, ErrTruncated) {
		t.Errorf("empty input: got %v, want ErrTruncated", err)
	}

	bad := make([]byte, 12)
	copy(bad, []byte("XXXX"))
	if _, err := Extract(bad, dest); !errors.Is(err, ErrBadMagic) {
		t.Errorf("bad magic: got %v, want ErrBadMagic", err)
	}

	wrongVersion := make([]byte, 12)
	copy(wrongVersion, Magic[:])
	wrongVersion[4] = 99
	if _, err := Extract(wrongVersion, dest); !errors.Is(err, ErrBadVersion) {
		t.Errorf("bad version: got %v, want ErrBadVersion", err)
	}
}

func TestExtractRejectsAbsurdEntryCount(t *testing.T) {
	// A declared count must not drive an allocation before it is bounded.
	buf := make([]byte, 12)
	copy(buf, Magic[:])
	buf[4] = Version
	buf[8], buf[9], buf[10], buf[11] = 0xFF, 0xFF, 0xFF, 0xFF

	if _, err := Extract(buf, t.TempDir()); !errors.Is(err, ErrTooManyFiles) {
		t.Errorf("got %v, want ErrTooManyFiles", err)
	}
}

func TestExtractRejectsOversizedDeclaredFile(t *testing.T) {
	// An entry declaring more bytes than the buffer holds must be rejected
	// before the size is used to slice, not indexed out of range.
	var buf bytes.Buffer
	buf.Write(Magic[:])
	buf.WriteByte(Version)
	buf.Write([]byte{0, 0, 0})
	buf.Write([]byte{1, 0, 0, 0})

	name := "big.bin"
	buf.Write([]byte{byte(len(name)), 0})
	buf.WriteString(name)
	buf.WriteByte(0)
	buf.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	if _, err := Extract(buf.Bytes(), t.TempDir()); err == nil {
		t.Error("an entry declaring a huge size was accepted")
	}
}

func TestExtractRejectsTruncatedBody(t *testing.T) {
	root := writeTree(t, map[string]string{"a.txt": "some content here"})
	var buf bytes.Buffer
	if _, err := Create(&buf, root); err != nil {
		t.Fatalf("Create: %v", err)
	}

	full := buf.Bytes()
	for _, cut := range []int{12, 15, len(full) - 1} {
		if cut < 0 || cut > len(full) {
			continue
		}
		if _, err := Extract(full[:cut], t.TempDir()); err == nil {
			t.Errorf("truncation to %d bytes was accepted", cut)
		}
	}
}

func TestExtractRefusesToOverwriteExistingFile(t *testing.T) {
	// O_EXCL: a symlink or file already at the target must not be followed or
	// clobbered.
	root := writeTree(t, map[string]string{"a.txt": "new"})
	var buf bytes.Buffer
	if _, err := Create(&buf, root); err != nil {
		t.Fatalf("Create: %v", err)
	}

	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "a.txt"), []byte("existing"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := Extract(buf.Bytes(), dest); err == nil {
		t.Error("extraction overwrote an existing file")
	}

	data, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "existing" {
		t.Error("the existing file was modified")
	}
}

func TestEmptyDirectoryPacks(t *testing.T) {
	var buf bytes.Buffer
	entries, err := Create(&buf, t.TempDir())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("packed %d entries from an empty tree", len(entries))
	}

	got, err := Extract(buf.Bytes(), t.TempDir())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("extracted %d entries, want 0", len(got))
	}
}

func TestCreateRecordsEachFileContentDigest(t *testing.T) {
	root := t.TempDir()
	files := map[string][]byte{
		"a.txt":       []byte("hello"),
		"empty.txt":   {},
		"sub/big.bin": bytes.Repeat([]byte{0xA5}, 3000),
	}
	for name, body := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(full, body, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	var archive bytes.Buffer
	entries, err := Create(&archive, root)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for _, e := range entries {
		// Checked against an independent digest of the file's real contents,
		// not against whatever Create happened to compute.
		want, err := ffi.Blake3(files[e.Name])
		if err != nil {
			t.Fatalf("Blake3: %v", err)
		}
		if e.Digest != want {
			t.Errorf("%s: digest = %x, want %x", e.Name, e.Digest, want)
		}
	}

	if len(entries) != len(files) {
		t.Fatalf("packed %d entries, want %d", len(entries), len(files))
	}
}

func TestCreateDigestsDifferWhenContentsDiffer(t *testing.T) {
	// Two files of the same name and length in two datasets: only the digest
	// can tell them apart, which is the whole point of recording it.
	digestOf := func(body []byte) [32]byte {
		t.Helper()
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "f.bin"), body, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		var archive bytes.Buffer
		entries, err := Create(&archive, root)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		return entries[0].Digest
	}

	a := bytes.Repeat([]byte{0x01}, 4096)
	b := bytes.Clone(a)
	b[2048] ^= 0x01

	if digestOf(a) == digestOf(b) {
		t.Error("two files differing by one bit produced the same digest")
	}
	if digestOf(a) != digestOf(bytes.Clone(a)) {
		t.Error("the same contents produced two different digests")
	}
}

func TestExtractLeavesDigestsZero(t *testing.T) {
	// Extract does not compute digests: the payload digest already covers the
	// whole archive. A zero here is the documented contract, and a test keeps
	// a caller from mistaking it for a real digest.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f.txt"), []byte("body"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var archive bytes.Buffer
	if _, err := Create(&archive, root); err != nil {
		t.Fatalf("Create: %v", err)
	}

	entries, err := Extract(archive.Bytes(), filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for _, e := range entries {
		if e.Digest != ([32]byte{}) {
			t.Errorf("%s: Extract filled a digest it does not compute", e.Name)
		}
	}
}
