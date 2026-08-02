// Package pack turns a directory into a single deterministic byte stream and
// back again.
//
// # Determinism
//
// The same directory contents must produce byte-identical output on every run
// and on every machine, because the whole transfer is required to be
// reproducible. That rules out anything the filesystem supplies incidentally:
// entries are sorted by name, and no timestamp, uid, gid, or inode is
// recorded. The only mode bit kept is whether the file is executable, since
// that changes what the file *is* rather than describing when it was touched.
//
// # Extraction is hostile-input handling
//
// An archive arriving over the optical channel is attacker-controlled until
// the manifest signature says otherwise, and even a signed archive may have
// been built by a mistaken sender. Extraction therefore enforces its own
// limits rather than trusting the header: names are re-validated against
// traversal, the entry count and total size are bounded, and no entry may
// write outside the destination directory.
package pack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Magic identifies a Dhow archive.
var Magic = [4]byte{'D', 'H', 'A', 'R'}

// Version is the archive format version.
const Version uint8 = 1

// Limits applied when reading an archive.
const (
	// MaxNameLen matches the manifest's file name limit.
	MaxNameLen = 4096
	// MaxEntries bounds the declared entry count before it drives any
	// allocation.
	MaxEntries = 1_000_000
	// MaxTotalSize bounds the sum of extracted file sizes, so a small archive
	// cannot ask for an unbounded write.
	MaxTotalSize int64 = 64 << 30
	// MaxFileSize bounds any single extracted file.
	MaxFileSize int64 = 16 << 30
)

// Errors reported by this package.
var (
	ErrBadMagic      = errors.New("pack: not a dhow archive")
	ErrBadVersion    = errors.New("pack: unsupported archive version")
	ErrTruncated     = errors.New("pack: archive is truncated")
	ErrPathTraversal = errors.New("pack: entry name escapes the destination")
	ErrTooLarge      = errors.New("pack: archive exceeds a size limit")
	ErrTooManyFiles  = errors.New("pack: archive declares too many entries")
)

// Entry describes one file in an archive.
type Entry struct {
	// Name is a relative slash-separated path.
	Name string
	// Executable records whether the owner execute bit was set.
	Executable bool
	// Size is the file's length in bytes.
	Size int64
}

// ValidateName rejects a name that could escape the extraction directory.
//
// This mirrors the manifest's rule deliberately: the archive and the manifest
// describe the same files, and a name that one accepts and the other rejects
// would be a gap between them. Every slash-separated component is inspected,
// because a name whose first component is harmless can still escape later.
func ValidateName(name string) error {
	if name == "" || len(name) > MaxNameLen {
		return fmt.Errorf("%w: %q", ErrPathTraversal, name)
	}
	// Backslash is a separator on a Windows receiver and ordinary data on a
	// Unix one. The sender cannot know which, so it is rejected outright.
	if strings.ContainsAny(name, "\x00\\") {
		return fmt.Errorf("%w: %q", ErrPathTraversal, name)
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("%w: %q", ErrPathTraversal, name)
	}
	// A drive-relative name such as C:evil.
	if len(name) > 1 && name[1] == ':' {
		return fmt.Errorf("%w: %q", ErrPathTraversal, name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return fmt.Errorf("%w: %q", ErrPathTraversal, name)
		}
	}
	return nil
}

// Create walks root and writes a deterministic archive to w.
//
// Only regular files are included. Symlinks are skipped rather than followed:
// following one could pull in a file from outside the tree, and recording one
// would let a receiver be talked into creating a link pointing anywhere.
func Create(w io.Writer, root string) ([]Entry, error) {
	entries, err := collect(root)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 0, 4+1+3+4)
	header = append(header, Magic[:]...)
	header = append(header, Version)
	header = append(header, 0, 0, 0) // reserved
	header = binary.LittleEndian.AppendUint32(header, uint32(len(entries)))
	if _, err := w.Write(header); err != nil {
		return nil, fmt.Errorf("writing archive header: %w", err)
	}

	for _, e := range entries {
		if err := writeEntry(w, root, e); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// collect gathers and sorts the regular files under root.
func collect(root string) ([]Entry, error) {
	var entries []Entry

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip anything that is not a regular file: directories are implied by
		// the names, and symlinks are deliberately not carried.
		if !d.Type().IsRegular() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("resolving %s: %w", path, err)
		}
		name := filepath.ToSlash(rel)
		if err := ValidateName(name); err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if info.Size() > MaxFileSize {
			return fmt.Errorf("%w: %s is %d bytes", ErrTooLarge, name, info.Size())
		}

		entries = append(entries, Entry{
			Name: name,
			// Only the executable bit survives. Everything else about the mode
			// varies by machine and would break reproducibility.
			Executable: info.Mode().Perm()&0o100 != 0,
			Size:       info.Size(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(entries) > MaxEntries {
		return nil, fmt.Errorf("%w: %d", ErrTooManyFiles, len(entries))
	}

	// Sorting is what makes the output independent of directory iteration
	// order, which varies by filesystem and by run.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	var total int64
	for _, e := range entries {
		total += e.Size
		if total > MaxTotalSize {
			return nil, fmt.Errorf("%w: total exceeds %d bytes", ErrTooLarge, MaxTotalSize)
		}
	}
	return entries, nil
}

// writeEntry appends one entry's header and contents.
func writeEntry(w io.Writer, root string, e Entry) error {
	var flags uint8
	if e.Executable {
		flags = 1
	}

	head := make([]byte, 0, 2+len(e.Name)+1+8)
	head = binary.LittleEndian.AppendUint16(head, uint16(len(e.Name)))
	head = append(head, e.Name...)
	head = append(head, flags)
	head = binary.LittleEndian.AppendUint64(head, uint64(e.Size))
	if _, err := w.Write(head); err != nil {
		return fmt.Errorf("writing entry header for %s: %w", e.Name, err)
	}

	f, err := os.Open(filepath.Join(root, filepath.FromSlash(e.Name)))
	if err != nil {
		return fmt.Errorf("opening %s: %w", e.Name, err)
	}
	// Read-only: a failing Close reports nothing the read did not already.
	defer func() { _ = f.Close() }()

	n, err := io.Copy(w, f)
	if err != nil {
		return fmt.Errorf("reading %s: %w", e.Name, err)
	}
	// A file that changed size between the walk and the read would desynchronise
	// every following entry, so it is an error rather than something to absorb.
	if n != e.Size {
		return fmt.Errorf("%s changed size during packing: expected %d, read %d", e.Name, e.Size, n)
	}
	return nil
}

// Extract reads an archive from data and writes its files under dest.
//
// Every name is re-validated and every resolved path is confirmed to stay
// within dest, so neither a traversal name nor a symlink already present at
// the destination can redirect a write outside it.
func Extract(data []byte, dest string) ([]Entry, error) {
	if len(data) < 12 {
		return nil, ErrTruncated
	}
	if [4]byte(data[0:4]) != Magic {
		return nil, ErrBadMagic
	}
	if data[4] != Version {
		return nil, fmt.Errorf("%w: %d", ErrBadVersion, data[4])
	}

	count := binary.LittleEndian.Uint32(data[8:12])
	if count > MaxEntries {
		return nil, fmt.Errorf("%w: %d", ErrTooManyFiles, count)
	}

	absDest, err := filepath.Abs(dest)
	if err != nil {
		return nil, fmt.Errorf("resolving destination: %w", err)
	}
	if err := os.MkdirAll(absDest, 0o755); err != nil {
		return nil, fmt.Errorf("creating destination: %w", err)
	}

	// Capacity is bounded by what the buffer could actually hold, not by the
	// declared count, so the claim alone drives no allocation.
	const minEntry = 2 + 1 + 8
	entries := make([]Entry, 0, min(int(count), len(data)/minEntry+1))

	offset := 12
	var total int64

	for range count {
		entry, next, err := readEntry(data, offset)
		if err != nil {
			return nil, err
		}

		total += entry.Size
		if total > MaxTotalSize {
			return nil, fmt.Errorf("%w: extraction exceeds %d bytes", ErrTooLarge, MaxTotalSize)
		}

		body := data[next : next+int(entry.Size)]
		if err := writeFile(absDest, entry, body); err != nil {
			return nil, err
		}

		entries = append(entries, entry)
		offset = next + int(entry.Size)
	}

	return entries, nil
}

// readEntry parses one entry header, returning it and the offset of its body.
func readEntry(data []byte, offset int) (Entry, int, error) {
	if offset+2 > len(data) {
		return Entry{}, 0, ErrTruncated
	}
	nameLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	if nameLen > MaxNameLen {
		return Entry{}, 0, fmt.Errorf("%w: name length %d", ErrPathTraversal, nameLen)
	}

	headEnd := offset + 2 + nameLen + 1 + 8
	if headEnd > len(data) {
		return Entry{}, 0, ErrTruncated
	}

	name := string(data[offset+2 : offset+2+nameLen])
	if err := ValidateName(name); err != nil {
		return Entry{}, 0, err
	}

	flags := data[offset+2+nameLen]
	size := binary.LittleEndian.Uint64(data[offset+3+nameLen : headEnd])

	// Check the declared size against the remaining bytes before it is used as
	// a length, so an absurd claim cannot index out of range.
	if size > uint64(MaxFileSize) || headEnd+int(size) > len(data) {
		return Entry{}, 0, ErrTruncated
	}

	return Entry{
		Name:       name,
		Executable: flags&1 != 0,
		Size:       int64(size),
	}, headEnd, nil
}

// writeFile writes one extracted entry, confirming it lands inside dest.
func writeFile(absDest string, e Entry, body []byte) error {
	target := filepath.Join(absDest, filepath.FromSlash(e.Name))

	// Join cleans the path, so this catches any traversal the name check might
	// not have anticipated. Belt and braces on the step that actually writes.
	if target != absDest && !strings.HasPrefix(target, absDest+string(os.PathSeparator)) {
		return fmt.Errorf("%w: %q", ErrPathTraversal, e.Name)
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", e.Name, err)
	}

	mode := os.FileMode(0o644)
	if e.Executable {
		mode = 0o755
	}

	// O_EXCL: refuse to follow or overwrite anything already at the target. A
	// symlink planted at the destination would otherwise redirect the write.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("creating %s: %w", e.Name, err)
	}

	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing %s: %w", e.Name, err)
	}

	// Close is checked rather than deferred and discarded: on some filesystems
	// a write error surfaces only here, and reporting a file as extracted when
	// its bytes never landed would be exactly the silent corruption this
	// project exists to rule out.
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", e.Name, err)
	}
	return nil
}
