package pack

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Benchmarks for the packaging path.
//
// pack.Create is the first thing `send` does and the last thing standing
// between an operator and a progress bar: it reads every byte of a dataset and
// hashes each file while writing it. If it were slow, a large transfer would
// appear to hang before printing anything, which is the complaint recorded in
// B-5.
//
// The numbers that matter here are throughput and, in the allocation column,
// whether the archive is being copied more times than the design says.

// fixtureTree writes a dataset of totalBytes spread over fileCount files.
func fixtureTree(b *testing.B, totalBytes, fileCount int) string {
	b.Helper()
	root := b.TempDir()
	per := totalBytes / fileCount

	// Deterministic content: a benchmark whose input changes between runs
	// produces numbers that cannot be compared between runs.
	block := make([]byte, per)
	for i := range block {
		block[i] = byte(i % 251)
	}

	for i := range fileCount {
		name := filepath.Join(root, fmt.Sprintf("dir%d", i%4), fmt.Sprintf("file%d.bin", i))
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			b.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(name, block, 0o644); err != nil {
			b.Fatalf("WriteFile: %v", err)
		}
	}
	return root
}

func BenchmarkCreate(b *testing.B) {
	cases := []struct {
		name  string
		total int
		files int
	}{
		// One large file: the per-byte cost, which is the digest.
		{"1MiB_1file", 1 << 20, 1},
		{"16MiB_1file", 16 << 20, 1},
		// Many small files: the per-file cost, which is a stat, an open, and
		// a hasher handle across the FFI boundary. A dataset of source code
		// looks like this, and it is the shape where per-file overhead shows.
		{"1MiB_256files", 1 << 20, 256},
	}

	for _, tc := range cases {
		root := fixtureTree(b, tc.total, tc.files)
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(tc.total))
			b.ReportAllocs()
			for b.Loop() {
				// io.Discard rather than a buffer: this measures packing, and
				// a growing buffer would fold reallocation into the number.
				if _, err := Create(io.Discard, root); err != nil {
					b.Fatalf("Create: %v", err)
				}
			}
		})
	}
}

func BenchmarkExtract(b *testing.B) {
	for _, tc := range []struct {
		name  string
		total int
		files int
	}{
		{"1MiB_1file", 1 << 20, 1},
		{"1MiB_256files", 1 << 20, 256},
	} {
		root := fixtureTree(b, tc.total, tc.files)
		var archive bytes.Buffer
		if _, err := Create(&archive, root); err != nil {
			b.Fatalf("Create: %v", err)
		}
		data := archive.Bytes()

		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(tc.total))
			b.ReportAllocs()
			for b.Loop() {
				// A fresh destination each iteration, because Extract refuses
				// to overwrite - which is the behaviour under test everywhere
				// else and must not be worked around here.
				dest := filepath.Join(b.TempDir(), "out")
				if _, err := Extract(data, dest); err != nil {
					b.Fatalf("Extract: %v", err)
				}
			}
		})
	}
}
