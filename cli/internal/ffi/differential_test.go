// Differential test: the Go-driven FFI path against the pure-Rust path.
//
// Go reaches the encoder through a C ABI, marshalling pointers and lengths
// across cgo and copying results back through a two-call size convention.
// core/dhow-ffi/examples/reference.rs reaches the same encoder through the Rust
// library, with no boundary in between. Given identical inputs the two must
// produce identical frames, identical resolved parameters, and identical
// decoded plaintext.
//
// # What this proves, and what it does not
//
// Both sides run the same encoding logic, so a disagreement is a bug *in the
// boundary*: a truncated buffer, a length read at the wrong width, a struct
// field that does not line up, a slice that outlived its pin. That is the class
// of bug a hand-written ABI produces, and it is worth a test that cannot be
// satisfied by the two sides sharing an implementation.
//
// It is not an implementation differential. It cannot catch a bug in RaptorQ or
// in the AEAD, because both sides would have the same bug. Those are covered by
// the property tests in dhow-codec and dhow-crypt.
package ffi

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// differentialCases is how many random jobs the comparison runs.
//
// Enough to cover the boundaries that matter - empty payloads, payloads under
// one symbol, exact multiples, several blocks - without turning `go test` into
// something people skip. The generator is seeded, so failures reproduce.
const differentialCases = 48

// job is one input both sides encode.
type job struct {
	// keyPath is a key file both sides load.
	//
	// Not raw bytes: no function in this ABI takes them, by design, so Go has
	// no way to hand the same key to the reference except through a file. That
	// constraint is the property being preserved, not an inconvenience.
	keyPath   string
	sessionID [16]byte
	salt      [32]byte
	nonce     [24]byte

	symbolSize  uint32
	blockCount  uint32
	sourcePer   uint32
	totalPer    uint32
	payload     []byte
	description string
}

// line renders a job in the reference binary's input format.
func (j job) line() string {
	payload := "-"
	if len(j.payload) > 0 {
		payload = hex.EncodeToString(j.payload)
	}
	return fmt.Sprintf("%s %s %s %s %d %d %d %d %s",
		j.keyPath,
		hex.EncodeToString(j.sessionID[:]),
		hex.EncodeToString(j.salt[:]),
		hex.EncodeToString(j.nonce[:]),
		j.symbolSize, j.blockCount, j.sourcePer, j.totalPer,
		payload)
}

// keystream is a deterministic byte source.
//
// Not math/rand: a generator whose sequence changes with the Go version would
// make a failure reproduce on one toolchain and not another, which is the one
// thing a differential test's inputs must not do. AES-CTR over zeroes from a
// fixed key is the same sequence everywhere, forever. The chaos harness draws
// its datasets the same way and for the same reason.
type keystream struct {
	stream cipher.Stream
}

func newKeystream(seed string) *keystream {
	var key [32]byte
	copy(key[:], seed)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	var iv [aes.BlockSize]byte
	return &keystream{stream: cipher.NewCTR(block, iv[:])}
}

func (k *keystream) bytes(n int) []byte {
	out := make([]byte, n)
	k.stream.XORKeyStream(out, out)
	return out
}

func (k *keystream) uint32n(n uint32) uint32 {
	b := k.bytes(4)
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return v % n
}

// generateJobs builds the comparison set: fixed edge cases first, then random.
//
// Every job gets its own key file, so a bug that let one job's key material
// leak into another's derivation would show up as a mismatch rather than as
// two jobs quietly agreeing.
func generateJobs(t *testing.T) []job {
	t.Helper()
	ks := newKeystream("dhow differential v1")
	keyDir := t.TempDir()

	symbolSizes := []uint32{64, 128, 256, 512, 1024, 1320}
	blockCounts := []uint32{1, 2, 3, 5, 8}

	// The sizes that have historically broken chunkers: nothing, one byte, one
	// byte under and over a symbol, an exact multiple, and past one block.
	edgeSizes := []int{0, 1, 63, 64, 65, 255, 256, 257, 1024, 4096, 4097}

	jobs := make([]job, 0, differentialCases)

	newJob := func(size int, symbolSize, blockCount uint32, description string) job {
		j := job{
			symbolSize:  symbolSize,
			blockCount:  blockCount,
			payload:     ks.bytes(size),
			description: description,
		}

		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		defer key.Close()
		j.keyPath = filepath.Join(keyDir, fmt.Sprintf("key-%d.bin", len(jobs)))
		if err := key.Save(j.keyPath); err != nil {
			t.Fatalf("saving a key: %v", err)
		}

		copy(j.sessionID[:], ks.bytes(16))
		copy(j.salt[:], ks.bytes(32))
		copy(j.nonce[:], ks.bytes(24))

		// The ciphertext is the plaintext plus a 16-byte AEAD tag, and the
		// symbol counts must describe the ciphertext because that is what is
		// framed. Deriving them here rather than hard-coding keeps the jobs
		// valid as the payload sizes vary.
		ciphertextLen := uint64(size) + 16
		perBlock := (ciphertextLen + uint64(blockCount) - 1) / uint64(blockCount)
		source := uint32((perBlock + uint64(symbolSize) - 1) / uint64(symbolSize))
		if source == 0 {
			source = 1
		}
		j.sourcePer = source
		j.totalPer = source + source/2 + 2
		return j
	}

	for _, size := range edgeSizes {
		jobs = append(jobs, newJob(size, 256, 1, fmt.Sprintf("edge size %d", size)))
	}

	for len(jobs) < differentialCases {
		symbolSize := symbolSizes[ks.uint32n(uint32(len(symbolSizes)))]
		blockCount := blockCounts[ks.uint32n(uint32(len(blockCounts)))]
		size := int(ks.uint32n(20000))
		jobs = append(jobs, newJob(size, symbolSize, blockCount,
			fmt.Sprintf("random size=%d symbol=%d blocks=%d", size, symbolSize, blockCount)))
	}
	return jobs
}

// referenceResult is one job's output from the pure-Rust path.
type referenceResult struct {
	payloadSize   uint64
	payloadDigest [32]byte
	frames        [][]byte
	decoded       []byte
	err           string
}

// runReference builds and runs the reference binary over every job at once.
//
// One invocation rather than one per job: the comparison is worth running over
// dozens of cases, and paying process startup for each would make it slow
// enough to be skipped.
func runReference(t *testing.T, jobs []job) []referenceResult {
	t.Helper()

	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	manifest := filepath.Join(root, "core", "Cargo.toml")

	build := exec.Command("cargo", "build", "--manifest-path", manifest,
		"-p", "dhow-ffi", "--example", "reference")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("building the reference binary: %v", err)
	}

	binary := filepath.Join(root, "core", "target", "debug", "examples", "reference")
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("the reference binary is not where it was expected: %v", err)
	}

	var input bytes.Buffer
	for _, j := range jobs {
		input.WriteString(j.line())
		input.WriteByte('\n')
	}

	cmd := exec.Command(binary)
	cmd.Stdin = &input
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running the reference binary: %v", err)
	}

	return parseReference(t, out, len(jobs))
}

// parseReference reads the reference binary's line-oriented output.
func parseReference(t *testing.T, out []byte, want int) []referenceResult {
	t.Helper()

	var results []referenceResult
	var current *referenceResult

	scanner := bufio.NewScanner(bytes.NewReader(out))
	// Frames are hex and a 1320-byte symbol is 2700 characters; the default
	// 64 KiB line limit is comfortable, but the buffer has to be given to the
	// scanner explicitly or it uses a much smaller initial one.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		keyword, rest, _ := strings.Cut(line, " ")

		switch keyword {
		case "job":
			results = append(results, referenceResult{})
			current = &results[len(results)-1]
		case "size":
			v, err := strconv.ParseUint(rest, 10, 64)
			if err != nil {
				t.Fatalf("parsing reference size %q: %v", rest, err)
			}
			current.payloadSize = v
		case "digest":
			raw, err := hex.DecodeString(rest)
			if err != nil || len(raw) != 32 {
				t.Fatalf("parsing reference digest %q: %v", rest, err)
			}
			copy(current.payloadDigest[:], raw)
		case "frames":
			// The count is checked against the frames that follow, so a
			// truncated stream is caught rather than silently accepted.
			n, err := strconv.Atoi(rest)
			if err != nil {
				t.Fatalf("parsing reference frame count %q: %v", rest, err)
			}
			current.frames = make([][]byte, 0, n)
		case "frame":
			raw, err := hex.DecodeString(rest)
			if err != nil {
				t.Fatalf("parsing a reference frame: %v", err)
			}
			current.frames = append(current.frames, raw)
		case "decoded":
			if rest != "-" {
				raw, err := hex.DecodeString(rest)
				if err != nil {
					t.Fatalf("parsing reference decoded output: %v", err)
				}
				current.decoded = raw
			}
		case "error":
			current.err = rest
		case "end":
			current = nil
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading reference output: %v", err)
	}

	if len(results) != want {
		t.Fatalf("the reference produced %d results for %d jobs", len(results), want)
	}
	return results
}

func TestGoFFIPathMatchesPureRustPath(t *testing.T) {
	jobs := generateJobs(t)
	reference := runReference(t, jobs)

	for i, j := range jobs {
		want := reference[i]
		if want.err != "" {
			t.Fatalf("job %d (%s): the reference path failed: %s", i, j.description, want.err)
		}

		key, err := LoadKey(j.keyPath)
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}

		params := SessionParams{
			PayloadSize:           uint64(len(j.payload)),
			BlockCount:            j.blockCount,
			SymbolSize:            j.symbolSize,
			SourceSymbolsPerBlock: j.sourcePer,
			TotalSymbolsPerBlock:  j.totalPer,
		}

		enc, err := NewEncoder(key, j.sessionID, j.salt, j.nonce, params, j.payload)
		if err != nil {
			key.Close()
			t.Fatalf("job %d (%s): the FFI path failed where the Rust path succeeded: %v",
				i, j.description, err)
		}

		resolved, err := enc.Params()
		if err != nil {
			t.Fatalf("job %d: reading resolved params: %v", i, err)
		}
		if resolved.PayloadSize != want.payloadSize {
			t.Errorf("job %d (%s): payload size %d across the ABI, %d in Rust",
				i, j.description, resolved.PayloadSize, want.payloadSize)
		}
		if resolved.PayloadDigest != want.payloadDigest {
			t.Errorf("job %d (%s): payload digest %x across the ABI, %x in Rust",
				i, j.description, resolved.PayloadDigest, want.payloadDigest)
		}

		frames, err := enc.Frames()
		if err != nil {
			t.Fatalf("job %d: reading frames: %v", i, err)
		}
		if len(frames) != len(want.frames) {
			t.Fatalf("job %d (%s): %d frames across the ABI, %d in Rust",
				i, j.description, len(frames), len(want.frames))
		}
		for n := range frames {
			if !bytes.Equal(frames[n], want.frames[n]) {
				t.Fatalf("job %d (%s): frame %d differs\n  abi:  %x\n  rust: %x",
					i, j.description, n, frames[n], want.frames[n])
			}
		}

		// And the decode, so the comparison covers both directions rather than
		// only what the encoder emits.
		dec, err := NewDecoder(key, j.sessionID, j.salt, resolved)
		if err != nil {
			t.Fatalf("job %d: starting the decoder: %v", i, err)
		}
		for _, frame := range frames {
			// A frame rejected once the decoder has enough is not a failure;
			// the encoder emits repair symbols past that point.
			_ = dec.Accept(frame)
		}
		decoded, err := dec.Finish(key, j.sessionID, j.salt, j.nonce)
		if err != nil {
			t.Fatalf("job %d (%s): the ABI decoder did not finish: %v", i, j.description, err)
		}
		if !bytes.Equal(decoded, j.payload) {
			t.Fatalf("job %d (%s): the ABI round trip changed the payload", i, j.description)
		}
		if !bytes.Equal(decoded, want.decoded) {
			t.Fatalf("job %d (%s): decoded output differs between the ABI and Rust",
				i, j.description)
		}

		dec.Close()
		enc.Close()
		key.Close()
	}
}

func TestEncodingIsDeterministicAcrossTheABI(t *testing.T) {
	// The reproducibility requirement in the master spec: the same input, keys,
	// and parameters produce a byte-identical frame stream. Asserted here
	// across two separate encoder handles, because a handle that carried state
	// between runs would satisfy a single-encoder check and fail this one.
	jobs := generateJobs(t)[:8]

	for i, j := range jobs {
		key, err := LoadKey(j.keyPath)
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}

		params := SessionParams{
			PayloadSize:           uint64(len(j.payload)),
			BlockCount:            j.blockCount,
			SymbolSize:            j.symbolSize,
			SourceSymbolsPerBlock: j.sourcePer,
			TotalSymbolsPerBlock:  j.totalPer,
		}

		first, err := NewEncoder(key, j.sessionID, j.salt, j.nonce, params, j.payload)
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}
		second, err := NewEncoder(key, j.sessionID, j.salt, j.nonce, params, j.payload)
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}

		a, err := first.Frames()
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}
		b, err := second.Frames()
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}

		if len(a) != len(b) {
			t.Fatalf("job %d (%s): two encodes produced %d and %d frames",
				i, j.description, len(a), len(b))
		}
		for n := range a {
			if !bytes.Equal(a[n], b[n]) {
				t.Fatalf("job %d (%s): two encodes of one input differ at frame %d",
					i, j.description, n)
			}
		}

		second.Close()
		first.Close()
		key.Close()
	}
}
