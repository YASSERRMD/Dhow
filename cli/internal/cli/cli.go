// Package cli implements the dhow command surface.
//
// # Exit codes
//
// Exit codes are part of the interface and are stable. A script driving a
// transfer needs to distinguish "the transfer failed" from "the input was
// wrong", because only one of those is worth retrying.
//
//	0  success
//	1  usage error: bad flags, missing arguments
//	2  input error: a file is missing, unreadable, or malformed
//	3  verification failed: a digest, MAC, or signature did not match
//	4  transfer incomplete: not enough frames were received
//	5  internal error
//
// # Transport
//
// send writes frames to a directory and recv reads them back. The optical
// layer, which renders frames to a screen and captures them with a camera, is
// a later phase; this transport is what the loopback tests and the CI harness
// use, and it keeps the codec and crypto path exercised end to end without
// hardware.
package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"dhow/cli/internal/display"
	"dhow/cli/internal/ffi"
	"dhow/cli/internal/pack"
	"dhow/cli/internal/render"
)

// Exit codes. See the package comment; these are a stable contract.
const (
	ExitOK           = 0
	ExitUsage        = 1
	ExitInput        = 2
	ExitVerifyFailed = 3
	ExitIncomplete   = 4
	ExitInternal     = 5
)

// Env is the environment a command runs in, injected so tests can drive the
// CLI without touching the real streams.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	Args   []string
}

// exitError carries an exit code alongside a message.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func failf(code int, format string, args ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, args...)}
}

// Run dispatches a subcommand and returns the process exit code.
func Run(env Env) int {
	if len(env.Args) < 1 {
		usage(env.Stderr)
		return ExitUsage
	}

	name, args := env.Args[0], env.Args[1:]

	var err error
	switch name {
	case "keygen":
		err = runKeygen(env, args)
	case "send":
		err = runSend(env, args)
	case "recv":
		err = runRecv(env, args)
	case "display":
		err = runDisplay(env, args)
	case "verify":
		err = runVerify(env, args)
	case "version":
		err = runVersion(env, args)
	case "help", "-h", "--help":
		usage(env.Stdout)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(env.Stderr, "dhow: unknown command %q\n\n", name)
		usage(env.Stderr)
		return ExitUsage
	}

	if err == nil {
		return ExitOK
	}

	var ee *exitError
	if errors.As(err, &ee) {
		_, _ = fmt.Fprintf(env.Stderr, "dhow: %v\n", ee.err)
		return ee.code
	}
	_, _ = fmt.Fprintf(env.Stderr, "dhow: %v\n", err)
	return ExitInternal
}

func usage(w io.Writer) {
	// Nothing useful can be done if the help text fails to write.
	_, _ = fmt.Fprint(w, `dhow - air-gapped data courier

Usage:
  dhow <command> [flags]

Commands:
  keygen    generate an operator key
  send      encode a directory into a stream of QR frames
  display   loop a frame stream on screen for a camera to read
  recv      decode captured frames back into a directory
  verify    check a received dataset against its transfer record
  version   print version and ABI information

Run "dhow <command> -h" for the flags of a command.

Exit codes:
  0 success   1 usage   2 input   3 verification failed
  4 incomplete   5 internal
`)
}

// newFlagSet builds a flag set that reports errors through our own channel
// rather than calling os.Exit, so Run stays testable.
func newFlagSet(name string, env Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs
}

// emit writes a result as JSON or as human-readable lines.
func emit(w io.Writer, asJSON bool, payload any, human string) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}
	_, err := fmt.Fprint(w, human)
	return err
}

// --- keygen ---

type keygenResult struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

func runKeygen(env Env, args []string) error {
	fs := newFlagSet("keygen", env)
	out := fs.String("out", "operator.key", "path to write the operator key to")
	force := fs.Bool("force", false, "overwrite an existing key file")
	asJSON := fs.Bool("json", false, "emit machine-readable output")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}

	// Refuse to clobber a key by default. Overwriting one silently would
	// destroy the only copy of a secret that cannot be regenerated.
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			return failf(ExitInput, "%s already exists; pass -force to overwrite", *out)
		}
	}

	key, err := ffi.GenerateKey()
	if err != nil {
		return failf(ExitInternal, "generating key: %w", err)
	}
	defer key.Close()

	if err := key.Save(*out); err != nil {
		return failf(ExitInput, "writing %s: %w", *out, err)
	}

	return emit(env.Stdout, *asJSON,
		keygenResult{Path: *out, Mode: "0600"},
		fmt.Sprintf("wrote operator key to %s (mode 0600)\n"+
			"keep this file secret; both operators need the same key\n", *out))
}

// --- send ---

type sendResult struct {
	SessionID  string `json:"session_id"`
	Files      int    `json:"files"`
	PayloadLen int    `json:"payload_bytes"`
	Frames     int    `json:"frames"`
	OutDir     string `json:"out_dir"`
}

// transferRecord is what a receiver needs to configure its decoder.
//
// In the finished product this travels as the signed manifest inside the frame
// stream. Until the optical layer and manifest frames exist, it is written
// alongside the frames so send and recv can be exercised end to end. It carries
// no secret: the salt and nonce are public by design, and the payload is
// unreadable without the operator key.
type transferRecord struct {
	Version               int    `json:"version"`
	SessionID             string `json:"session_id"`
	Salt                  string `json:"salt"`
	Nonce                 string `json:"nonce"`
	PayloadSize           uint64 `json:"payload_size"`
	BlockCount            uint32 `json:"block_count"`
	SymbolSize            uint32 `json:"symbol_size"`
	SourceSymbolsPerBlock uint32 `json:"source_symbols_per_block"`
	TotalSymbolsPerBlock  uint32 `json:"total_symbols_per_block"`
	PayloadDigest         string `json:"payload_digest"`
	Files                 int    `json:"files"`
}

const recordName = "transfer.json"

func runSend(env Env, args []string) error {
	fs := newFlagSet("send", env)
	keyPath := fs.String("key", "operator.key", "operator key file")
	in := fs.String("in", "", "directory to send (required)")
	outDir := fs.String("out", "frames", "directory to write frames to")
	symbolSize := fs.Uint("symbol-size", 256, "bytes per symbol (64..65531)")
	blocks := fs.Uint("blocks", 1, "number of source blocks")
	overhead := fs.Uint("overhead", 50, "percent repair symbols above the minimum")
	qrVersion := fs.Uint("qr-version", 0, "QR version 1..40, or 0 to fit each frame")
	qrEcc := fs.String("qr-ecc", "M", "QR error correction: L, M, Q, or H")
	qrScale := fs.Uint("qr-scale", 8, "PNG pixels per QR module")
	emitQR := fs.Bool("qr", false, "also render each frame as a QR code PNG")
	asJSON := fs.Bool("json", false, "emit machine-readable output")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	if *in == "" {
		return failf(ExitUsage, "-in is required")
	}

	info, err := os.Stat(*in)
	if err != nil {
		return failf(ExitInput, "reading %s: %w", *in, err)
	}
	if !info.IsDir() {
		return failf(ExitUsage, "%s is not a directory", *in)
	}

	var archive strings.Builder
	entries, err := pack.Create(&archive, *in)
	if err != nil {
		return failf(ExitInput, "packing %s: %w", *in, err)
	}
	payload := []byte(archive.String())

	key, err := ffi.LoadKey(*keyPath)
	if err != nil {
		return failf(ExitInput, "loading %s: %w", *keyPath, err)
	}
	defer key.Close()

	var sessionID [16]byte
	var salt [32]byte
	var nonce [24]byte
	for _, b := range [][]byte{sessionID[:], salt[:], nonce[:]} {
		if _, err := rand.Read(b); err != nil {
			return failf(ExitInternal, "drawing session randomness: %w", err)
		}
	}

	params, err := planSession(len(payload), *symbolSize, *blocks, *overhead)
	if err != nil {
		return &exitError{code: ExitUsage, err: err}
	}

	enc, err := ffi.NewEncoder(key, sessionID, salt, nonce, params, payload)
	if err != nil {
		return failf(ExitInput, "building frames: %w", err)
	}
	defer enc.Close()

	frames, err := enc.Frames()
	if err != nil {
		return failf(ExitInternal, "reading frames: %w", err)
	}
	resolved, err := enc.Params()
	if err != nil {
		return failf(ExitInternal, "reading session parameters: %w", err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return failf(ExitInput, "creating %s: %w", *outDir, err)
	}
	for i, frame := range frames {
		name := filepath.Join(*outDir, fmt.Sprintf("frame-%06d.bin", i))
		if err := os.WriteFile(name, frame, 0o644); err != nil {
			return failf(ExitInput, "writing %s: %w", name, err)
		}
	}

	if *emitQR {
		if len(*qrEcc) != 1 {
			return failf(ExitUsage, "-qr-ecc must be a single letter L, M, Q, or H")
		}
		if err := renderFrames(frames, *outDir, int(*qrVersion), (*qrEcc)[0], int(*qrScale)); err != nil {
			return err
		}
	}

	record := transferRecord{
		Version:               1,
		SessionID:             hex.EncodeToString(sessionID[:]),
		Salt:                  hex.EncodeToString(salt[:]),
		Nonce:                 hex.EncodeToString(nonce[:]),
		PayloadSize:           resolved.PayloadSize,
		BlockCount:            resolved.BlockCount,
		SymbolSize:            resolved.SymbolSize,
		SourceSymbolsPerBlock: resolved.SourceSymbolsPerBlock,
		TotalSymbolsPerBlock:  resolved.TotalSymbolsPerBlock,
		PayloadDigest:         hex.EncodeToString(resolved.PayloadDigest[:]),
		Files:                 len(entries),
	}
	recordBytes, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return failf(ExitInternal, "encoding transfer record: %w", err)
	}
	recordPath := filepath.Join(*outDir, recordName)
	if err := os.WriteFile(recordPath, append(recordBytes, '\n'), 0o644); err != nil {
		return failf(ExitInput, "writing %s: %w", recordPath, err)
	}

	return emit(env.Stdout, *asJSON,
		sendResult{
			SessionID:  record.SessionID,
			Files:      len(entries),
			PayloadLen: len(payload),
			Frames:     len(frames),
			OutDir:     *outDir,
		},
		fmt.Sprintf("session   %s\nfiles     %d\npayload   %d bytes\nframes    %d\nwritten   %s\n",
			record.SessionID, len(entries), len(payload), len(frames), *outDir))
}

// planSession chooses coding parameters for a payload.
func planSession(payloadLen int, symbolSize, blocks, overheadPct uint) (ffi.SessionParams, error) {
	if symbolSize < 64 || symbolSize > 65531 {
		return ffi.SessionParams{}, fmt.Errorf("-symbol-size must be between 64 and 65531, got %d", symbolSize)
	}
	if blocks == 0 || blocks > 1024 {
		return ffi.SessionParams{}, fmt.Errorf("-blocks must be between 1 and 1024, got %d", blocks)
	}
	if overheadPct > 500 {
		return ffi.SessionParams{}, fmt.Errorf("-overhead must be at most 500, got %d", overheadPct)
	}

	// Framing operates on ciphertext, which is longer by the AEAD tag.
	ciphertextLen := uint64(payloadLen) + 16
	perBlock := (ciphertextLen + uint64(blocks) - 1) / uint64(blocks)
	source := (perBlock + uint64(symbolSize) - 1) / uint64(symbolSize)
	if source == 0 {
		source = 1
	}
	// Always add a few symbols beyond the percentage: on a small block a
	// percentage alone rounds down to no repair at all, leaving no tolerance
	// for even one missed frame.
	repair := source*uint64(overheadPct)/100 + 4

	return ffi.SessionParams{
		PayloadSize:           ciphertextLen,
		BlockCount:            uint32(blocks),
		SymbolSize:            uint32(symbolSize),
		SourceSymbolsPerBlock: uint32(source),
		TotalSymbolsPerBlock:  uint32(source + repair),
	}, nil
}

// --- recv ---

type recvResult struct {
	SessionID string `json:"session_id"`
	Frames    int    `json:"frames_accepted"`
	Rejected  int    `json:"frames_rejected"`
	Files     int    `json:"files"`
	OutDir    string `json:"out_dir"`
}

func runRecv(env Env, args []string) error {
	fs := newFlagSet("recv", env)
	keyPath := fs.String("key", "operator.key", "operator key file")
	in := fs.String("in", "frames", "directory holding captured frames")
	outDir := fs.String("out", "received", "directory to extract into")
	asJSON := fs.Bool("json", false, "emit machine-readable output")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}

	record, err := readRecord(filepath.Join(*in, recordName))
	if err != nil {
		return err
	}

	sessionID, salt, nonce, params, err := record.decode()
	if err != nil {
		return err
	}

	key, err := ffi.LoadKey(*keyPath)
	if err != nil {
		return failf(ExitInput, "loading %s: %w", *keyPath, err)
	}
	defer key.Close()

	dec, err := ffi.NewDecoder(key, sessionID, salt, params)
	if err != nil {
		return failf(ExitInput, "starting decoder: %w", err)
	}
	defer dec.Close()

	names, err := filepath.Glob(filepath.Join(*in, "frame-*.bin"))
	if err != nil {
		return failf(ExitInput, "listing frames in %s: %w", *in, err)
	}
	if len(names) == 0 {
		return failf(ExitInput, "no frames found in %s", *in)
	}
	sort.Strings(names)

	accepted, rejected := 0, 0
	for _, name := range names {
		frame, err := os.ReadFile(name)
		if err != nil {
			return failf(ExitInput, "reading %s: %w", name, err)
		}
		// A frame that fails to authenticate is discarded and the receiver
		// keeps going, exactly as it would with a blurred camera capture.
		if err := dec.Accept(frame); err != nil {
			rejected++
			continue
		}
		accepted++
	}

	complete, err := dec.IsComplete()
	if err != nil {
		return failf(ExitInternal, "checking completion: %w", err)
	}
	if !complete {
		return failf(ExitIncomplete,
			"transfer incomplete: %d frames accepted, %d rejected; more frames are needed",
			accepted, rejected)
	}

	payload, err := dec.Finish(key, sessionID, salt, nonce)
	if err != nil {
		if errors.Is(err, ffi.ErrIncomplete) {
			return failf(ExitIncomplete, "transfer incomplete")
		}
		return failf(ExitVerifyFailed, "verifying transfer: %w", err)
	}

	entries, err := pack.Extract(payload, *outDir)
	if err != nil {
		return failf(ExitVerifyFailed, "extracting into %s: %w", *outDir, err)
	}

	return emit(env.Stdout, *asJSON,
		recvResult{
			SessionID: record.SessionID,
			Frames:    accepted,
			Rejected:  rejected,
			Files:     len(entries),
			OutDir:    *outDir,
		},
		fmt.Sprintf("session   %s\naccepted  %d frames\nrejected  %d frames\nfiles     %d\nwritten   %s\n",
			record.SessionID, accepted, rejected, len(entries), *outDir))
}

// --- verify ---

type verifyResult struct {
	OK        bool     `json:"ok"`
	SessionID string   `json:"session_id"`
	Files     int      `json:"files"`
	Problems  []string `json:"problems"`
}

func runVerify(env Env, args []string) error {
	fs := newFlagSet("verify", env)
	in := fs.String("in", "frames", "directory holding the transfer record")
	dir := fs.String("dir", "received", "extracted dataset to check")
	asJSON := fs.Bool("json", false, "emit machine-readable output")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}

	record, err := readRecord(filepath.Join(*in, recordName))
	if err != nil {
		return err
	}

	var problems []string

	info, err := os.Stat(*dir)
	switch {
	case err != nil:
		problems = append(problems, fmt.Sprintf("cannot read %s: %v", *dir, err))
	case !info.IsDir():
		problems = append(problems, fmt.Sprintf("%s is not a directory", *dir))
	default:
		count := 0
		err := filepath.Walk(*dir, func(_ string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.Mode().IsRegular() {
				count++
			}
			return nil
		})
		if err != nil {
			problems = append(problems, fmt.Sprintf("walking %s: %v", *dir, err))
		} else if count != record.Files {
			problems = append(problems,
				fmt.Sprintf("expected %d files, found %d", record.Files, count))
		}
	}

	ok := len(problems) == 0
	human := fmt.Sprintf("session   %s\nfiles     %d\nresult    OK\n", record.SessionID, record.Files)
	if !ok {
		var b strings.Builder
		fmt.Fprintf(&b, "session   %s\nresult    FAILED\n", record.SessionID)
		for _, p := range problems {
			fmt.Fprintf(&b, "  - %s\n", p)
		}
		human = b.String()
	}

	if err := emit(env.Stdout, *asJSON,
		verifyResult{OK: ok, SessionID: record.SessionID, Files: record.Files, Problems: problems},
		human); err != nil {
		return err
	}
	if !ok {
		return &exitError{code: ExitVerifyFailed, err: errors.New("verification failed")}
	}
	return nil
}

// --- version ---

type versionResult struct {
	ABIVersion uint32 `json:"abi_version"`
	Core       string `json:"core_version"`
}

func runVersion(env Env, args []string) error {
	fs := newFlagSet("version", env)
	asJSON := fs.Bool("json", false, "emit machine-readable output")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	return emit(env.Stdout, *asJSON,
		versionResult{ABIVersion: ffi.ABIVersion(), Core: ffi.Version()},
		fmt.Sprintf("dhow core %s (ABI %d)\n", ffi.Version(), ffi.ABIVersion()))
}

// --- transfer record ---

func readRecord(path string) (*transferRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, failf(ExitInput, "reading %s: %w", path, err)
	}
	var r transferRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, failf(ExitInput, "parsing %s: %w", path, err)
	}
	if r.Version != 1 {
		return nil, failf(ExitInput, "%s has unsupported version %d", path, r.Version)
	}
	return &r, nil
}

// decode turns the record's hex fields back into the values the core needs.
func (r *transferRecord) decode() (sid [16]byte, salt [32]byte, nonce [24]byte, params ffi.SessionParams, err error) {
	if err = decodeHexInto(sid[:], r.SessionID, "session_id"); err != nil {
		return
	}
	if err = decodeHexInto(salt[:], r.Salt, "salt"); err != nil {
		return
	}
	if err = decodeHexInto(nonce[:], r.Nonce, "nonce"); err != nil {
		return
	}

	var digest [32]byte
	if err = decodeHexInto(digest[:], r.PayloadDigest, "payload_digest"); err != nil {
		return
	}

	params = ffi.SessionParams{
		PayloadSize:           r.PayloadSize,
		BlockCount:            r.BlockCount,
		SymbolSize:            r.SymbolSize,
		SourceSymbolsPerBlock: r.SourceSymbolsPerBlock,
		TotalSymbolsPerBlock:  r.TotalSymbolsPerBlock,
		PayloadDigest:         digest,
	}
	return
}

// decodeHexInto decodes a hex string of exactly len(dst) bytes.
func decodeHexInto(dst []byte, s, field string) error {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return failf(ExitInput, "%s is not valid hex: %w", field, err)
	}
	if len(raw) != len(dst) {
		return failf(ExitInput, "%s must be %d bytes, got %d", field, len(dst), len(raw))
	}
	copy(dst, raw)
	return nil
}

// renderFrames writes each frame as a QR code PNG beside its binary form.
//
// Rendering is a separate step from framing so a failure here cannot corrupt
// the frame stream that has already been written: the transfer stays valid
// even if the operator's chosen QR version turns out to be too small.
func renderFrames(frames [][]byte, outDir string, version int, ecc byte, scale int) error {
	for i, frame := range frames {
		qr, err := ffi.EncodeQR(frame, version, ecc)
		if err != nil {
			// A frame that does not fit is a configuration error the operator
			// can act on, so name the size rather than just failing.
			return failf(ExitUsage,
				"frame %d (%d bytes) will not fit a QR code at version %d level %c: %w",
				i, len(frame), version, ecc, err)
		}

		name := filepath.Join(outDir, fmt.Sprintf("frame-%06d.png", i))
		f, err := os.Create(name)
		if err != nil {
			return failf(ExitInput, "creating %s: %w", name, err)
		}
		if err := render.PNG(f, qr, scale); err != nil {
			_ = f.Close()
			return failf(ExitInternal, "rendering %s: %w", name, err)
		}
		if err := f.Close(); err != nil {
			return failf(ExitInput, "closing %s: %w", name, err)
		}
	}
	return nil
}

// --- display ---

type displayResult struct {
	SessionID   string `json:"session_id"`
	Fingerprint string `json:"fingerprint"`
	Frames      int    `json:"frames_shown"`
	Loops       int    `json:"loops_completed"`
	Seconds     int    `json:"seconds"`
}

func runDisplay(env Env, args []string) error {
	fs := newFlagSet("display", env)
	in := fs.String("in", "frames", "directory holding the frames to show")
	fps := fs.Uint("fps", display.DefaultFPS, "frames per second")
	loops := fs.Uint("loops", 0, "passes through the stream, or 0 to loop until stopped")
	calibration := fs.Uint("calibration", 3, "seconds to hold the calibration pattern")
	qrVersion := fs.Uint("qr-version", 0, "QR version 1..40, or 0 to fit each frame")
	qrEcc := fs.String("qr-ecc", "M", "QR error correction: L, M, Q, or H")
	noClear := fs.Bool("no-clear", false, "do not clear the terminal between frames")
	asJSON := fs.Bool("json", false, "emit machine-readable output")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	if len(*qrEcc) != 1 {
		return failf(ExitUsage, "-qr-ecc must be a single letter L, M, Q, or H")
	}

	record, err := readRecord(filepath.Join(*in, recordName))
	if err != nil {
		return err
	}
	sessionID, _, _, _, err := record.decode()
	if err != nil {
		return err
	}

	names, err := filepath.Glob(filepath.Join(*in, "frame-*.bin"))
	if err != nil {
		return failf(ExitInput, "listing frames in %s: %w", *in, err)
	}
	if len(names) == 0 {
		return failf(ExitInput, "no frames found in %s", *in)
	}
	sort.Strings(names)

	frames := make([][]byte, 0, len(names))
	for _, name := range names {
		frame, err := os.ReadFile(name)
		if err != nil {
			return failf(ExitInput, "reading %s: %w", name, err)
		}
		frames = append(frames, frame)
	}

	cfg := display.Config{
		FPS:                int(*fps),
		Loops:              int(*loops),
		CalibrationSeconds: int(*calibration),
		SessionID:          sessionID,
		ClearScreen:        !*noClear,
	}
	if err := cfg.Validate(); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}

	// Ctrl-C ends a transfer normally: the sender cannot know when the
	// receiver has enough, so the operator decides.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stats, err := display.Run(ctx, env.Stdout, frames, cfg, int(*qrVersion), (*qrEcc)[0])
	if err != nil {
		return failf(ExitInput, "displaying frames: %w", err)
	}

	return emit(env.Stderr, *asJSON,
		displayResult{
			SessionID:   record.SessionID,
			Fingerprint: display.Fingerprint(sessionID),
			Frames:      stats.FramesShown,
			Loops:       stats.LoopsCompleted,
			Seconds:     int(stats.Elapsed.Seconds()),
		},
		fmt.Sprintf("\nsession     %s\nfingerprint %s\nshown       %d frames over %d passes in %ds\n",
			record.SessionID, display.Fingerprint(sessionID),
			stats.FramesShown, stats.LoopsCompleted, int(stats.Elapsed.Seconds())))
}
