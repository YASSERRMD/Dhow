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
//
// # Resuming
//
// recv -state <dir> keeps progress on disk so an interrupted capture is
// continued rather than repeated. It is opt-in: without the flag, recv writes
// nothing outside -out. See docs/RESUME.md.
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
	"dhow/cli/internal/resume"
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

Common flags:
  -json      machine-readable output on stdout
  -quiet     print nothing but errors
  -verbose   print progress and detail while working

Exit codes (stable; a script may branch on these):
  0  success
  1  usage: a flag or argument was wrong
  2  input: a file was missing, unreadable, or malformed
  3  verification failed: a digest, MAC, or signature did not match
  4  incomplete: not enough frames arrived; show the stream again
  5  internal: a bug in dhow

Only 4 is worth retrying unchanged. 2 and 3 mean something on disk is wrong,
and repeating the command will reproduce them.
`)
}

// newFlagSet builds a flag set that reports errors through our own channel
// rather than calling os.Exit, so Run stays testable.
func newFlagSet(name string, env Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs
}

// verbosity controls how much a command says while it works.
//
// It governs commentary only. Results still go to stdout and errors still go
// to stderr at every level, because a script that pipes one and reads the
// other must not have its data silenced by a display preference. -quiet
// suppresses the summary a person reads; it never suppresses a failure.
type verbosity int

const (
	// quiet prints nothing but errors. An exit code is the whole report.
	quiet verbosity = iota - 1
	// normal prints the end-of-command summary.
	normal
	// loud adds progress and detail while the command runs.
	loud
)

// verbosityFlags registers -quiet and -verbose on a flag set.
//
// Returns a function that resolves them after parsing, because the two can be
// given together and something has to decide what that means.
func verbosityFlags(fs *flag.FlagSet) func() (verbosity, error) {
	q := fs.Bool("quiet", false, "print nothing but errors")
	v := fs.Bool("verbose", false, "print progress and detail while working")
	return func() (verbosity, error) {
		switch {
		case *q && *v:
			// Guessing which one the operator meant would make the tool
			// unpredictable in exactly the situation where they are already
			// unsure what it is doing.
			return normal, errors.New("-quiet and -verbose contradict each other; pass at most one")
		case *q:
			return quiet, nil
		case *v:
			return loud, nil
		default:
			return normal, nil
		}
	}
}

// say writes commentary at or above the given level.
//
// Commentary goes to stderr so stdout carries only results, which is what lets
// `dhow send -json | jq` work while a person still sees what happened.
func (v verbosity) say(w io.Writer, level verbosity, format string, args ...any) {
	if v < level {
		return
	}
	// Commentary that cannot be written is not worth failing a transfer over.
	_, _ = fmt.Fprintf(w, format, args...)
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
	resolve := verbosityFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	level, err := resolve()
	if err != nil {
		return &exitError{code: ExitUsage, err: err}
	}

	// Refuse to clobber a key by default. Overwriting one silently would
	// destroy the only copy of a secret that cannot be regenerated.
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			return failf(ExitInput, "%s already exists; pass -force to overwrite", *out)
		}
	}

	level.say(env.Stderr, loud, "drawing a key from the system CSPRNG\n")

	key, err := ffi.GenerateKey()
	if err != nil {
		return failf(ExitInternal, "generating key: %w", err)
	}
	defer key.Close()

	if err := key.Save(*out); err != nil {
		return failf(ExitInput, "writing %s: %w", *out, err)
	}

	if level == quiet && !*asJSON {
		return nil
	}
	return emit(env.Stdout, *asJSON,
		keygenResult{Path: *out, Mode: "0600"},
		fmt.Sprintf("wrote operator key to %s (mode 0600)\n"+
			"keep this file secret; both operators need the same key\n", *out))
}

// loadKey opens the operator key, turning the core's diagnosis into an
// instruction.
//
// The two ways this fails in practice are a path that is wrong and a file
// whose permissions are wrong, and the fix for each is a single command. An
// operator reading "invalid key data: cannot stat key file" has been told what
// happened and not what to do about it, which is the difference between an
// error message and a useful one.
func loadKey(path string) (*ffi.Key, error) {
	key, err := ffi.LoadKey(path)
	if err == nil {
		return key, nil
	}

	if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
		return nil, failf(ExitInput,
			"no operator key at %s; generate one with \"dhow keygen -out %s\", "+
				"or pass -key with the path to the key both operators share",
			path, path)
	}

	if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm()&0o077 != 0 {
		return nil, failf(ExitInput,
			"%s is readable by other users (mode %04o); dhow refuses to load a key "+
				"anyone else can read. Fix it with \"chmod 600 %s\", and consider the "+
				"key compromised if the machine is shared",
			path, info.Mode().Perm(), path)
	}

	return nil, failf(ExitInput, "loading %s: %w", path, err)
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
	Version               int          `json:"version"`
	SessionID             string       `json:"session_id"`
	Salt                  string       `json:"salt"`
	Nonce                 string       `json:"nonce"`
	PayloadSize           uint64       `json:"payload_size"`
	BlockCount            uint32       `json:"block_count"`
	SymbolSize            uint32       `json:"symbol_size"`
	SourceSymbolsPerBlock uint32       `json:"source_symbols_per_block"`
	TotalSymbolsPerBlock  uint32       `json:"total_symbols_per_block"`
	PayloadDigest         string       `json:"payload_digest"`
	Files                 []fileRecord `json:"files"`
}

// fileRecord is one file's entry in the transfer record's inventory.
//
// The inventory is what makes `dhow verify` mean something. Without it the
// command can only count files, so a dataset of the right shape and entirely
// wrong contents passes. With it, verify can be run months later against a
// dataset sitting on disk and say exactly which file changed.
type fileRecord struct {
	// Name is the file's path within the dataset, slash-separated.
	Name string `json:"name"`
	// Size is its length in bytes.
	Size int64 `json:"size"`
	// Executable records whether the owner execute bit was set.
	Executable bool `json:"executable"`
	// Digest is the BLAKE3 digest of the contents, hex-encoded.
	Digest string `json:"digest"`
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
	resolve := verbosityFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	level, err := resolve()
	if err != nil {
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

	level.say(env.Stderr, loud, "packing %s\n", *in)

	var archive strings.Builder
	entries, err := pack.Create(&archive, *in)
	if err != nil {
		return failf(ExitInput, "packing %s: %w", *in, err)
	}
	payload := []byte(archive.String())

	key, err := loadKey(*keyPath)
	if err != nil {
		return err
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

	level.say(env.Stderr, loud, "packed %d files into %d bytes; encoding\n",
		len(entries), archive.Len())

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

	level.say(env.Stderr, loud, "wrote %d frames to %s\n", len(frames), *outDir)

	if *emitQR {
		if len(*qrEcc) != 1 {
			return failf(ExitUsage, "-qr-ecc must be a single letter L, M, Q, or H")
		}
		if err := renderFrames(frames, *outDir, int(*qrVersion), (*qrEcc)[0], int(*qrScale)); err != nil {
			return err
		}
	}

	inventory := make([]fileRecord, 0, len(entries))
	for _, e := range entries {
		inventory = append(inventory, fileRecord{
			Name:       e.Name,
			Size:       e.Size,
			Executable: e.Executable,
			Digest:     hex.EncodeToString(e.Digest[:]),
		})
	}

	record := transferRecord{
		Version:               2,
		SessionID:             hex.EncodeToString(sessionID[:]),
		Salt:                  hex.EncodeToString(salt[:]),
		Nonce:                 hex.EncodeToString(nonce[:]),
		PayloadSize:           resolved.PayloadSize,
		BlockCount:            resolved.BlockCount,
		SymbolSize:            resolved.SymbolSize,
		SourceSymbolsPerBlock: resolved.SourceSymbolsPerBlock,
		TotalSymbolsPerBlock:  resolved.TotalSymbolsPerBlock,
		PayloadDigest:         hex.EncodeToString(resolved.PayloadDigest[:]),
		Files:                 inventory,
	}
	recordBytes, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return failf(ExitInternal, "encoding transfer record: %w", err)
	}
	recordPath := filepath.Join(*outDir, recordName)
	if err := os.WriteFile(recordPath, append(recordBytes, '\n'), 0o644); err != nil {
		return failf(ExitInput, "writing %s: %w", recordPath, err)
	}

	if level == quiet && !*asJSON {
		return nil
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
	Resumed   int    `json:"frames_resumed"`
	Files     int    `json:"files"`
	OutDir    string `json:"out_dir"`
	StateDir  string `json:"state_dir,omitempty"`
}

func runRecv(env Env, args []string) error {
	fs := newFlagSet("recv", env)
	keyPath := fs.String("key", "operator.key", "operator key file")
	in := fs.String("in", "frames", "directory holding captured frames")
	outDir := fs.String("out", "received", "directory to extract into")
	stateDir := fs.String("state", "", "directory to keep resumable progress in")
	saveEvery := fs.Uint("save-every", 200, "accepted frames between saves of the resume state")
	stopAfter := fs.Uint("stop-after", 0, "stop after accepting this many frames, or 0 for no limit")
	keepState := fs.Bool("keep-state", false, "keep the resume state after the transfer completes")
	asJSON := fs.Bool("json", false, "emit machine-readable output")
	resolve := verbosityFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	level, err := resolve()
	if err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	if *saveEvery == 0 {
		return failf(ExitUsage, "-save-every must be at least 1")
	}

	record, err := readRecord(filepath.Join(*in, recordName))
	if err != nil {
		return err
	}

	sessionID, salt, nonce, params, err := record.decode()
	if err != nil {
		return err
	}

	key, err := loadKey(*keyPath)
	if err != nil {
		return err
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

	// Restore whatever a previous run got through, if the operator asked for
	// resumable progress and there is any.
	store, resumed, err := restoreProgress(env, level, *stateDir, sessionID, dec)
	if err != nil {
		return err
	}
	if store != nil {
		defer func() { _ = store.Close() }()
	}

	// A stop is an ordinary end to a receiving session: the operator decides
	// when to walk away, and what was captured must survive that decision.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// How many consecutive rejections with nothing accepted before saying so.
	// Low enough to be noticed early, high enough not to fire on the ordinary
	// run of unreadable frames at the start of a capture.
	const captureNoiseWarning = 50

	accepted, rejected := 0, 0
	blocksDone := -1
	stopped := false

	level.say(env.Stderr, loud, "decoding %d blocks from %d captured frames\n",
		params.BlockCount, len(names))

	for _, name := range names {
		if ctx.Err() != nil {
			stopped = true
			break
		}
		if *stopAfter > 0 && uint(accepted) >= *stopAfter {
			stopped = true
			break
		}
		if len(names) > 0 && level >= loud && accepted == 0 && rejected == captureNoiseWarning {
			// Frames are arriving and none of them authenticate. That is the
			// wrong key, not a bad camera angle, and an operator who does not
			// hear it now will wait out the whole stream to learn it.
			level.say(env.Stderr, loud,
				"warning: %d frames read and none accepted; this is what a wrong key looks like\n",
				rejected)
		}

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

		// Progress is reported by block rather than by frame. Frames arrive in
		// their thousands and most of them change nothing an operator can act
		// on; a block completing is the unit of real progress, and it is what
		// tells them whether pointing the camera differently is helping.
		if level >= loud {
			done, err := dec.BlocksComplete()
			if err != nil {
				return failf(ExitInternal, "reading progress: %w", err)
			}
			if done != blocksDone {
				blocksDone = done
				level.say(env.Stderr, loud, "%d of %d blocks decoded (%d frames accepted, %d rejected)\n",
					done, params.BlockCount, resumed+accepted, rejected)
			}
		}

		// Journal first, then the index. The other order would produce an
		// index describing a frame the journal does not hold, which is the one
		// inconsistency a replay cannot recover from.
		if store != nil {
			if err := store.Append(frame); err != nil {
				return failf(ExitInput, "recording progress: %w", err)
			}
			if uint(accepted)%*saveEvery == 0 {
				if err := saveProgress(store, dec); err != nil {
					return err
				}
			}
		}
	}

	if store != nil {
		if err := saveProgress(store, dec); err != nil {
			return err
		}
	}

	complete, err := dec.IsComplete()
	if err != nil {
		return failf(ExitInternal, "checking completion: %w", err)
	}
	if !complete {
		detail := "more frames are needed"
		if stopped {
			detail = "stopped before the end of the stream"
		}
		if store != nil {
			detail += fmt.Sprintf("; progress saved in %s, rerun with -state %s to continue",
				store.Dir(), store.Dir())
		}
		return failf(ExitIncomplete,
			"transfer incomplete: %d frames accepted, %d rejected; %s",
			resumed+accepted, rejected, detail)
	}

	payload, err := dec.Finish(key, sessionID, salt, nonce)
	if err != nil {
		if errors.Is(err, ffi.ErrIncomplete) {
			return failf(ExitIncomplete, "transfer incomplete")
		}
		return failf(ExitVerifyFailed, "verifying transfer: %w", err)
	}

	entries, err := extractAtomically(payload, *outDir)
	if err != nil {
		return err
	}

	// The state has done its job. Leaving it behind would be picked up by the
	// next transfer pointed at the same directory and rejected as a foreign
	// session, which is a confusing way to learn that a stale file exists.
	if store != nil && !*keepState {
		if err := store.Discard(); err != nil {
			return failf(ExitInput, "clearing resume state: %w", err)
		}
	}

	if level == quiet && !*asJSON {
		return nil
	}

	human := fmt.Sprintf("session   %s\naccepted  %d frames\nrejected  %d frames\nfiles     %d\nwritten   %s\n",
		record.SessionID, accepted, rejected, len(entries), *outDir)
	if resumed > 0 {
		human = fmt.Sprintf("session   %s\nresumed   %d frames\naccepted  %d frames\nrejected  %d frames\nfiles     %d\nwritten   %s\n",
			record.SessionID, resumed, accepted, rejected, len(entries), *outDir)
	}

	stateShown := ""
	if store != nil {
		stateShown = store.Dir()
	}
	return emit(env.Stdout, *asJSON,
		recvResult{
			SessionID: record.SessionID,
			Frames:    accepted,
			Rejected:  rejected,
			Resumed:   resumed,
			Files:     len(entries),
			OutDir:    *outDir,
			StateDir:  stateShown,
		},
		human)
}

// extractAtomically unpacks a payload so the output directory either holds the
// whole dataset or does not exist.
//
// Extraction can fail partway - a name the archive should not have contained,
// a disk filling, a permission the destination does not grant - and writing
// directly into the destination would leave a partial dataset behind. The
// transfer reports failure either way, but an operator who reruns a script and
// sees a populated directory has been handed something that looks like output
// and is not.
//
// So it unpacks into a sibling and renames. A sibling rather than the system
// temporary directory because a rename across filesystems is a copy, and the
// point is that the last step is atomic.
func extractAtomically(payload []byte, outDir string) ([]pack.Entry, error) {
	if _, err := os.Stat(outDir); err == nil {
		return nil, failf(ExitInput,
			"%s already exists; extract into a directory that does not, "+
				"so a partial or stale dataset cannot be mistaken for this one", outDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, failf(ExitInput, "checking %s: %w", outDir, err)
	}

	parent := filepath.Dir(outDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, failf(ExitInput, "creating %s: %w", parent, err)
	}

	staging, err := os.MkdirTemp(parent, "."+filepath.Base(outDir)+".partial-")
	if err != nil {
		return nil, failf(ExitInput, "creating a staging directory in %s: %w", parent, err)
	}

	entries, err := pack.Extract(payload, staging)
	if err != nil {
		// The staging directory holds whatever was written before the failure,
		// and none of it is wanted. Its removal is best effort: reporting a
		// cleanup error would replace the diagnosis that matters.
		_ = os.RemoveAll(staging)
		return nil, failf(ExitVerifyFailed, "extracting into %s: %w", outDir, err)
	}

	if err := os.Rename(staging, outDir); err != nil {
		_ = os.RemoveAll(staging)
		return nil, failf(ExitInput, "moving the extracted dataset into %s: %w", outDir, err)
	}

	return entries, nil
}

// restoreProgress opens the state directory and replays whatever it holds.
//
// Returns the store, the number of frames replayed, and an error. A nil store
// means the operator did not ask for resumable progress, which is not a
// failure: it is the default.
//
// Every failure here is fail-closed. A state that cannot be trusted is never
// partially applied, because a decoder holding some of a previous run's frames
// and no record of which ones is worse than one holding none.
func restoreProgress(env Env, level verbosity, dir string, sessionID [16]byte, dec *ffi.Decoder) (*resume.Store, int, error) {
	if dir == "" {
		return nil, 0, nil
	}

	store, err := resume.Open(dir)
	if err != nil {
		return nil, 0, failf(ExitInput, "opening state directory: %w", err)
	}

	state, err := store.State()
	if errors.Is(err, resume.ErrNoState) {
		// First run against this directory.
		if err := store.Begin(0); err != nil {
			return nil, 0, failf(ExitInput, "preparing the journal: %w", err)
		}
		return store, 0, nil
	}
	if err != nil {
		return nil, 0, failf(ExitInput, "reading saved state: %w", err)
	}

	info, err := ffi.ReadResumeState(state)
	if err != nil {
		return nil, 0, failf(ExitInput,
			"saved state in %s is unusable (%v); delete it to start this transfer over", dir, err)
	}
	if info.SessionID != sessionID {
		return nil, 0, failf(ExitInput,
			"saved state in %s belongs to session %s, not %s; point -state at the right directory",
			dir, hex.EncodeToString(info.SessionID[:]), hex.EncodeToString(sessionID[:]))
	}

	replayed, err := store.Replay(info.JournalBytes, dec.Accept)
	if err != nil {
		return nil, 0, failf(ExitInput,
			"replaying saved progress from %s: %w; delete the directory to start this transfer over",
			dir, err)
	}

	// The replay is checked against what the state said it would produce.
	// Every replayed frame was authenticated on the way in, so this is not
	// what keeps forged symbols out; it is what stops a stale or swapped pair
	// of files from passing as progress that was really made.
	if err := dec.VerifyResume(state); err != nil {
		return nil, 0, failf(ExitInput,
			"saved progress in %s does not match its journal (%v); delete the directory to start this transfer over",
			dir, err)
	}

	if err := store.Begin(info.JournalBytes); err != nil {
		return nil, 0, failf(ExitInput, "preparing the journal: %w", err)
	}

	// Reported at normal level, not verbose: an operator who does not realise
	// a run resumed will misread every count that follows it.
	level.say(env.Stderr, normal, "resumed %d frames from %s\n", replayed, dir)
	return store, replayed, nil
}

// saveProgress writes the decoder's progress alongside the journal it covers.
func saveProgress(store *resume.Store, dec *ffi.Decoder) error {
	// The length is read after the last append and handed to the decoder in
	// the same breath, so the state describes exactly the journal on disk.
	state, err := dec.ResumeState(store.Written())
	if err != nil {
		return failf(ExitInternal, "building resume state: %w", err)
	}
	if err := store.Save(state); err != nil {
		return failf(ExitInput, "saving resume state: %w", err)
	}
	return nil
}

// --- verify ---

// Problem is one discrepancy between a dataset and what was sent.
type Problem struct {
	// File is the dataset-relative name the problem concerns, empty when the
	// problem is about the dataset as a whole.
	File string `json:"file,omitempty"`
	// Kind classifies the problem, so a script can branch without parsing
	// English.
	Kind string `json:"kind"`
	// Detail describes it for a person.
	Detail string `json:"detail"`
}

// Problem kinds. These are part of the JSON interface and are stable.
const (
	ProblemUnreadable = "unreadable"
	ProblemMissing    = "missing"
	ProblemUnexpected = "unexpected"
	ProblemSize       = "size"
	ProblemContent    = "content"
	ProblemMode       = "mode"
)

type verifyResult struct {
	OK        bool      `json:"ok"`
	SessionID string    `json:"session_id"`
	Files     int       `json:"files"`
	Checked   int       `json:"files_checked"`
	Bytes     int64     `json:"bytes_checked"`
	Problems  []Problem `json:"problems"`
}

func runVerify(env Env, args []string) error {
	fs := newFlagSet("verify", env)
	in := fs.String("in", "frames", "directory holding the transfer record")
	dir := fs.String("dir", "received", "extracted dataset to check")
	asJSON := fs.Bool("json", false, "emit machine-readable output")
	resolve := verbosityFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	level, err := resolve()
	if err != nil {
		return &exitError{code: ExitUsage, err: err}
	}

	record, err := readRecord(filepath.Join(*in, recordName))
	if err != nil {
		return err
	}

	level.say(env.Stderr, loud, "checking %d files in %s against the transfer record\n",
		len(record.Files), *dir)

	problems, checked, bytes := inspectDataset(*dir, record.Files)
	ok := len(problems) == 0

	var b strings.Builder
	if ok {
		fmt.Fprintf(&b, "session   %s\nfiles     %d\nbytes     %d\nresult    OK\n",
			record.SessionID, checked, bytes)
	} else {
		fmt.Fprintf(&b, "session   %s\nfiles     %d checked of %d\nresult    FAILED\n",
			record.SessionID, checked, len(record.Files))
		for _, p := range problems {
			if p.File == "" {
				fmt.Fprintf(&b, "  - %s\n", p.Detail)
				continue
			}
			fmt.Fprintf(&b, "  - %s: %s\n", p.File, p.Detail)
		}
	}

	// A failure is always reported, at every level. -quiet suppresses the
	// summary a person reads, never the fact that verification failed.
	if level == quiet && !*asJSON && ok {
		return nil
	}
	if err := emit(env.Stdout, *asJSON,
		verifyResult{
			OK:        ok,
			SessionID: record.SessionID,
			Files:     len(record.Files),
			Checked:   checked,
			Bytes:     bytes,
			Problems:  problems,
		},
		b.String()); err != nil {
		return err
	}
	if !ok {
		return &exitError{code: ExitVerifyFailed, err: errors.New("verification failed")}
	}
	return nil
}

// inspectDataset compares a directory against the inventory that was sent.
//
// Returns every discrepancy, the number of files it managed to check, and the
// number of bytes it read. It does not stop at the first problem: an operator
// looking at a dataset that came back wrong needs the whole picture, not the
// alphabetically first part of it.
func inspectDataset(dir string, want []fileRecord) (problems []Problem, checked int, bytesRead int64) {
	info, err := os.Stat(dir)
	switch {
	case err != nil:
		return []Problem{{Kind: ProblemUnreadable, Detail: fmt.Sprintf("cannot read %s: %v", dir, err)}}, 0, 0
	case !info.IsDir():
		return []Problem{{Kind: ProblemUnreadable, Detail: fmt.Sprintf("%s is not a directory", dir)}}, 0, 0
	}

	found, err := walkDataset(dir)
	if err != nil {
		return []Problem{{Kind: ProblemUnreadable, Detail: fmt.Sprintf("walking %s: %v", dir, err)}}, 0, 0
	}

	expected := make(map[string]struct{}, len(want))

	for _, entry := range want {
		expected[entry.Name] = struct{}{}

		fi, present := found[entry.Name]
		if !present {
			problems = append(problems, Problem{
				File:   entry.Name,
				Kind:   ProblemMissing,
				Detail: "missing from the dataset",
			})
			continue
		}

		// Size is checked before the contents so a truncated file is reported
		// as truncated rather than as a digest mismatch, which says nothing
		// about what went wrong.
		if fi.Size() != entry.Size {
			problems = append(problems, Problem{
				File:   entry.Name,
				Kind:   ProblemSize,
				Detail: fmt.Sprintf("is %d bytes, expected %d", fi.Size(), entry.Size),
			})
			continue
		}

		if executable(fi) != entry.Executable {
			problems = append(problems, Problem{
				File:   entry.Name,
				Kind:   ProblemMode,
				Detail: modeDetail(entry.Executable),
			})
			// Not a `continue`: the mode is wrong but the contents may still
			// be worth checking, and reporting one problem per file would hide
			// the more serious of the two.
		}

		digest, err := digestFile(filepath.Join(dir, filepath.FromSlash(entry.Name)))
		if err != nil {
			problems = append(problems, Problem{
				File:   entry.Name,
				Kind:   ProblemUnreadable,
				Detail: err.Error(),
			})
			continue
		}
		checked++
		bytesRead += entry.Size

		if digest != entry.Digest {
			problems = append(problems, Problem{
				File: entry.Name,
				Kind: ProblemContent,
				Detail: fmt.Sprintf("contents differ: digest %s, expected %s",
					shortDigest(digest), shortDigest(entry.Digest)),
			})
		}
	}

	// A file nobody sent is as much a problem as one that went missing: it
	// means the directory is not the dataset that was transferred.
	extra := make([]string, 0)
	for name := range found {
		if _, ok := expected[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		problems = append(problems, Problem{
			File:   name,
			Kind:   ProblemUnexpected,
			Detail: "is not part of the transfer",
		})
	}

	return problems, checked, bytesRead
}

// walkDataset indexes the regular files under dir by dataset-relative name.
func walkDataset(dir string) (map[string]os.FileInfo, error) {
	found := make(map[string]os.FileInfo)
	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		found[filepath.ToSlash(rel)] = fi
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// digestFile returns the hex BLAKE3 digest of a file's contents.
//
// Streamed rather than read whole: verify runs against datasets that were
// worth moving across an air gap, and a file too big to fit in memory is not
// an unreasonable thing to find in one.
func digestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot read: %w", err)
	}
	// Read-only: a failing Close reports nothing the read did not already.
	defer func() { _ = f.Close() }()

	hasher, err := ffi.NewHasher()
	if err != nil {
		return "", fmt.Errorf("preparing a digest: %w", err)
	}
	defer hasher.Close()

	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("cannot read: %w", err)
	}
	sum, err := hasher.Sum()
	if err != nil {
		return "", fmt.Errorf("computing the digest: %w", err)
	}
	return hex.EncodeToString(sum[:]), nil
}

// executable reports whether the owner execute bit is set.
func executable(fi os.FileInfo) bool {
	return fi.Mode().Perm()&0o100 != 0
}

func modeDetail(wantExecutable bool) string {
	if wantExecutable {
		return "is not executable but was sent executable"
	}
	return "is executable but was not sent executable"
}

// shortDigest trims a digest for display.
//
// The full 64 hex characters twice on one line pushes the part that differs
// off the edge of a terminal, which is the opposite of helpful. The first
// eight are enough to tell two apart.
func shortDigest(d string) string {
	if len(d) <= 8 {
		return d
	}
	return d[:8]
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
	if r.Version != 2 {
		return nil, failf(ExitInput,
			"%s has unsupported version %d; this build writes and reads version 2",
			path, r.Version)
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
	resolve := verbosityFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	level, err := resolve()
	if err != nil {
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

	if level == quiet && !*asJSON {
		return nil
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
