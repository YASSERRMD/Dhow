package cli

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // registered so detect can read a camera still
	"image/png"
	"os"
	"path/filepath"
	"strings"

	"dhow/cli/internal/capture"
	"dhow/cli/internal/optical"
)

// Where a receiver gets its frames from.
//
// Until Phase 37 there was one answer - binary frames in a directory - and it
// was the only one because there was no camera path. There now are four, and
// they differ only in where the images come from; everything after that is the
// same pipeline.

// captureSourceUsage is the -source flag's help text, kept here so the flag and
// the parser cannot drift apart.
const captureSourceUsage = `where frames come from:
    frames        binary frames written by "dhow send", in -in (the default)
    images[:DIR]  image files of QR codes, in DIR or -in
    pipe          a stream of Netpbm images on standard input
    cmd:COMMAND   a capture program dhow starts, writing Netpbm to its output`

// openCaptureSource resolves a -source specification.
//
// The second return says whether the source produces images whether or not
// anybody is reading: a camera does, a directory does not, and the difference
// decides whether falling behind means dropping or just taking longer.
func openCaptureSource(ctx context.Context, env Env, spec, inDir string) (capture.Source, bool, error) {
	kind, argument, _ := strings.Cut(spec, ":")

	switch kind {
	case "images":
		dir := argument
		if dir == "" {
			dir = inDir
		}
		src, err := capture.OpenDir(dir)
		if err != nil {
			return nil, false, failf(ExitInput, "%w", err)
		}
		return src, false, nil

	case "pipe":
		if env.Stdin == nil {
			return nil, false, failf(ExitUsage, "-source pipe has no standard input to read")
		}
		return capture.OpenStream(env.Stdin, nil), true, nil

	case "cmd":
		argv, err := splitCommand(argument)
		if err != nil {
			return nil, false, failf(ExitUsage, "-source cmd: %w", err)
		}
		src, err := capture.StartCommand(ctx, argv)
		if err != nil {
			return nil, false, failf(ExitInput, "%w", err)
		}
		return src, true, nil

	default:
		return nil, false, failf(ExitUsage,
			"unknown -source %q; expected frames, images, pipe, or cmd", spec)
	}
}

// splitCommand splits a capture command into arguments.
//
// Quoting is handled because a capture command frequently contains one - a
// device name with a space in it is the normal case on macOS - and the
// alternative is an operator discovering that dhow split their device name in
// half. It is deliberately not a shell: no expansion, no substitution, no
// pipelines. A capture source is a program dhow starts, and running it through
// a shell would turn a flag into a way to run arbitrary commands on the
// receiver, which is the machine in the deployment that is trusted most.
func splitCommand(line string) ([]string, error) {
	var argv []string
	var current strings.Builder
	var quote rune
	started := false

	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			started = true
		case r == ' ' || r == '\t':
			if started {
				argv = append(argv, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteRune(r)
			started = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if started {
		argv = append(argv, current.String())
	}
	if len(argv) == 0 {
		return nil, errors.New("no command given")
	}
	return argv, nil
}

// --- detect ---

// detectResult is what `dhow detect` reports about one image.
type detectResult struct {
	File    string `json:"file"`
	Read    bool   `json:"read"`
	Version int    `json:"qr_version,omitempty"`
	Level   string `json:"qr_ecc,omitempty"`
	Mask    int    `json:"qr_mask,omitempty"`
	Bytes   int    `json:"bytes,omitempty"`
	Frame   bool   `json:"is_dhow_frame"`
	Session string `json:"session_id,omitempty"`
	Block   uint32 `json:"block,omitempty"`
	Symbol  uint32 `json:"symbol,omitempty"`
	Problem string `json:"problem,omitempty"`
}

// runDetect reads one image at a time and says what it found, which is the
// only way an operator can tell a camera problem from a key problem.
//
// `recv` reports counts: so many images, so many unreadable. That is the right
// summary for a running transfer and useless for diagnosis, because it cannot
// say whether the symbol was not found, was found and would not decode, or
// decoded to a frame of a different session. This says which, for one picture,
// and can write out what the binarizer saw - a threshold that has eaten a
// corner of the symbol is obvious at a glance and invisible in any count.
func runDetect(env Env, args []string) error {
	fs := newFlagSet("detect", env)
	binarized := fs.String("binarized", "", "directory to write the binarized image to, for inspection")
	asJSON := fs.Bool("json", false, "emit machine-readable output")
	resolve := verbosityFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	level, err := resolve()
	if err != nil {
		return &exitError{code: ExitUsage, err: err}
	}

	names := fs.Args()
	if len(names) == 0 {
		return failf(ExitUsage, "detect needs at least one image file")
	}
	if *binarized != "" {
		if err := os.MkdirAll(*binarized, 0o755); err != nil {
			return failf(ExitInput, "creating %s: %w", *binarized, err)
		}
	}

	results := make([]detectResult, 0, len(names))
	readCount := 0

	for _, name := range names {
		result := detectResult{File: name}

		img, err := readImageFile(name)
		if err != nil {
			result.Problem = err.Error()
			results = append(results, result)
			continue
		}

		bitmap := optical.Binarize(img)
		if *binarized != "" {
			out := filepath.Join(*binarized, filepath.Base(name)+".binarized.png")
			if err := writePNG(out, bitmap.ToImage()); err != nil {
				return err
			}
			level.say(env.Stderr, loud, "wrote %s\n", out)
		}

		decoded, err := optical.ReadBitmap(bitmap)
		if err != nil {
			result.Problem = err.Error()
			results = append(results, result)
			continue
		}
		readCount++
		result.Read = true
		result.Version = decoded.Version
		result.Level = decoded.Level.String()
		result.Mask = decoded.Mask
		result.Bytes = len(decoded.Data)

		// Reported without a session to compare against, because `detect` is
		// what an operator reaches for when they do not yet know which session
		// they are looking at. `recv` is where a frame is held to one.
		if block, symbol, ok := capture.Position(decoded.Data); ok &&
			len(decoded.Data) >= capture.HeaderSize &&
			string(decoded.Data[:4]) == "DHOW" {
			result.Frame = true
			result.Session = hex.EncodeToString(decoded.Data[8:24])
			result.Block = block
			result.Symbol = symbol
		}
		results = append(results, result)
	}

	if level == quiet && !*asJSON {
		if readCount == len(names) {
			return nil
		}
		return failf(ExitInput, "%d of %d images held no readable symbol", len(names)-readCount, len(names))
	}

	var human strings.Builder
	for _, r := range results {
		switch {
		case !r.Read:
			fmt.Fprintf(&human, "%s: no symbol read (%s)\n", r.File, r.Problem)
		case r.Frame:
			fmt.Fprintf(&human, "%s: QR v%d %s mask %d, %d bytes, dhow frame %d/%d of session %s\n",
				r.File, r.Version, r.Level, r.Mask, r.Bytes, r.Block, r.Symbol, r.Session[:16])
		default:
			fmt.Fprintf(&human, "%s: QR v%d %s mask %d, %d bytes, not a dhow frame\n",
				r.File, r.Version, r.Level, r.Mask, r.Bytes)
		}
	}

	if err := emit(env.Stdout, *asJSON, results, human.String()); err != nil {
		return err
	}
	if readCount < len(names) {
		return failf(ExitInput, "%d of %d images held no readable symbol", len(names)-readCount, len(names))
	}
	return nil
}

// readImageFile decodes one image from disk.
func readImageFile(name string) (image.Image, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()

	img, _, err := image.Decode(bufio.NewReader(f))
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", name, err)
	}
	return img, nil
}

// writePNG writes an image, used only for the binarizer's diagnostic output.
func writePNG(name string, img image.Image) error {
	f, err := os.Create(name)
	if err != nil {
		return failf(ExitInput, "creating %s: %w", name, err)
	}
	if err := png.Encode(f, img); err != nil {
		_ = f.Close()
		return failf(ExitInternal, "writing %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return failf(ExitInput, "closing %s: %w", name, err)
	}
	return nil
}

// captureSummary renders capture statistics for an operator.
//
// Every image is in exactly one bucket and the buckets are printed in the
// order an operator diagnoses them: nothing found means aim and focus, foreign
// means the wrong session or somebody else's code on screen, damaged means the
// picture is marginal, and repeats mean the transfer is simply waiting for the
// frames it has not seen yet.
func captureSummary(s capture.Stats) string {
	return fmt.Sprintf(
		"captured  %d images (%d dropped)\nread      %d frames (%d unreadable, %d foreign, %d damaged, %d repeats)\n",
		s.Images, s.Dropped, s.Frames, s.Unreadable, s.Foreign, s.Damaged, s.Repeats)
}
