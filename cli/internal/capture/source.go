// Package capture supplies the receiver with images to look for frames in.
//
// # Why this is an interface
//
// Opening a camera is platform work: AVFoundation on macOS, V4L2 on Linux,
// Media Foundation on Windows, each with its own device enumeration, pixel
// formats, and exposure controls. Writing three of those inside a tool whose
// correctness-critical parts are elsewhere would add a large amount of code
// that nobody here can test, on the one machine in the deployment that is
// deliberately off every network and therefore hardest to debug on.
//
// So dhow does not open a camera. It reads images from a source, and a source
// is one of:
//
//	Dir      a directory of image files, which is how a capture is replayed
//	         or a rendering is read back without hardware
//	Stream   a sequence of Netpbm images on a pipe
//	Command  a program dhow starts, whose standard output is that pipe
//
// The third is the camera path. `ffmpeg -f avfoundation -i 0 -f image2pipe
// -vcodec pgm -` is a camera, and so is the v4l2 equivalent, and so is a
// gphoto2 tether or a network-free capture card utility. Each of them already
// solves the platform problem, is already installed on machines that do video
// work, and can be replaced by an operator whose hardware needs something
// else without touching dhow. `docs/OPERATIONS.md` gives the exact commands.
//
// The honest cost of this is written down in `docs/BACKLOG.md`: every path
// here is exercised, and none of them has been exercised against a real
// camera pointed at a real screen.
package capture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // registered so a Dir source can read camera stills
	_ "image/png"  // registered so a Dir source can read rendered frames
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// ErrExhausted reports a source with no more images. It is not a failure: a
// directory ends, and a capture command that exits has ended the capture.
var ErrExhausted = errors.New("capture: source exhausted")

// Source yields captured images one at a time.
//
// Next blocks until an image is available, the context is cancelled, or the
// source is exhausted. Implementations must return [ErrExhausted] rather than
// io.EOF so a caller cannot confuse the end of a capture with a read error
// somewhere inside it.
type Source interface {
	Next(ctx context.Context) (image.Image, error)
	Close() error
}

// --- directory ---

// Dir reads image files from a directory in sorted order.
//
// The order matters more than it looks: a capture replayed out of order is
// still decodable, because the fountain code does not care, but a *test* that
// replays out of order cannot tell a detector bug from a shuffled input.
type Dir struct {
	names []string
	next  int
}

// OpenDir lists the images in a directory.
//
// Patterns are matched case-insensitively against the file extension rather
// than by probing the contents, because a directory being pointed at by an
// operator will contain a manifest and frame binaries alongside the images and
// opening each of those to find out is noise in the error output.
func OpenDir(path string) (*Dir, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("capture: reading %s: %w", path, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".png", ".jpg", ".jpeg", ".pgm", ".ppm", ".pnm":
			names = append(names, filepath.Join(path, e.Name()))
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("capture: no images in %s", path)
	}
	sort.Strings(names)
	return &Dir{names: names}, nil
}

// Len reports how many images the directory holds, which is the ground truth a
// drop counter is checked against.
func (d *Dir) Len() int { return len(d.names) }

// Next returns the next image.
func (d *Dir) Next(ctx context.Context) (image.Image, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.next >= len(d.names) {
		return nil, ErrExhausted
	}
	name := d.names[d.next]
	d.next++

	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("capture: opening %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()

	img, err := decodeImage(bufio.NewReader(f))
	if err != nil {
		return nil, fmt.Errorf("capture: decoding %s: %w", name, err)
	}
	return img, nil
}

// Close releases nothing; a Dir holds no handles between reads.
func (d *Dir) Close() error { return nil }

// --- stream ---

// Stream reads a sequence of Netpbm images from a reader.
//
// Netpbm rather than PNG because a PNG decoder over-reads: it buffers ahead
// past the end of one image, which loses the start of the next one in a
// concatenated stream. Netpbm's header declares its own length exactly, so a
// reader can stop on the last byte of an image and leave the next one intact.
// It is also what every capture tool can emit and what none of them compresses,
// which for a pipe on the same machine is the right trade.
type Stream struct {
	r      *bufio.Reader
	closer io.Closer
}

// OpenStream reads Netpbm images from r.
func OpenStream(r io.Reader, closer io.Closer) *Stream {
	return &Stream{r: bufio.NewReaderSize(r, 1<<20), closer: closer}
}

// Next reads the next image from the stream.
func (s *Stream) Next(ctx context.Context) (image.Image, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	img, err := readNetpbm(s.r)
	if errors.Is(err, io.EOF) {
		return nil, ErrExhausted
	}
	return img, err
}

// Close closes the underlying reader if there is one to close.
func (s *Stream) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
}

// --- command ---

// Command runs a capture program and reads Netpbm images from its output.
//
// This is the camera path. The command is whatever the operator's hardware
// needs; dhow's part is to start it, read it, and stop it cleanly when the
// transfer ends or the operator does.
type Command struct {
	cmd    *exec.Cmd
	stream *Stream
	stderr *strings.Builder
}

// StartCommand runs argv and streams images from its standard output.
//
// The command's standard error is captured rather than passed through, so that
// a capture tool's per-frame chatter does not overwrite the receiver's progress
// display - and is included in the error when the command fails, because
// "exit status 1" on its own tells an operator nothing about a camera that is
// in use by something else.
func StartCommand(ctx context.Context, argv []string) (*Command, error) {
	if len(argv) == 0 {
		return nil, errors.New("capture: empty capture command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("capture: connecting to %s: %w", argv[0], err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("capture: starting %s: %w", argv[0], err)
	}
	return &Command{cmd: cmd, stream: OpenStream(stdout, nil), stderr: &stderr}, nil
}

// Next reads the next image the command produced.
func (c *Command) Next(ctx context.Context) (image.Image, error) {
	img, err := c.stream.Next(ctx)
	if errors.Is(err, ErrExhausted) {
		// The command ended. Whether that is normal or a failure is what its
		// exit status says, and its standard error is the only place an
		// operator will find out why.
		if waitErr := c.cmd.Wait(); waitErr != nil {
			return nil, fmt.Errorf("capture: %s failed: %w: %s",
				c.cmd.Path, waitErr, strings.TrimSpace(c.stderr.String()))
		}
		return nil, ErrExhausted
	}
	return img, err
}

// Close stops the capture command.
func (c *Command) Close() error {
	if c.cmd.Process == nil {
		return nil
	}
	// Killed rather than signalled politely: a capture tool holding a camera
	// open has nothing to flush, and a receiver that hangs waiting for one to
	// exit is worse than one that ends abruptly.
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
	return nil
}
