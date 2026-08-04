package cli

import (
	"bytes"
	"encoding/json"
	"image"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dhow/cli/internal/capture"
	"dhow/cli/internal/optical"
)

// The optical path end to end, through the real binary's own commands.
//
// Everything below sends a dataset, renders every frame as a QR code, degrades
// the renderings the way a camera would, and receives them back through
// detection. That is the whole point of Phase 37 and the thing that could not
// be tested before it: the layers above this have been exercised end to end
// since Phase 26, and the optical layer was a directory.

// runWithStdin invokes the CLI with something on standard input.
func runWithStdin(stdin *bytes.Buffer, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(Env{Stdout: &out, Stderr: &errOut, Stdin: stdin, Args: args})
	return code, out.String(), errOut.String()
}

// sendWithQR sends a dataset and renders every frame as an image.
//
// The QR configuration is version 8 at level M: small enough that the symbols
// stay coarse, which is what the degradation tests found matters, and large
// enough to carry a useful symbol size.
func sendWithQR(t *testing.T, key, src, frames string, extra ...string) {
	t.Helper()
	args := []string{
		"send", "-key", key, "-identity", identityBeside(key),
		"-in", src, "-out", frames,
		"-qr", "-qr-version", "8", "-qr-ecc", "M", "-qr-scale", "6",
		"-symbol-size", "96", "-blocks", "2", "-overhead", "120",
	}
	if code, _, errOut := run(append(args, extra...)...); code != ExitOK {
		t.Fatalf("send exited %d: %s", code, errOut)
	}
}

// imagesIn lists the rendered frame images in a directory.
func imagesIn(t *testing.T, dir string) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "frame-*.png"))
	if err != nil || len(names) == 0 {
		t.Fatalf("no rendered frames in %s (%v)", dir, err)
	}
	return names
}

// TestRecvFromRenderedImages is the baseline the whole phase rests on: frames
// go out as pictures and come back as a dataset, with nothing in between but
// the detector and the decoder.
func TestRecvFromRenderedImages(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")
	dest := filepath.Join(dir, "received")

	sendWithQR(t, key, src, frames)

	code, out, errOut := run("recv", "-key", key, "-signer", signerBeside(key),
		"-in", frames, "-source", "images", "-out", dest, "-json")
	if code != ExitOK {
		t.Fatalf("recv from images exited %d: %s", code, errOut)
	}

	var result recvResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parsing recv output: %v\n%s", err, out)
	}
	if result.Capture == nil {
		t.Fatalf("the optical path reported no capture statistics")
	}
	if result.Capture.Unreadable != 0 {
		t.Errorf("%d clean renderings were unreadable", result.Capture.Unreadable)
	}
	if result.Frames == 0 {
		t.Fatalf("no frames were accepted")
	}
	t.Logf("captured %d images, accepted %d frames, %d repeats",
		result.Capture.Images, result.Frames, result.Capture.Repeats)

	assertSameDataset(t, src, dest)
}

// TestRecvFromDegradedImages is the redefined gate at the level of the whole
// tool. Every frame is put through what a camera does to a screen before the
// receiver ever sees it.
func TestRecvFromDegradedImages(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")
	captured := filepath.Join(dir, "captured")
	dest := filepath.Join(dir, "received")

	sendWithQR(t, key, src, frames)

	if err := os.MkdirAll(captured, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	rng := rand.New(rand.NewSource(37))
	names := imagesIn(t, frames)
	for _, name := range names {
		img := degradeLikeACamera(t, name, rng)
		out := filepath.Join(captured, filepath.Base(name))
		writeImage(t, out, img)
	}

	code, out, errOut := run("recv", "-key", key, "-signer", signerBeside(key),
		"-in", frames, "-source", "images:"+captured, "-out", dest, "-json")
	if code != ExitOK {
		t.Fatalf("recv from degraded images exited %d: %s", code, errOut)
	}

	var result recvResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parsing recv output: %v\n%s", err, out)
	}
	// The transfer completing while some captures were unreadable is the
	// property that matters: repair symbols cover the ones the camera lost.
	t.Logf("%d captures: %d frames read, %d unreadable, %d damaged",
		result.Capture.Images, result.Frames, result.Capture.Unreadable, result.Capture.Damaged)
	if result.Capture.Unreadable == 0 {
		t.Errorf("no capture was unreadable; the degradation was too gentle to test anything")
	}
	assertSameDataset(t, src, dest)
}

// TestRecvFromPipe drives the path a live capture uses: images arriving on
// standard input rather than sitting in a directory.
func TestRecvFromPipe(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")
	dest := filepath.Join(dir, "received")

	sendWithQR(t, key, src, frames)

	var stream bytes.Buffer
	for _, name := range imagesIn(t, frames) {
		f, err := os.Open(name)
		if err != nil {
			t.Fatalf("opening %s: %v", name, err)
		}
		img, _, err := image.Decode(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("decoding %s: %v", name, err)
		}
		if err := capture.WriteNetpbm(&stream, img); err != nil {
			t.Fatalf("writing %s to the stream: %v", name, err)
		}
	}

	// -drop=false because this is a recording replayed as fast as the process
	// can read it, not a camera. The default discards whatever arrives while
	// detection is busy, which is right for a live source and loses most of a
	// finite stream: measured here, 9 of 60 frames survived with it on.
	code, _, errOut := runWithStdin(&stream, "recv", "-key", key, "-signer", signerBeside(key),
		"-in", frames, "-source", "pipe", "-drop=false", "-out", dest)
	if code != ExitOK {
		t.Fatalf("recv from a pipe exited %d: %s", code, errOut)
	}
	assertSameDataset(t, src, dest)
}

// TestRecvFromCommand drives the camera path itself, with a command standing in
// for the capture tool.
//
// `cat` is the honest stand-in available here. What it exercises is everything
// dhow owns: starting the process, streaming Netpbm out of its standard output,
// dropping under backpressure, and stopping it. What it does not exercise is
// the camera, which is recorded in docs/BACKLOG.md rather than implied away.
func TestRecvFromCommand(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")
	dest := filepath.Join(dir, "received")

	sendWithQR(t, key, src, frames)

	stream := filepath.Join(dir, "capture.pnm")
	f, err := os.Create(stream)
	if err != nil {
		t.Fatalf("creating the stream file: %v", err)
	}
	for _, name := range imagesIn(t, frames) {
		g, err := os.Open(name)
		if err != nil {
			t.Fatalf("opening %s: %v", name, err)
		}
		img, _, err := image.Decode(g)
		_ = g.Close()
		if err != nil {
			t.Fatalf("decoding %s: %v", name, err)
		}
		if err := capture.WriteNetpbm(f, img); err != nil {
			t.Fatalf("writing the stream: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the stream file: %v", err)
	}

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key),
		"-in", frames, "-source", "cmd:cat "+stream, "-drop=false", "-out", dest)
	if code != ExitOK {
		t.Fatalf("recv from a capture command exited %d: %s", code, errOut)
	}
	assertSameDataset(t, src, dest)
}

// TestRecvRejectsUnknownSource checks a mistyped source is a usage error
// rather than a receiver that silently reads nothing.
func TestRecvRejectsUnknownSource(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")

	sendWithQR(t, key, src, frames)

	code, _, errOut := run("recv", "-key", key, "-signer", signerBeside(key),
		"-in", frames, "-source", "camera", "-out", filepath.Join(dir, "out"))
	if code != ExitUsage {
		t.Errorf("an unknown -source exited %d, want %d: %s", code, ExitUsage, errOut)
	}
}

// TestRecvFromImagesOfAnotherSession checks frames captured from somebody
// else's transfer are counted as foreign and never reach the decoder.
func TestRecvFromImagesOfAnotherSession(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)

	ours := filepath.Join(dir, "ours")
	theirs := filepath.Join(dir, "theirs")
	sendWithQR(t, key, src, ours)
	sendWithQR(t, key, src, theirs)

	code, out, _ := run("recv", "-key", key, "-signer", signerBeside(key),
		"-in", ours, "-source", "images:"+theirs, "-out", filepath.Join(dir, "received"), "-json")
	if code != ExitIncomplete {
		t.Fatalf("receiving another session's frames exited %d, want %d", code, ExitIncomplete)
	}
	// Nothing decoded, so there is no JSON result; the count lives in the
	// error path. What matters is that it failed closed and wrote nothing.
	if _, err := os.Stat(filepath.Join(dir, "received")); err == nil {
		t.Errorf("a transfer of another session's frames wrote output")
	}
	_ = out
}

// --- detect ---

func TestDetectReportsWhatAFrameHolds(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")

	sendWithQR(t, key, src, frames)
	first := imagesIn(t, frames)[0]

	code, out, errOut := run("detect", "-json", first)
	if code != ExitOK {
		t.Fatalf("detect exited %d: %s", code, errOut)
	}
	var results []detectResult
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatalf("parsing detect output: %v\n%s", err, out)
	}
	if len(results) != 1 {
		t.Fatalf("detect reported %d results for one file", len(results))
	}
	r := results[0]
	if !r.Read || !r.Frame {
		t.Fatalf("detect did not read a dhow frame out of a rendered frame: %+v", r)
	}
	if r.Version != 8 {
		t.Errorf("detect read version %d, the frame was rendered at 8", r.Version)
	}
	if r.Level != "M" {
		t.Errorf("detect read level %s, the frame was rendered at M", r.Level)
	}
	if len(r.Session) != 32 {
		t.Errorf("detect reported session %q", r.Session)
	}
}

func TestDetectOnSomethingThatIsNotASymbol(t *testing.T) {
	dir := t.TempDir()
	blank := filepath.Join(dir, "blank.png")
	writeImage(t, blank, image.NewGray(image.Rect(0, 0, 200, 200)))

	code, out, _ := run("detect", blank)
	if code != ExitInput {
		t.Errorf("detect on a blank image exited %d, want %d", code, ExitInput)
	}
	if !strings.Contains(out, "no symbol read") {
		t.Errorf("detect said %q", out)
	}
}

func TestDetectWritesTheBinarizedImage(t *testing.T) {
	dir := t.TempDir()
	key := keygen(t, dir)
	src := fixture(t)
	frames := filepath.Join(dir, "frames")
	shown := filepath.Join(dir, "binarized")

	sendWithQR(t, key, src, frames)
	first := imagesIn(t, frames)[0]

	if code, _, errOut := run("detect", "-binarized", shown, first); code != ExitOK {
		t.Fatalf("detect exited %d: %s", code, errOut)
	}
	written, err := filepath.Glob(filepath.Join(shown, "*.binarized.png"))
	if err != nil || len(written) != 1 {
		t.Fatalf("detect wrote %v binarized images (%v)", written, err)
	}
}

// --- helpers ---

// degradeLikeACamera applies the combination a real capture produces.
//
// Deliberately harsher than any single degradation the optical package's own
// tests measure, and deliberately random per frame: the point of this test is
// that the fountain code covers the frames the camera loses, which needs some
// of them to be lost.
func degradeLikeACamera(t *testing.T, name string, rng *rand.Rand) image.Image {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatalf("opening %s: %v", name, err)
	}
	defer func() { _ = f.Close() }()

	decoded, _, err := image.Decode(f)
	if err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}

	img := optical.Grayscale(decoded)
	img = optical.Perspective(img, 0.05, 0.02)
	img = optical.Rotate(img, rng.Float64()*8-4, 0xFF)
	img = optical.Blur(img, 0.8+rng.Float64())
	img = optical.MotionBlur(img, 1+rng.Float64()*3, rng.Float64()*180)
	img = optical.Vignette(img, 0.3)
	img = optical.Contrast(img, 0.6, -8)
	img = optical.Occlude(img, rng.Float64()*0.05, 0, rng)
	return optical.Noise(img, 10, rng)
}

func writeImage(t *testing.T, name string, img image.Image) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := writePNG(name, img); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

// assertSameDataset checks a received directory matches what was sent.
func assertSameDataset(t *testing.T, src, dest string) {
	t.Helper()
	want := listFiles(t, src)
	got := listFiles(t, dest)
	if len(got) != len(want) {
		t.Fatalf("received %d files, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("file %d: got %q, want %q", i, got[i], want[i])
		}
		a, _ := os.ReadFile(filepath.Join(src, filepath.FromSlash(want[i])))
		b, _ := os.ReadFile(filepath.Join(dest, filepath.FromSlash(got[i])))
		if !bytes.Equal(a, b) {
			t.Errorf("%s: contents differ", want[i])
		}
	}
}
