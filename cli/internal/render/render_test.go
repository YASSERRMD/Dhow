package render

import (
	"bytes"
	"image"
	"image/png"
	"strings"
	"testing"

	"dhow/cli/internal/ffi"
)

// encode builds a QR code for test data at a pinned version.
func encode(t *testing.T, data []byte, version int) *ffi.QRCode {
	t.Helper()
	qr, err := ffi.EncodeQR(data, version, 'M')
	if err != nil {
		t.Fatalf("EncodeQR: %v", err)
	}
	return qr
}

func TestTerminalIncludesQuietZone(t *testing.T) {
	// Without the margin a scanner cannot find the code's edge against
	// whatever is behind it.
	qr := encode(t, []byte("quiet zone"), 5)

	var buf bytes.Buffer
	if err := Terminal(&buf, qr); err != nil {
		t.Fatalf("Terminal: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	wantLines := qr.Size + 2*QuietZone
	if len(lines) != wantLines {
		t.Fatalf("got %d lines, want %d", len(lines), wantLines)
	}

	// The first and last QuietZone rows must be entirely light.
	for _, i := range []int{0, QuietZone - 1, len(lines) - QuietZone, len(lines) - 1} {
		if strings.Contains(lines[i], darkCell) {
			t.Errorf("line %d should be part of the quiet zone but has dark modules", i)
		}
	}
}

func TestTerminalRowWidthIsUniform(t *testing.T) {
	qr := encode(t, []byte("uniform"), 5)

	var buf bytes.Buffer
	if err := Terminal(&buf, qr); err != nil {
		t.Fatalf("Terminal: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// Two cells per module, so a square code stays square on a terminal.
	want := (qr.Size + 2*QuietZone) * 2
	for i, line := range lines {
		if got := len([]rune(line)); got != want {
			t.Errorf("line %d width = %d runes, want %d", i, got, want)
		}
	}
}

func TestTerminalIsDeterministic(t *testing.T) {
	qr := encode(t, []byte("deterministic"), 5)

	var a, b bytes.Buffer
	if err := Terminal(&a, qr); err != nil {
		t.Fatalf("Terminal: %v", err)
	}
	if err := Terminal(&b, qr); err != nil {
		t.Fatalf("Terminal: %v", err)
	}
	if a.String() != b.String() {
		t.Error("two renderings of one code differed")
	}
}

func TestImageDimensionsIncludeQuietZone(t *testing.T) {
	qr := encode(t, []byte("dimensions"), 10)

	for _, scale := range []int{1, 4, 8} {
		img, err := Image(qr, scale)
		if err != nil {
			t.Fatalf("scale %d: Image: %v", scale, err)
		}
		want := (qr.Size + 2*QuietZone) * scale
		b := img.Bounds()
		if b.Dx() != want || b.Dy() != want {
			t.Errorf("scale %d: got %dx%d, want %dx%d", scale, b.Dx(), b.Dy(), want, want)
		}
	}
}

func TestImageRejectsNonPositiveScale(t *testing.T) {
	qr := encode(t, []byte("scale"), 5)
	for _, scale := range []int{0, -1} {
		if _, err := Image(qr, scale); err == nil {
			t.Errorf("scale %d was accepted", scale)
		}
	}
}

func TestImageIsTwoColoursOnly(t *testing.T) {
	// Anti-aliasing or a wider palette would soften module edges, which is
	// exactly what makes a capture ambiguous.
	qr := encode(t, []byte("two colours"), 10)
	img, err := Image(qr, 4)
	if err != nil {
		t.Fatalf("Image: %v", err)
	}

	pal, ok := img.(*image.Paletted)
	if !ok {
		t.Fatalf("got %T, want *image.Paletted", img)
	}
	if len(pal.Palette) != 2 {
		t.Errorf("palette has %d entries, want 2", len(pal.Palette))
	}
}

func TestImageModulesMatchTheGrid(t *testing.T) {
	qr := encode(t, []byte("module fidelity"), 5)
	const scale = 3

	img, err := Image(qr, scale)
	if err != nil {
		t.Fatalf("Image: %v", err)
	}
	pal, ok := img.(*image.Paletted)
	if !ok {
		t.Fatalf("Image returned %T, want *image.Paletted", img)
	}

	for y := range qr.Size {
		for x := range qr.Size {
			// Sample the centre of the module's block of pixels.
			px := (x+QuietZone)*scale + scale/2
			py := (y+QuietZone)*scale + scale/2
			gotDark := pal.ColorIndexAt(px, py) == 1
			if gotDark != qr.Dark(x, y) {
				t.Fatalf("module (%d,%d): rendered dark=%v, grid dark=%v",
					x, y, gotDark, qr.Dark(x, y))
			}
		}
	}
}

func TestImageQuietZoneIsLight(t *testing.T) {
	qr := encode(t, []byte("margin"), 5)
	const scale = 2

	img, err := Image(qr, scale)
	if err != nil {
		t.Fatalf("Image: %v", err)
	}
	pal, ok := img.(*image.Paletted)
	if !ok {
		t.Fatalf("Image returned %T, want *image.Paletted", img)
	}
	total := (qr.Size + 2*QuietZone) * scale

	for i := range total {
		for _, p := range [][2]int{
			{i, 0}, {i, total - 1}, {0, i}, {total - 1, i},
		} {
			if pal.ColorIndexAt(p[0], p[1]) != 0 {
				t.Fatalf("edge pixel (%d,%d) was dark", p[0], p[1])
			}
		}
	}
}

func TestPNGIsDecodable(t *testing.T) {
	qr := encode(t, []byte("a real frame worth of bytes"), 10)

	var buf bytes.Buffer
	if err := PNG(&buf, qr, 6); err != nil {
		t.Fatalf("PNG: %v", err)
	}

	img, err := png.Decode(&buf)
	if err != nil {
		t.Fatalf("decoding the PNG we just wrote: %v", err)
	}
	want := (qr.Size + 2*QuietZone) * 6
	if img.Bounds().Dx() != want {
		t.Errorf("decoded width = %d, want %d", img.Bounds().Dx(), want)
	}
}

func TestPNGIsDeterministic(t *testing.T) {
	// The sender must produce a byte-identical stream for a given transfer.
	qr := encode(t, []byte("reproducible"), 10)

	var a, b bytes.Buffer
	if err := PNG(&a, qr, 4); err != nil {
		t.Fatalf("PNG: %v", err)
	}
	if err := PNG(&b, qr, 4); err != nil {
		t.Fatalf("PNG: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("two PNG renderings of one code differed")
	}
}

func TestPNGRejectsBadScale(t *testing.T) {
	qr := encode(t, []byte("scale"), 5)
	if err := PNG(&bytes.Buffer{}, qr, 0); err == nil {
		t.Error("scale 0 was accepted")
	}
}

func TestCapacityAndSymbolSizeAreConsistent(t *testing.T) {
	// The symbol size a caller may request is the QR capacity minus the frame
	// header and the RaptorQ payload identifier.
	const frameOverhead = 46 + 4

	for _, version := range []int{10, 20, 40} {
		capacity, err := ffi.QRCapacity(version, 'M')
		if err != nil {
			t.Fatalf("QRCapacity: %v", err)
		}
		sym, err := ffi.QRMaxSymbolSize(version, 'M')
		if err != nil {
			t.Fatalf("QRMaxSymbolSize: %v", err)
		}
		if sym+frameOverhead != capacity {
			t.Errorf("version %d: symbol %d + overhead %d != capacity %d",
				version, sym, frameOverhead, capacity)
		}
	}
}

func TestCapacityRejectsBadArguments(t *testing.T) {
	if _, err := ffi.QRCapacity(0, 'M'); err == nil {
		t.Error("version 0 was accepted")
	}
	if _, err := ffi.QRCapacity(41, 'M'); err == nil {
		t.Error("version 41 was accepted")
	}
	if _, err := ffi.QRCapacity(10, 'X'); err == nil {
		t.Error("error-correction level X was accepted")
	}
}

func TestEncodeQRRejectsEmptyFrame(t *testing.T) {
	if _, err := ffi.EncodeQR(nil, 10, 'M'); err == nil {
		t.Error("an empty frame was accepted")
	}
}

func TestEncodeQRRejectsOversizedFrame(t *testing.T) {
	// A frame larger than the pinned version must be reported rather than
	// silently promoted to a bigger version, which would change the physical
	// size of that frame on screen mid-stream.
	capacity, err := ffi.QRCapacity(5, 'M')
	if err != nil {
		t.Fatalf("QRCapacity: %v", err)
	}
	if _, err := ffi.EncodeQR(make([]byte, capacity+1), 5, 'M'); err == nil {
		t.Error("an oversized frame was accepted at a pinned version")
	}
}

func TestEncodeQRAutoSelectsVersion(t *testing.T) {
	// Version 0 means "choose the smallest that fits".
	small, err := ffi.EncodeQR([]byte("tiny"), 0, 'M')
	if err != nil {
		t.Fatalf("EncodeQR: %v", err)
	}
	large, err := ffi.EncodeQR(make([]byte, 800), 0, 'M')
	if err != nil {
		t.Fatalf("EncodeQR: %v", err)
	}
	if large.Size <= small.Size {
		t.Errorf("larger payload produced a %d-module code, small produced %d",
			large.Size, small.Size)
	}
}

func TestDarkReadsOutsideTheGridAreLight(t *testing.T) {
	qr := encode(t, []byte("bounds"), 5)
	for _, p := range [][2]int{{-1, 0}, {0, -1}, {qr.Size, 0}, {0, qr.Size}} {
		if qr.Dark(p[0], p[1]) {
			t.Errorf("out-of-range module (%d,%d) read as dark", p[0], p[1])
		}
	}
}
