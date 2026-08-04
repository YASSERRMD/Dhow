package optical

import (
	"bytes"
	"image"
	"math/rand"
	"testing"

	"dhow/cli/internal/ffi"
	"dhow/cli/internal/render"
)

// renderPayload produces the image the sender's screen would show: a QR code
// at a given number of pixels per module, with the quiet zone the
// specification requires.
func renderPayload(t *testing.T, payload []byte, version int, ecc byte, scale int) image.Image {
	t.Helper()
	code, err := ffi.EncodeQR(payload, version, ecc)
	if err != nil {
		t.Fatalf("encoding %d bytes at version %d: %v", len(payload), version, err)
	}
	img, err := render.Image(code, scale)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	return img
}

// samplePayload is a stand-in for a wire frame: incompressible, so the symbol
// has no large uniform regions that would make detection easier than it is.
func samplePayload(seed int64, n int) []byte {
	rng := rand.New(rand.NewSource(seed))
	out := make([]byte, n)
	_, _ = rng.Read(out)
	return out
}

// TestReadsCleanRenderings is the baseline: a perfect capture of a perfect
// rendering. Everything else in this package is measured against it.
func TestReadsCleanRenderings(t *testing.T) {
	for _, version := range []int{1, 2, 6, 7, 15, 25, 40} {
		for _, scale := range []int{3, 5, 8} {
			capacity, err := ffi.QRCapacity(version, 'M')
			if err != nil {
				t.Fatalf("capacity: %v", err)
			}
			payload := samplePayload(int64(version*100+scale), capacity)
			img := renderPayload(t, payload, version, 'M', scale)

			got, err := Read(img)
			if err != nil {
				t.Errorf("version %d at %d px/module: %v", version, scale, err)
				continue
			}
			if !bytes.Equal(got.Data, payload) {
				t.Errorf("version %d at %d px/module: recovered %d of %d bytes",
					version, scale, len(got.Data), len(payload))
			}
			if got.Version != version {
				t.Errorf("version %d at %d px/module: read as version %d",
					version, scale, got.Version)
			}
		}
	}
}

// TestReadsSymbolAmongClutter puts the symbol somewhere in a larger frame with
// other things in it, which is what a photograph of a screen in a room is.
func TestReadsSymbolAmongClutter(t *testing.T) {
	payload := samplePayload(42, 200)
	code := renderPayload(t, payload, 10, 'M', 6)

	scene := image.NewGray(image.Rect(0, 0, 900, 700))
	for i := range scene.Pix {
		scene.Pix[i] = 0xFF
	}
	// A dark border along one edge and a block in a corner: the kind of thing
	// a monitor bezel and a shadow put in frame.
	for y := range 700 {
		for x := range 40 {
			scene.Pix[y*scene.Stride+x] = 0x20
		}
	}
	for y := 600; y < 690; y++ {
		for x := 700; x < 880; x++ {
			scene.Pix[y*scene.Stride+x] = 0x30
		}
	}

	b := code.Bounds()
	for y := range b.Dy() {
		for x := range b.Dx() {
			r, _, _, _ := code.At(b.Min.X+x, b.Min.Y+y).RGBA()
			scene.Pix[(y+120)*scene.Stride+(x+300)] = byte(r >> 8)
		}
	}

	got, err := Read(scene)
	if err != nil {
		t.Fatalf("reading a symbol placed in a larger scene: %v", err)
	}
	if !bytes.Equal(got.Data, payload) {
		t.Errorf("recovered %d bytes, sent %d", len(got.Data), len(payload))
	}
}

// TestImagesWithoutSymbolsAreRejected checks the detector reports nothing
// rather than finding a symbol in noise.
func TestImagesWithoutSymbolsAreRejected(t *testing.T) {
	rng := rand.New(rand.NewSource(3))

	blank := image.NewGray(image.Rect(0, 0, 320, 240))
	for i := range blank.Pix {
		blank.Pix[i] = 0xFF
	}

	noise := image.NewGray(image.Rect(0, 0, 320, 240))
	for i := range noise.Pix {
		noise.Pix[i] = byte(rng.Intn(256))
	}

	stripes := image.NewGray(image.Rect(0, 0, 320, 240))
	for y := range 240 {
		for x := range 320 {
			v := byte(0xFF)
			if (x/7)%2 == 0 {
				v = 0
			}
			stripes.Pix[y*stripes.Stride+x] = v
		}
	}

	for name, img := range map[string]image.Image{
		"blank": blank, "noise": noise, "stripes": stripes,
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Read(img); err == nil {
				t.Errorf("read %d bytes out of an image with no symbol in it", len(got.Data))
			}
		})
	}
}

// TestTinyAndEmptyImagesDoNotPanic covers the degenerate captures: a source
// that returned nothing, or a single pixel.
func TestTinyAndEmptyImagesDoNotPanic(t *testing.T) {
	for _, r := range []image.Rectangle{
		image.Rect(0, 0, 0, 0),
		image.Rect(0, 0, 1, 1),
		image.Rect(0, 0, 1, 500),
		image.Rect(0, 0, 500, 1),
		image.Rect(0, 0, 7, 7),
	} {
		img := image.NewGray(r)
		if _, err := Read(img); err == nil {
			t.Errorf("%v: read a symbol out of an image that cannot hold one", r)
		}
	}
}
