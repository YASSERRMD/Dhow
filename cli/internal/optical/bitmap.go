// Package optical turns a captured image into the module grid a QR decoder
// can read.
//
// This is the half of Dhow that was missing until Phase 37. The sender renders
// each wire frame as a QR code and shows it on a screen; a camera photographs
// the screen; and what arrives here is an image that is a photograph of a
// rendering, not a rendering. It is out of focus, at an angle, unevenly lit,
// partly covered by whatever is in front of the screen, and smeared by the
// motion of a hand-held camera during the exposure.
//
// The pipeline is the standard one and is worth naming because each stage
// exists to survive a specific thing a camera does:
//
//	binarize   uneven lighting: a threshold computed per region, not per image
//	locate     framing: find the three finder patterns wherever they landed
//	sample     perspective: map module coordinates through the distortion
//
// What comes out is a [qr.Grid], which is the same object the encoder
// produces. From there the decoder cannot tell a photograph from a rendering,
// which is what makes the whole path testable without a camera.
package optical

import (
	"image"
	"image/color"
)

// Bitmap is a binarized image: one bit per pixel, true for dark.
type Bitmap struct {
	// W and H are the pixel dimensions.
	W, H int
	// Dark holds the pixels, row-major, true for dark.
	Dark []bool
}

// At reports whether the pixel at (x, y) is dark. Coordinates outside the
// image read as light, so a scan that runs off the edge sees a boundary rather
// than wrapping.
func (b *Bitmap) At(x, y int) bool {
	if x < 0 || y < 0 || x >= b.W || y >= b.H {
		return false
	}
	return b.Dark[y*b.W+x]
}

// blockSize is the side of the region each local threshold is computed over.
//
// Eight pixels is the standard choice and the reason is geometric rather than
// arbitrary: it has to be small enough that the illumination across it is
// roughly constant and large enough to contain both a dark and a light module
// at the smallest module size worth capturing. A block that lands entirely
// inside one module has no contrast to threshold and has to be handled
// separately, which is what minDynamicRange below is for.
const blockSize = 8

// minDynamicRange is the contrast below which a block is treated as uniform.
const minDynamicRange = 24

// Luminance converts an image to 8-bit grey.
//
// The weights are the usual perceptual ones. They matter here for a reason
// specific to this application: a QR code photographed off an LCD picks up
// colour fringing from the subpixel layout, and weighting the channels equally
// turns that fringing into noise at exactly the spatial frequency of the
// module grid.
func Luminance(img image.Image) (pixels []byte, w, h int) {
	b := img.Bounds()
	w, h = b.Dx(), b.Dy()
	pixels = make([]byte, w*h)

	// The fast path for the form the renderer produces, which is what the
	// tests and the file-backed capture source feed in.
	if p, ok := img.(*image.Gray); ok && p.Stride == w {
		copy(pixels, p.Pix[:w*h])
		return pixels, w, h
	}

	i := 0
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			// RGBA returns 16-bit values; the shift brings them back to 8.
			pixels[i] = byte((19595*r + 38470*g + 7471*bl + 1<<15) >> 24)
			i++
		}
	}
	return pixels, w, h
}

// Binarize converts an image to black and white using a threshold computed per
// region rather than for the whole image.
//
// A single global threshold fails on the capture that actually happens: a
// screen photographed at an angle is brighter at the near edge, and a room lamp
// puts a gradient across the frame. Either can leave one corner of the symbol
// entirely above or entirely below a global threshold, and a lost corner is a
// lost finder pattern, which is a lost frame.
func Binarize(img image.Image) *Bitmap {
	pixels, w, h := Luminance(img)
	return BinarizeGray(pixels, w, h)
}

// BinarizeGray binarizes an 8-bit greyscale buffer.
func BinarizeGray(pixels []byte, w, h int) *Bitmap {
	out := &Bitmap{W: w, H: h, Dark: make([]bool, w*h)}
	if w <= 0 || h <= 0 || len(pixels) < w*h {
		return out
	}
	if w < blockSize || h < blockSize {
		// Too small to have regions. A global threshold is all there is.
		lo, hi := pixels[0], pixels[0]
		for _, p := range pixels[:w*h] {
			lo = min(lo, p)
			hi = max(hi, p)
		}
		threshold := int(lo) + (int(hi)-int(lo))/2
		for i := range out.Dark {
			out.Dark[i] = int(pixels[i]) < threshold
		}
		return out
	}

	// A whole-image fallback for blocks that contain no edge at all. The
	// obvious fallback - half the block's own darkest pixel - assumes that
	// black in the image is near zero, and a screen photographed through
	// glare has a black nearer a hundred. That assumption reads every uniform
	// dark region as light, which is a lost symbol rather than a lost module:
	// measured, it cost about a quarter of the usable contrast range.
	globalLo, globalHi := pixels[0], pixels[0]
	for _, p := range pixels[:w*h] {
		globalLo = min(globalLo, p)
		globalHi = max(globalHi, p)
	}
	globalThreshold := (int(globalLo) + int(globalHi)) / 2

	// One threshold per block, then smoothed across neighbouring blocks so a
	// block boundary does not become a visible edge in the binarized image.
	bw := (w + blockSize - 1) / blockSize
	bh := (h + blockSize - 1) / blockSize
	thresholds := make([]int, bw*bh)

	for by := range bh {
		for bx := range bw {
			x0, y0 := bx*blockSize, by*blockSize
			x1, y1 := min(x0+blockSize, w), min(y0+blockSize, h)

			sum, lo, hi, n := 0, 255, 0, 0
			for y := y0; y < y1; y++ {
				row := y * w
				for x := x0; x < x1; x++ {
					v := int(pixels[row+x])
					sum += v
					lo = min(lo, v)
					hi = max(hi, v)
					n++
				}
			}

			var t int
			switch {
			case hi-lo > minDynamicRange:
				t = sum / n
			case bx > 0 && by > 0:
				// A block with no contrast is entirely inside one module, so
				// its own statistics say nothing about where the boundary
				// between dark and light is. Its neighbours, which have
				// already been computed, do - unless the block is lighter
				// than they are, in which case it is inside a light module
				// and half its own darkest pixel is the tighter bound.
				neighbour := (thresholds[(by-1)*bw+bx] +
					2*thresholds[by*bw+bx-1] +
					thresholds[(by-1)*bw+bx-1]) / 4
				t = neighbour
				if lo >= neighbour {
					t = lo / 2
				}
			default:
				// The first row and column have no computed neighbours yet.
				t = globalThreshold
			}
			thresholds[by*bw+bx] = t
		}
	}

	for by := range bh {
		for bx := range bw {
			// Average over a five-by-five neighbourhood of blocks, clamped
			// at the edges, so a block boundary does not become a visible
			// edge in the binarized image.
			//
			// Over every block, not only the ones that measured a real
			// threshold. Restricting it to those was tried and is worse: it
			// cut the tolerable defocus at version 15 from 0.44 modules to
			// 0.19, because the blocks it excludes are the flat interiors of
			// large modules and excluding them lets the threshold track the
			// noise at the edges.
			sum, n := 0, 0
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					nx, ny := bx+dx, by+dy
					if nx < 0 || ny < 0 || nx >= bw || ny >= bh {
						continue
					}
					sum += thresholds[ny*bw+nx]
					n++
				}
			}
			t := sum / n

			x0, y0 := bx*blockSize, by*blockSize
			x1, y1 := min(x0+blockSize, w), min(y0+blockSize, h)
			for y := y0; y < y1; y++ {
				row := y * w
				for x := x0; x < x1; x++ {
					out.Dark[row+x] = int(pixels[row+x]) < t
				}
			}
		}
	}

	return out
}

// ToImage renders a bitmap back to an image, for diagnostics.
//
// An operator whose captures are not decoding needs to see what the binarizer
// saw. "The threshold ate the left third of the symbol" is visible in one
// glance at this and invisible in any amount of log output.
func (b *Bitmap) ToImage() image.Image {
	img := image.NewPaletted(image.Rect(0, 0, b.W, b.H), color.Palette{color.White, color.Black})
	for i, d := range b.Dark {
		if d {
			img.Pix[i] = 1
		}
	}
	return img
}
