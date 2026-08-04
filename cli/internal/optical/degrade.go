package optical

import (
	"image"
	"math"
	"math/rand"
)

// Synthetic degradation: what a camera does to a rendering, applied
// deliberately so the detector can be tested without one.
//
// # Why this exists and what it is not
//
// The phase pack's gate for this work calls for recorded video fixtures at
// three quality levels. Those fixtures do not exist in this repository and
// could not be produced here: there is no camera and no screen to point it at.
// Committing video recorded elsewhere would make the gate depend on binary
// blobs whose provenance is a sentence in a log.
//
// So the substitute is this: take the image the renderer actually produces -
// which is exactly what the screen would show - and apply, one at a time and in
// combination, the specific things a camera does to it. Each function below
// models one physical effect, takes a strength, and is deterministic given a
// seed, so a test can assert the strength at which detection still succeeds
// rather than only that it succeeds somewhere.
//
// **This is a model of a camera and not a camera.** It does not reproduce
// rolling-shutter skew during a screen refresh, moire between the sensor's
// pixel grid and the screen's, chromatic aberration at the edges of a cheap
// lens, auto-exposure hunting, or a display's gamma. `docs/BACKLOG.md` records
// that the hardware path remains unexercised, and this comment is here so that
// nobody reading the passing tests concludes otherwise.

// Grayscale copies an image into an 8-bit grey buffer that the functions below
// operate on.
func Grayscale(img image.Image) *image.Gray {
	pixels, w, h := Luminance(img)
	out := image.NewGray(image.Rect(0, 0, w, h))
	copy(out.Pix, pixels)
	return out
}

// Blur applies a Gaussian blur of the given radius in pixels.
//
// Models a lens out of focus, which is the single most common reason a capture
// fails: focus is set once by an operator at one distance, and a screen at a
// slightly different distance is soft everywhere. Separable, because a
// two-dimensional Gaussian is the product of two one-dimensional ones and the
// separable form is linear rather than quadratic in the radius.
func Blur(img *image.Gray, radius float64) *image.Gray {
	if radius <= 0 {
		return copyGray(img)
	}
	kernel := gaussianKernel(radius)
	half := len(kernel) / 2
	w, h := img.Rect.Dx(), img.Rect.Dy()

	horizontal := image.NewGray(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			var sum float64
			for k, weight := range kernel {
				sum += weight * float64(grayAt(img, x+k-half, y))
			}
			horizontal.Pix[y*horizontal.Stride+x] = clampByte(sum)
		}
	}

	out := image.NewGray(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			var sum float64
			for k, weight := range kernel {
				sum += weight * float64(grayAt(horizontal, x, y+k-half))
			}
			out.Pix[y*out.Stride+x] = clampByte(sum)
		}
	}
	return out
}

// MotionBlur smears the image along a direction.
//
// Models a hand-held camera moving during the exposure, or a screen scrolling
// under it. Distinct from defocus because it is directional: it destroys the
// module grid along one axis and leaves it intact along the other, which is a
// different problem for the detector than uniform softening.
func MotionBlur(img *image.Gray, length float64, angleDegrees float64) *image.Gray {
	if length <= 1 {
		return copyGray(img)
	}
	w, h := img.Rect.Dx(), img.Rect.Dy()
	steps := int(math.Ceil(length))
	radians := angleDegrees * math.Pi / 180
	dx, dy := math.Cos(radians), math.Sin(radians)

	out := image.NewGray(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			var sum float64
			for s := range steps {
				offset := float64(s) - float64(steps-1)/2
				sum += float64(grayAt(img,
					x+int(math.Round(offset*dx)),
					y+int(math.Round(offset*dy))))
			}
			out.Pix[y*out.Stride+x] = clampByte(sum / float64(steps))
		}
	}
	return out
}

// Perspective reprojects the image as though photographed from an angle.
//
// tilt is how far the far edge shrinks, as a fraction of the image width; yaw
// is the same for the vertical axis. A camera on a tripod beside an operator
// standing at the screen is at ten to twenty degrees off the normal, which is
// a shrink of roughly a tenth.
//
// This is the degradation the perspective transform in the sampler exists for,
// and the one an affine model cannot represent.
func Perspective(img *image.Gray, tilt, yaw float64) *image.Gray {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	if w <= 0 || h <= 0 {
		return copyGray(img)
	}
	fw, fh := float64(w), float64(h)

	// The destination quadrilateral: the corners of the image moved inward on
	// the far side of each axis.
	x0, y0 := 0.0, 0.0
	x1, y1 := fw-1, fh*yaw
	x2, y2 := fw-1-fw*tilt, fh-1-fh*yaw
	x3, y3 := fw*tilt, fh-1

	// Mapped backwards, destination to source, so every output pixel gets a
	// value: forwards mapping leaves holes wherever the projection expands.
	t := quadToQuad(x0, y0, x1, y1, x2, y2, x3, y3, 0, 0, fw-1, 0, fw-1, fh-1, 0, fh-1)
	if t == nil {
		return copyGray(img)
	}

	out := image.NewGray(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			sx, sy := t.apply(float64(x), float64(y))
			out.Pix[y*out.Stride+x] = byte(bilinear(img, sx, sy))
		}
	}
	return out
}

// Rotate turns the image about its centre, filling the corners with the
// background.
//
// Models a camera that is not square to the screen. QR detection is supposed to
// be rotation invariant; this is what checks that it is, including the case
// that swaps which finder pattern is which.
func Rotate(img *image.Gray, degrees float64, background byte) *image.Gray {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	radians := degrees * math.Pi / 180
	sin, cos := math.Sin(radians), math.Cos(radians)
	cx, cy := float64(w-1)/2, float64(h-1)/2

	out := image.NewGray(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			dx, dy := float64(x)-cx, float64(y)-cy
			sx := cx + dx*cos + dy*sin
			sy := cy - dx*sin + dy*cos
			if sx < 0 || sy < 0 || sx > float64(w-1) || sy > float64(h-1) {
				out.Pix[y*out.Stride+x] = background
				continue
			}
			out.Pix[y*out.Stride+x] = byte(bilinear(img, sx, sy))
		}
	}
	return out
}

// Occlude paints a rectangle over a fraction of the image.
//
// Models the thing that actually interrupts a transfer: a hand, a coffee cup, a
// reflection of a window, an operator walking past. Deliberately an opaque
// block rather than noise, because a block is the case that error correction
// has to survive as a burst rather than as scattered damage.
func Occlude(img *image.Gray, fraction float64, shade byte, rng *rand.Rand) *image.Gray {
	out := copyGray(img)
	if fraction <= 0 {
		return out
	}
	w, h := img.Rect.Dx(), img.Rect.Dy()
	side := int(math.Sqrt(fraction * float64(w) * float64(h)))
	if side < 1 {
		return out
	}
	x0 := rng.Intn(max(w-side, 1))
	y0 := rng.Intn(max(h-side, 1))
	for y := y0; y < min(y0+side, h); y++ {
		for x := x0; x < min(x0+side, w); x++ {
			out.Pix[y*out.Stride+x] = shade
		}
	}
	return out
}

// Noise adds zero-mean Gaussian noise of the given standard deviation.
//
// Models sensor noise, which rises steeply as a room gets darker and is the
// reason a capture that works at midday fails at dusk.
func Noise(img *image.Gray, sigma float64, rng *rand.Rand) *image.Gray {
	out := copyGray(img)
	if sigma <= 0 {
		return out
	}
	for i, p := range out.Pix {
		out.Pix[i] = clampByte(float64(p) + rng.NormFloat64()*sigma)
	}
	return out
}

// Contrast compresses the range towards mid grey and shifts it.
//
// scale of 1 leaves the image alone; 0.3 leaves a picture whose black is dark
// grey and whose white is light grey, which is what a screen photographed
// through glare looks like. This is what the local binarizer exists for, and
// what a fixed global threshold fails on.
func Contrast(img *image.Gray, scale float64, offset float64) *image.Gray {
	out := copyGray(img)
	for i, p := range out.Pix {
		out.Pix[i] = clampByte((float64(p)-128)*scale + 128 + offset)
	}
	return out
}

// Vignette darkens the image towards its corners.
//
// Models both a lens's falloff and the far side of a screen photographed at an
// angle being further from the light. It is the degradation that most directly
// defeats a single global threshold, because it moves the boundary between dark
// and light across the frame without changing anything about the symbol.
func Vignette(img *image.Gray, strength float64) *image.Gray {
	out := copyGray(img)
	w, h := img.Rect.Dx(), img.Rect.Dy()
	cx, cy := float64(w-1)/2, float64(h-1)/2
	maxDistance := math.Hypot(cx, cy)
	if maxDistance == 0 {
		return out
	}
	for y := range h {
		for x := range w {
			d := math.Hypot(float64(x)-cx, float64(y)-cy) / maxDistance
			factor := 1 - strength*d*d
			i := y*out.Stride + x
			out.Pix[i] = clampByte(float64(out.Pix[i]) * factor)
		}
	}
	return out
}

// Downsample shrinks the image by an integer factor by averaging, then leaves
// it at the smaller size.
//
// Models a camera that resolves fewer pixels per module than the renderer drew,
// which is what distance does. It is the cheapest way to find the point at
// which a symbol becomes unreadable at a given screen size.
func Downsample(img *image.Gray, factor int) *image.Gray {
	if factor <= 1 {
		return copyGray(img)
	}
	w, h := img.Rect.Dx()/factor, img.Rect.Dy()/factor
	out := image.NewGray(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			sum := 0
			for dy := range factor {
				for dx := range factor {
					sum += int(grayAt(img, x*factor+dx, y*factor+dy))
				}
			}
			out.Pix[y*out.Stride+x] = byte(sum / (factor * factor))
		}
	}
	return out
}

// --- helpers ---

func copyGray(img *image.Gray) *image.Gray {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	out := image.NewGray(image.Rect(0, 0, w, h))
	for y := range h {
		src := img.PixOffset(img.Rect.Min.X, img.Rect.Min.Y+y)
		copy(out.Pix[y*out.Stride:y*out.Stride+w], img.Pix[src:src+w])
	}
	return out
}

// grayAt reads a pixel, clamping at the edges so a kernel that runs off the
// image sees the edge repeated rather than black. Black would put a false edge
// around the frame, which is exactly the feature a detector looks for.
func grayAt(img *image.Gray, x, y int) byte {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	if w <= 0 || h <= 0 {
		return 0
	}
	x = min(max(x, 0), w-1)
	y = min(max(y, 0), h-1)
	return img.Pix[img.PixOffset(img.Rect.Min.X+x, img.Rect.Min.Y+y)]
}

func bilinear(img *image.Gray, x, y float64) float64 {
	x0, y0 := int(math.Floor(x)), int(math.Floor(y))
	fx, fy := x-float64(x0), y-float64(y0)
	p00 := float64(grayAt(img, x0, y0))
	p10 := float64(grayAt(img, x0+1, y0))
	p01 := float64(grayAt(img, x0, y0+1))
	p11 := float64(grayAt(img, x0+1, y0+1))
	return p00*(1-fx)*(1-fy) + p10*fx*(1-fy) + p01*(1-fx)*fy + p11*fx*fy
}

func gaussianKernel(radius float64) []float64 {
	half := int(math.Ceil(radius * 3))
	if half < 1 {
		half = 1
	}
	kernel := make([]float64, 2*half+1)
	sum := 0.0
	for i := range kernel {
		d := float64(i - half)
		kernel[i] = math.Exp(-d * d / (2 * radius * radius))
		sum += kernel[i]
	}
	for i := range kernel {
		kernel[i] /= sum
	}
	return kernel
}

func clampByte(v float64) byte {
	switch {
	case v <= 0:
		return 0
	case v >= 255:
		return 255
	default:
		return byte(v + 0.5)
	}
}
