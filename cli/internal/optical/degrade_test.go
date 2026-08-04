package optical

import (
	"bytes"
	"fmt"
	"image"
	"math/rand"
	"testing"

	"dhow/cli/internal/ffi"
)

// These tests are the redefined gate for Phase 37. The phase pack asks for
// recorded video fixtures at three quality levels; there is no camera here, so
// the substitute is the rendering the screen would actually show with each of
// a camera's effects applied at a measured strength.
//
// Every test below reports the strength at which detection stopped working
// rather than only asserting that it worked somewhere. The threshold is what a
// future change can regress against; "it decoded" is not.

// frameSized returns a payload the size of a real wire frame at a common
// configuration, so the symbol under test is the size the tool actually shows.
func frameSized(t *testing.T, version int, ecc byte) []byte {
	t.Helper()
	capacity, err := ffi.QRCapacity(version, ecc)
	if err != nil {
		t.Fatalf("capacity at version %d level %c: %v", version, ecc, err)
	}
	return samplePayload(int64(version)*31+int64(ecc), capacity)
}

// readsBack reports whether an image decodes to the expected payload.
func readsBack(img image.Image, want []byte) bool {
	got, err := Read(img)
	return err == nil && bytes.Equal(got.Data, want)
}

// findThreshold walks a strength upward and returns the last value that still
// decoded, along with the first that did not.
//
// Walking rather than bisecting: these are not guaranteed monotonic - a
// particular blur radius can happen to land module edges favourably - and a
// bisection over a non-monotonic predicate reports a boundary that is not one.
func findThreshold(steps int, apply func(int) image.Image, want []byte) (lastGood, firstBad int) {
	lastGood, firstBad = -1, -1
	for i := range steps {
		if readsBack(apply(i), want) {
			lastGood = i
		} else if firstBad < 0 {
			firstBad = i
		}
	}
	return lastGood, firstBad
}

// TestSurvivesDefocus is the most common capture fault: focus set once at one
// distance, and the screen at another.
func TestSurvivesDefocus(t *testing.T) {
	const scale = 8
	for _, version := range []int{5, 15, 25} {
		payload := frameSized(t, version, 'M')
		base := Grayscale(renderPayload(t, payload, version, 'M', scale))

		lastGood, _ := findThreshold(16, func(i int) image.Image {
			return Blur(base, float64(i)*0.5)
		}, payload)

		radius := float64(lastGood) * 0.5
		t.Logf("version %d at %d px/module: readable through a blur radius of %.1f px (%.2f modules)",
			version, scale, radius, radius/scale)
		// A blur radius of a third of a module is a visibly soft image. Below
		// that the detector is not doing its job.
		if radius < float64(scale)/3 {
			t.Errorf("version %d: blur tolerance %.1f px is under a third of a module (%d px)",
				version, radius, scale)
		}
	}
}

// TestSurvivesPerspective is the degradation the sampler's projective transform
// exists for, and the one an affine model cannot represent.
func TestSurvivesPerspective(t *testing.T) {
	const scale = 8
	for _, version := range []int{5, 15, 25} {
		payload := frameSized(t, version, 'M')
		base := Grayscale(renderPayload(t, payload, version, 'M', scale))

		lastGood, _ := findThreshold(9, func(i int) image.Image {
			tilt := float64(i) * 0.03
			return Perspective(base, tilt, tilt/2)
		}, payload)

		tilt := float64(lastGood) * 0.03
		t.Logf("version %d: readable with the far edge shrunk by %.0f%%", version, tilt*100)
		// Six per cent is roughly fifteen degrees off the screen's normal,
		// which is where a camera on a tripod beside a standing operator sits.
		if tilt < 0.06 {
			t.Errorf("version %d: perspective tolerance %.0f%% is below a plausible camera angle",
				version, tilt*100)
		}
	}
}

// TestSurvivesRotation checks the detector is rotation invariant, which is what
// the finder patterns' ratio is for. The corners swap roles as the image turns
// and the ordering logic has to keep up.
func TestSurvivesRotation(t *testing.T) {
	payload := frameSized(t, 10, 'M')
	base := Grayscale(renderPayload(t, payload, 10, 'M', 8))

	// A wider canvas, so a rotated symbol does not run off the frame.
	canvas := image.NewGray(image.Rect(0, 0, base.Rect.Dx()*3/2, base.Rect.Dy()*3/2))
	for i := range canvas.Pix {
		canvas.Pix[i] = 0xFF
	}
	offX := (canvas.Rect.Dx() - base.Rect.Dx()) / 2
	offY := (canvas.Rect.Dy() - base.Rect.Dy()) / 2
	for y := range base.Rect.Dy() {
		for x := range base.Rect.Dx() {
			canvas.Pix[(y+offY)*canvas.Stride+x+offX] = grayAt(base, x, y)
		}
	}

	failures := 0
	for degrees := 0; degrees < 360; degrees += 15 {
		if !readsBack(Rotate(canvas, float64(degrees), 0xFF), payload) {
			t.Errorf("a symbol rotated by %d degrees did not read", degrees)
			failures++
		}
	}
	if failures == 0 {
		t.Logf("readable at all 24 rotations from 0 to 345 degrees")
	}
}

// TestSurvivesMotionBlur models a hand-held camera moving during the exposure.
// It is directional, which is a different problem from defocus: it destroys the
// module grid along one axis and leaves the other intact.
func TestSurvivesMotionBlur(t *testing.T) {
	const scale = 8
	payload := frameSized(t, 12, 'M')
	base := Grayscale(renderPayload(t, payload, 12, 'M', scale))

	for _, angle := range []float64{0, 30, 90} {
		lastGood, _ := findThreshold(14, func(i int) image.Image {
			return MotionBlur(base, float64(i), angle)
		}, payload)
		t.Logf("motion at %.0f degrees: readable through a smear of %d px (%.2f modules)",
			angle, lastGood, float64(lastGood)/scale)
		if lastGood < scale/2 {
			t.Errorf("motion at %.0f degrees: tolerated only %d px, under half a module",
				angle, lastGood)
		}
	}
}

// TestSurvivesOcclusion covers the thing that actually interrupts a transfer: a
// hand, a cup, an operator walking past. Error correction has to survive it as
// a burst rather than as scattered damage, which is what the block
// interleaving is for.
func TestSurvivesOcclusion(t *testing.T) {
	const scale = 6
	rng := rand.New(rand.NewSource(9))

	for _, level := range []byte{'M', 'Q', 'H'} {
		payload := frameSized(t, 12, level)
		base := Grayscale(renderPayload(t, payload, 12, level, scale))

		// Twenty independent placements per fraction: where the block lands
		// matters far more than how big it is. A patch over a finder pattern
		// ends detection outright at any size, and one in the middle of the
		// data area is what error correction is for.
		best := 0.0
		for step := 1; step <= 12; step++ {
			fraction := float64(step) * 0.01
			survived := 0
			for range 20 {
				if readsBack(Occlude(base, fraction, 0, rng), payload) {
					survived++
				}
			}
			if survived >= 15 {
				best = fraction
			}
		}
		t.Logf("level %c: three quarters of placements survived an opaque patch over %.0f%% of the frame",
			level, best*100)
		if best < 0.02 {
			t.Errorf("level %c: survived only %.0f%% occlusion", level, best*100)
		}
	}
}

// TestSurvivesPoorLighting is what the local binarizer exists for. A vignette
// moves the boundary between dark and light across the frame without changing
// anything about the symbol, and a single global threshold loses a corner to it.
func TestSurvivesPoorLighting(t *testing.T) {
	payload := frameSized(t, 12, 'M')
	base := Grayscale(renderPayload(t, payload, 12, 'M', 8))

	lastGood, _ := findThreshold(10, func(i int) image.Image {
		return Vignette(base, float64(i)*0.1)
	}, payload)
	t.Logf("readable with the corners darkened by %.0f%%", float64(lastGood)*10)
	if lastGood < 5 {
		t.Errorf("vignette tolerance %.0f%% is below what a lens does on its own",
			float64(lastGood)*10)
	}

	// Glare: the whole range compressed towards mid grey.
	//
	// Forty per cent of full range is about a hundred grey levels between a
	// module and its neighbour, which is a visibly washed-out picture and
	// still a long way from unreadable by eye. Below that the binarizer loses
	// it, and the reason is the smoothing pass: a symbol is surrounded by a
	// quiet zone whose blocks have no contrast to measure, and their inferred
	// thresholds are averaged into the ones at the symbol's edge. Recorded
	// rather than tuned away, because both attempts to tune it traded away
	// more defocus tolerance than they bought in contrast.
	worst := 1.0
	for i := 10; i >= 1; i-- {
		scale := float64(i) * 0.1
		if readsBack(Contrast(base, scale, 0), payload) {
			worst = scale
		}
	}
	t.Logf("readable with contrast compressed to %.0f%% of full range", worst*100)
	if worst > 0.4 {
		t.Errorf("needed %.0f%% of full contrast, worse than the recorded limit of 40%%", worst*100)
	}
}

// TestSurvivesSensorNoise models a dark room, where noise rises steeply.
func TestSurvivesSensorNoise(t *testing.T) {
	rng := rand.New(rand.NewSource(17))
	payload := frameSized(t, 12, 'Q')
	base := Grayscale(renderPayload(t, payload, 12, 'Q', 8))

	best := 0.0
	for _, sigma := range []float64{5, 10, 20, 30, 40, 50, 60, 80} {
		survived := 0
		for range 5 {
			if readsBack(Noise(base, sigma, rng), payload) {
				survived++
			}
		}
		if survived == 5 {
			best = sigma
		}
	}
	t.Logf("readable at a noise standard deviation of %.0f grey levels", best)
	if best < 20 {
		t.Errorf("noise tolerance of %.0f grey levels is below a dim room", best)
	}
}

// TestResolutionLimit finds how few camera pixels per module still decode,
// which is the number that converts a screen size into a working distance.
func TestResolutionLimit(t *testing.T) {
	for _, version := range []int{5, 15, 25, 40} {
		payload := frameSized(t, version, 'M')
		// Rendered large, then shrunk, so the downsampling averages the way a
		// sensor does rather than picking one pixel per module.
		base := Grayscale(renderPayload(t, payload, version, 'M', 24))

		limit := 0
		for factor := 1; factor <= 20; factor++ {
			if readsBack(Downsample(base, factor), payload) {
				limit = factor
			}
		}
		t.Logf("version %d: readable down to %.1f camera pixels per module",
			version, 24/float64(limit))
		if 24/float64(limit) > 4 {
			t.Errorf("version %d needs %.1f pixels per module, which is a very close camera",
				version, 24/float64(limit))
		}
	}
}

// TestSurvivesEverythingAtOnce is the realistic case, and it is the test that
// produced this phase's most useful number.
//
// A real capture is not blurred or skewed or noisy; it is all of them at once.
// Each effect below is individually well inside the tolerances the tests above
// measured - a blur radius of 0.15 modules against a limit near 0.5, a smear of
// 0.3 modules against 1.6, four per cent of perspective against twelve - and
// the combination is far harsher than any of them. It bites larger versions
// first, because a larger version has more modules across the same picture and
// therefore fewer camera pixels holding each one.
//
// Two things are asserted. Small versions have to stay comfortably readable,
// because that is the configuration an operator will be told to use. And no
// capture at any version may ever decode to the wrong bytes: a frame that fails
// costs one more showing of it, and a frame that decodes wrongly is handed to
// the frame parser with only the CRC and the session MAC behind it.
func TestSurvivesEverythingAtOnce(t *testing.T) {
	rng := rand.New(rand.NewSource(2026))
	const trials = 20

	for _, version := range []int{5, 12, 20} {
		for _, level := range []byte{'M', 'Q'} {
			payload := frameSized(t, version, level)
			base := Grayscale(renderPayload(t, payload, version, level, 10))

			decoded, wrong := 0, 0
			for range trials {
				img := Perspective(base, 0.04, 0.02)
				img = Rotate(img, rng.Float64()*10-5, 0xFF)
				img = Blur(img, 1.5)
				img = MotionBlur(img, 3, rng.Float64()*180)
				img = Vignette(img, 0.35)
				img = Contrast(img, 0.55, -10)
				img = Noise(img, 12, rng)

				got, err := Read(img)
				switch {
				case err != nil:
				case bytes.Equal(got.Data, payload):
					decoded++
				default:
					wrong++
				}
			}

			name := fmt.Sprintf("version %d level %c", version, level)
			t.Logf("%s: %d of %d captures decoded, %d wrong", name, decoded, trials, wrong)
			if wrong != 0 {
				t.Errorf("%s: %d captures decoded to the wrong bytes", name, wrong)
			}
			// Versions up to 12 are what `docs/OPERATIONS.md` recommends and
			// have to stay comfortably readable under this. Above that the
			// rate falls off rather than stopping: the sender loops the
			// stream, so a lower rate is a slower transfer and not a failed
			// one. Measured at 10 pixels per module on the run these floors
			// came from: 80% and 65% at version 5, 60% and 45% at version 12,
			// 10% and 15% at version 20 for levels M and Q respectively, and
			// nothing at all at version 25. That falloff is where the
			// recommendation to stay at or below version 12 comes from.
			floor := trials / 10
			if version <= 12 {
				floor = trials * 2 / 5
			}
			if decoded < floor {
				t.Errorf("%s: only %d of %d decoded, floor is %d", name, decoded, trials, floor)
			}
		}
	}
}
