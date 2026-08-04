package qr

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"dhow/cli/internal/ffi"
)

// encodeGrid renders data with the encoder dhow ships and hands back the grid
// a perfect capture would produce.
//
// Every test in this file goes through the real encoder rather than a fixture.
// A decoder tested against its own idea of what an encoder does is a decoder
// tested against itself, which is the failure Phase 34 found in the conformance
// suite and is worth not repeating.
func encodeGrid(t *testing.T, data []byte, version int, ecc byte) *Grid {
	t.Helper()
	code, err := ffi.EncodeQR(data, version, ecc)
	if err != nil {
		t.Fatalf("encoding %d bytes at version %d level %c: %v", len(data), version, ecc, err)
	}
	g, err := GridFromModules(code.Size, code.Modules)
	if err != nil {
		t.Fatalf("building a grid from the encoder's modules: %v", err)
	}
	return g
}

var levels = []struct {
	letter byte
	level  Level
}{{'L', Low}, {'M', Medium}, {'Q', Quartile}, {'H', High}}

// TestBlockLayoutMatchesEncoderCapacity checks the two transcribed tables
// against the encoder at every version and level.
//
// The encoder reports its capacity by binary-searching itself, so it cannot
// disagree with what it will actually accept. The layout derived here predicts
// the same number by a completely different route: two tables and the module
// geometry. A single wrong digit in either table moves one of the 160 answers.
func TestBlockLayoutMatchesEncoderCapacity(t *testing.T) {
	for version := MinVersion; version <= MaxVersion; version++ {
		for _, l := range levels {
			want, err := ffi.QRCapacity(version, l.letter)
			if err != nil {
				t.Fatalf("version %d level %s: encoder capacity: %v", version, l.level, err)
			}
			lay, ok := blockLayout(version, l.level)
			if !ok {
				t.Fatalf("version %d level %s: no layout", version, l.level)
			}
			// A byte-mode segment spends four bits on the mode and a
			// version-dependent count field before any payload.
			got := (lay.dataCodewords*8 - 4 - charCountBits(version)) / 8
			if got != want {
				t.Errorf("version %d level %s: layout predicts %d bytes, encoder accepts %d",
					version, l.level, got, want)
			}
		}
	}
}

// TestRoundTripEveryVersionAndLevel decodes a full-capacity symbol at all 160
// configurations.
//
// Full capacity on purpose: a short payload leaves the rest of the symbol as
// padding, and padding decodes correctly under a block layout that is wrong
// about where the last block ends. Filling the symbol is what makes the final
// block's length matter.
func TestRoundTripEveryVersionAndLevel(t *testing.T) {
	rng := rand.New(rand.NewSource(20260804))

	for version := MinVersion; version <= MaxVersion; version++ {
		for _, l := range levels {
			capacity, err := ffi.QRCapacity(version, l.letter)
			if err != nil {
				t.Fatalf("version %d level %s: %v", version, l.level, err)
			}
			payload := make([]byte, capacity)
			if _, err := rng.Read(payload); err != nil {
				t.Fatalf("drawing a payload: %v", err)
			}

			got, err := Decode(encodeGrid(t, payload, version, l.letter))
			if err != nil {
				t.Fatalf("version %d level %s: decode: %v", version, l.level, err)
			}
			if !bytes.Equal(got.Data, payload) {
				t.Fatalf("version %d level %s: recovered %d bytes, sent %d",
					version, l.level, len(got.Data), len(payload))
			}
			if got.Version != version {
				t.Errorf("version %d level %s: decoded as version %d", version, l.level, got.Version)
			}
			if got.Level != l.level {
				t.Errorf("version %d level %s: decoded as level %s", version, l.level, got.Level)
			}
			if got.Mask < 0 || got.Mask > 7 {
				t.Errorf("version %d level %s: mask %d out of range", version, l.level, got.Mask)
			}
		}
	}
}

// TestRoundTripShortPayloads covers the padding path, which full-capacity
// symbols never reach: after the segment ends the encoder writes a terminator
// and then alternating pad bytes, and a decoder that reads past the terminator
// finds them.
func TestRoundTripShortPayloads(t *testing.T) {
	for _, n := range []int{1, 2, 7, 8, 9, 15, 16, 17, 100} {
		payload := bytes.Repeat([]byte{0xA5}, n)
		for _, version := range []int{5, 12, 30} {
			capacity, err := ffi.QRCapacity(version, 'M')
			if err != nil {
				t.Fatalf("version %d capacity: %v", version, err)
			}
			if n > capacity {
				continue
			}
			got, err := Decode(encodeGrid(t, payload, version, 'M'))
			if err != nil {
				t.Fatalf("%d bytes at version %d: %v", n, version, err)
			}
			if !bytes.Equal(got.Data, payload) {
				t.Errorf("%d bytes at version %d: recovered %d bytes", n, version, len(got.Data))
			}
		}
	}
}

// TestErrorCorrectionRecoversDamagedModules flips modules at random and checks
// the symbol still decodes.
//
// The damage budget is deliberately below the theoretical limit. Error
// correction works on whole bytes, and a scattered flip usually lands in a
// fresh byte, so the number of modules a symbol survives is close to the number
// of correctable bytes rather than a multiple of it. The point of the test is
// that correction happens at all and that it is not accidentally disabled, not
// to find the exact cliff.
func TestErrorCorrectionRecoversDamagedModules(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	payload := bytes.Repeat([]byte("dhow frame payload "), 20)

	for _, l := range levels {
		version := 20
		lay, ok := blockLayout(version, l.level)
		if !ok {
			t.Fatalf("no layout for version %d level %s", version, l.level)
		}
		// Half the correctable bytes, so a flip landing twice in one byte
		// still leaves headroom.
		budget := lay.eccLen / 2 * lay.numBlocks / 2

		g := encodeGrid(t, payload, version, l.letter)
		fn := functionModules(version)
		flipped := 0
		for flipped < budget {
			x, y := rng.Intn(g.Size), rng.Intn(g.Size)
			if fn[y*g.Size+x] {
				continue
			}
			g.Set(x, y, !g.At(x, y))
			flipped++
		}

		got, err := Decode(g)
		if err != nil {
			t.Fatalf("level %s: %d flipped modules defeated decoding: %v", l.level, flipped, err)
		}
		if !bytes.Equal(got.Data, payload) {
			t.Errorf("level %s: %d flipped modules produced wrong data", l.level, flipped)
		}
	}
}

// TestOverwhelmingDamageIsRejected checks the decoder fails rather than
// inventing data when a symbol is past saving.
//
// This is the case that matters most. A frame that fails to decode is normal
// and costs one more showing of it; a frame that decodes to plausible-looking
// wrong bytes would be handed to the frame parser, and only the CRC and the
// session MAC stand behind it.
func TestOverwhelmingDamageIsRejected(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	payload := bytes.Repeat([]byte{0x5A}, 400)

	rejected, wrong, accepted := 0, 0, 0
	for trial := range 40 {
		g := encodeGrid(t, payload, 15, 'M')
		fn := functionModules(15)
		// A quarter of the data area, far past any level's correcting radius.
		for i := range g.Dark {
			x, y := i%g.Size, i/g.Size
			if fn[i] || rng.Intn(4) != 0 {
				continue
			}
			g.Set(x, y, rng.Intn(2) == 0)
		}

		got, err := Decode(g)
		switch {
		case err != nil:
			rejected++
		case bytes.Equal(got.Data, payload):
			accepted++
		default:
			wrong++
			if wrong == 1 {
				t.Errorf("trial %d: heavily damaged symbol decoded to %d wrong bytes",
					trial, len(got.Data))
			}
		}
	}
	t.Logf("40 heavily damaged symbols: %d rejected, %d recovered, %d silently wrong",
		rejected, accepted, wrong)
	if wrong != 0 {
		t.Errorf("%d symbols decoded to the wrong bytes without an error", wrong)
	}
	if rejected == 0 {
		t.Errorf("no symbol was rejected; the damage was not severe enough to test anything")
	}
}

// TestMalformedGridsAreRejected feeds the decoder input no encoder produced.
//
// None of these may panic. The optical channel is public, so a grid can be
// anything at all, including three finder patterns painted on a wall.
func TestMalformedGridsAreRejected(t *testing.T) {
	cases := []struct {
		name string
		grid *Grid
		want error
	}{
		{"nil", nil, ErrNotAQRCode},
		{"zero size", &Grid{Size: 0}, ErrNotAQRCode},
		{"negative size", &Grid{Size: -21, Dark: nil}, ErrNotAQRCode},
		{"not a version size", NewGrid(22), ErrNotAQRCode},
		{"too small", NewGrid(9), ErrNotAQRCode},
		{"too large", NewGrid(181), ErrNotAQRCode},
		{"short module slice", &Grid{Size: 21, Dark: make([]bool, 10)}, ErrNotAQRCode},
		{"long module slice", &Grid{Size: 21, Dark: make([]bool, 1000)}, ErrNotAQRCode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.grid)
			if !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestAllLightAndAllDarkGrids checks the two degenerate captures a camera
// actually produces: a lens cap and a blown-out exposure.
func TestAllLightAndAllDarkGrids(t *testing.T) {
	for _, size := range []int{21, 57, 177} {
		for _, dark := range []bool{false, true} {
			g := NewGrid(size)
			for i := range g.Dark {
				g.Dark[i] = dark
			}
			// The only requirement is that it does not panic and does not
			// claim success with data in it.
			got, err := Decode(g)
			if err == nil && len(got.Data) > 0 {
				t.Errorf("size %d dark=%v: a blank grid decoded to %d bytes",
					size, dark, len(got.Data))
			}
		}
	}
}

// TestRandomGridsNeverPanic is the blunt instrument: noise in, no crash out.
func TestRandomGridsNeverPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(1729))
	for version := MinVersion; version <= MaxVersion; version += 7 {
		size := sizeForVersion(version)
		for range 200 {
			g := NewGrid(size)
			for i := range g.Dark {
				g.Dark[i] = rng.Intn(2) == 0
			}
			if got, err := Decode(g); err == nil {
				// Random noise decoding successfully is astronomically
				// unlikely but not impossible; what must never happen is a
				// declared length larger than the symbol can hold.
				lay, _ := blockLayout(version, got.Level)
				if len(got.Data) > lay.dataCodewords {
					t.Fatalf("version %d: decoded %d bytes from a symbol holding %d",
						version, len(got.Data), lay.dataCodewords)
				}
			}
		}
	}
}

// TestCalibrationPatternRoundTrips decodes the pattern the display loop shows
// before a transfer, which is the first thing a receiver ever sees.
func TestCalibrationPatternRoundTrips(t *testing.T) {
	payload := []byte("DHOW-CALIBRATION session=1A2B-3C4D-5E6F-7089")
	got, err := Decode(encodeGrid(t, payload, 0, 'M'))
	if err != nil {
		t.Fatalf("decoding the calibration pattern: %v", err)
	}
	if !bytes.Equal(got.Data, payload) {
		t.Errorf("recovered %q, sent %q", got.Data, payload)
	}
}
