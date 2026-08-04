package qr

import "testing"

// TestFormatBitsRoundTrip checks the two-bit encoding of an error-correction
// level and its inverse agree.
//
// The specification's ordering of the levels in its block-structure tables is
// not the ordering it writes into the format information, and the two are
// deliberately different: the format bits are arranged so a single bit error is
// less likely to turn one level into its neighbour. Two mappings written from
// the same table by hand is exactly the shape of a transcription error, and a
// wrong one would decode a symbol under the wrong block layout - which fails
// error correction rather than producing wrong data, but fails it for a reason
// nobody would find.
func TestFormatBitsRoundTrip(t *testing.T) {
	seen := map[int]Level{}
	for _, level := range []Level{Low, Medium, Quartile, High} {
		bits := level.formatBits()
		if bits < 0 || bits > 3 {
			t.Fatalf("level %s encodes to %d, which is not two bits", level, bits)
		}
		if other, clash := seen[bits]; clash {
			t.Fatalf("levels %s and %s both encode to %d", level, other, bits)
		}
		seen[bits] = level

		back, ok := levelFromFormatBits(bits)
		if !ok || back != level {
			t.Errorf("level %s encoded to %d and decoded back to %s (ok=%v)",
				level, bits, back, ok)
		}
	}
	if len(seen) != 4 {
		t.Errorf("four levels produced %d distinct encodings", len(seen))
	}
}

// TestAlignmentPatternPositions checks the derived positions against the
// specification's published values for the versions where a mistake in the
// spacing formula is most likely to hide.
//
// Version 1 has none. Version 7 is the first with three, which is where a wrong
// formula first produces a wrong middle position rather than only endpoints -
// and is exactly where one did: it put version 7's middle pattern at 28 instead
// of 22 and left versions 1 to 6 passing. Version 32 is a special case in the
// specification rather than an artefact of rounding.
func TestAlignmentPatternPositions(t *testing.T) {
	cases := map[int][]int{
		1:  nil,
		2:  {6, 18},
		6:  {6, 34},
		7:  {6, 22, 38},
		14: {6, 26, 46, 66},
		21: {6, 28, 50, 72, 94},
		32: {6, 34, 60, 86, 112, 138},
		40: {6, 30, 58, 86, 114, 142, 170},
	}
	for version, want := range cases {
		got := alignmentPatternPositions(version)
		if len(got) != len(want) {
			t.Errorf("version %d: got %v, want %v", version, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("version %d: got %v, want %v", version, got, want)
				break
			}
		}
	}
}

// TestVersionForSizeRejectsImpossibleSizes checks the inverse of the module
// count, which is how a decoder establishes the version. Everything that is not
// four modules more than the last valid size has to be refused.
func TestVersionForSizeRejectsImpossibleSizes(t *testing.T) {
	for version := MinVersion; version <= MaxVersion; version++ {
		size := sizeForVersion(version)
		got, ok := versionForSize(size)
		if !ok || got != version {
			t.Errorf("size %d resolved to version %d (ok=%v), want %d", size, got, ok, version)
		}
		for _, offset := range []int{-3, -2, -1, 1, 2, 3} {
			if _, ok := versionForSize(size + offset); ok {
				t.Errorf("size %d was accepted as a QR symbol size", size+offset)
			}
		}
	}
	for _, size := range []int{-1, 0, 1, 20, 178, 181, 1 << 20} {
		if _, ok := versionForSize(size); ok {
			t.Errorf("size %d was accepted as a QR symbol size", size)
		}
	}
}
