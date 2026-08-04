// Package qr decodes QR symbols back into the bytes that were encoded into
// them.
//
// Dhow renders every wire frame as one QR code and shows it on a screen. This
// package is the other half of that: given a grid of modules sampled from a
// captured image, it recovers the frame. `internal/optical` produces the grid
// from an image; this package takes it from there.
//
// # Adversarial input
//
// Everything here parses input that arrived over an optical channel the threat
// model treats as fully public and fully hostile. A grid can be any size, can
// declare any version, can claim a segment longer than the symbol holds, and
// can be pure noise that happens to have three finder patterns in it. Every
// path returns a typed error; none panics, indexes out of range, or allocates
// on an attacker-chosen length before that length has been checked against
// what the grid actually holds.
//
// Nothing this package returns is trusted. The caller checks the frame's
// CRC32C before the bytes cross the FFI, and the Rust core then checks the
// frame's session MAC before they reach the decoder. This layer's job is to
// recover bytes, not to vouch for them.
package qr

import (
	"errors"
	"fmt"
)

// Errors a caller may want to distinguish. Everything else is a wrapped
// description.
var (
	// ErrNotAQRCode reports a grid whose size is not one a QR symbol can have.
	ErrNotAQRCode = errors.New("qr: grid is not a QR symbol size")
	// ErrFormatInfo reports format information too damaged to read. Both
	// copies of it are protected by their own error-correcting code, so this
	// means the corners of the symbol were unreadable.
	ErrFormatInfo = errors.New("qr: format information is unreadable")
	// ErrUnsupportedMode reports a segment encoding other than byte mode.
	// Dhow renders binary frames and nothing else, so anything else in the
	// stream did not come from a dhow sender.
	ErrUnsupportedMode = errors.New("qr: only byte-mode segments are supported")
	// ErrTruncated reports a segment claiming more data than the symbol holds.
	ErrTruncated = errors.New("qr: segment declares more data than the symbol holds")
)

// Result is what a successful decode recovered, with the parameters it was
// recovered under.
//
// The parameters are returned rather than discarded because they are the first
// thing an operator diagnosing a bad capture wants: a symbol that decodes at
// the wrong version is a framing problem, and one whose level disagrees with
// what the sender was told to use is a configuration problem.
type Result struct {
	// Data is the recovered payload.
	Data []byte
	// Version is the QR version, 1 to 40.
	Version int
	// Level is the error-correction level read from the format information.
	Level Level
	// Mask is the data mask pattern, 0 to 7.
	Mask int
}

// Decode recovers the payload from a sampled module grid.
func Decode(g *Grid) (Result, error) {
	if g == nil || len(g.Dark) != g.Size*g.Size {
		return Result{}, ErrNotAQRCode
	}
	version, ok := versionForSize(g.Size)
	if !ok {
		return Result{}, fmt.Errorf("%w: %d modules per side", ErrNotAQRCode, g.Size)
	}

	level, mask, err := readFormatInfo(g)
	if err != nil {
		return Result{}, err
	}

	lay, ok := blockLayout(version, level)
	if !ok {
		return Result{}, fmt.Errorf("%w: version %d level %s", ErrNotAQRCode, version, level)
	}

	codewords := readCodewords(g, version, mask, lay.totalCodewords)
	data, err := deinterleaveAndCorrect(codewords, lay)
	if err != nil {
		return Result{}, err
	}

	payload, err := parseSegments(data, version)
	if err != nil {
		return Result{}, err
	}

	return Result{Data: payload, Version: version, Level: level, Mask: mask}, nil
}

// --- format information ---

// formatMask is the constant the specification XORs the format bits with, so
// that an all-light symbol does not read as a valid format.
const formatMask = 0x5412

// formatBitPositions returns where the two copies of the format information
// live, indexed by bit number.
//
// The information is stored twice, in opposite corners, because the corners of
// a symbol are the parts a camera is most likely to lose to framing or
// distortion, and losing the format means losing the whole symbol regardless of
// how well the data area was captured.
func formatBitPositions(size int) (first, second [15][2]int) {
	for i := range 6 {
		first[i] = [2]int{8, i}
	}
	first[6] = [2]int{8, 7}
	first[7] = [2]int{8, 8}
	first[8] = [2]int{7, 8}
	for i := 9; i < 15; i++ {
		first[i] = [2]int{14 - i, 8}
	}

	for i := range 8 {
		second[i] = [2]int{size - 1 - i, 8}
	}
	for i := 8; i < 15; i++ {
		second[i] = [2]int{8, size - 15 + i}
	}
	return first, second
}

// readFormatInfo recovers the error-correction level and mask pattern.
func readFormatInfo(g *Grid) (Level, int, error) {
	first, second := formatBitPositions(g.Size)

	var bestBits, bestDistance = -1, 16
	for _, positions := range []*[15][2]int{&first, &second} {
		raw := 0
		for i, p := range positions {
			if g.At(p[0], p[1]) {
				raw |= 1 << i
			}
		}
		bits, distance := nearestFormat(raw ^ formatMask)
		if distance < bestDistance {
			bestBits, bestDistance = bits, distance
		}
	}

	// Three is the code's correcting radius. Accepting a fourth bit of damage
	// would mean guessing between two equally distant formats, and decoding
	// the whole symbol under the wrong mask produces bytes that look like data.
	if bestBits < 0 || bestDistance > 3 {
		return 0, 0, ErrFormatInfo
	}

	level, ok := levelFromFormatBits(bestBits >> 3)
	if !ok {
		return 0, 0, ErrFormatInfo
	}
	return level, bestBits & 7, nil
}

// nearestFormat finds the valid five-bit format closest to what was read, and
// how far away it was.
//
// Exhaustive over all thirty-two possibilities rather than an algebraic
// decode: thirty-two is small, the exhaustive version cannot be subtly wrong,
// and it runs once per frame rather than once per byte.
func nearestFormat(raw int) (bits, distance int) {
	bits, distance = -1, 16
	for candidate := range 32 {
		d := hammingDistance(raw, formatCodeword(candidate))
		if d < distance {
			bits, distance = candidate, d
		}
	}
	return bits, distance
}

// formatCodeword returns the fifteen-bit BCH codeword for a five-bit format.
func formatCodeword(data int) int {
	rem := data
	for range 10 {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	return data<<10 | rem
}

func hammingDistance(a, b int) int {
	d, x := 0, a^b
	for x != 0 {
		d += x & 1
		x >>= 1
	}
	return d
}

// --- function patterns ---

// functionModules marks every module that carries structure rather than data:
// the finder patterns and their separators, the timing patterns, the alignment
// patterns, the format information, the version information, and the single
// dark module beside the lower-left finder.
//
// The data-reading walk skips exactly these, so it has to agree with the
// encoder module for module. It is built rather than tabulated for the same
// reason the block layout is derived: a table of function positions for forty
// versions is a transcription risk with no upside.
func functionModules(version int) []bool {
	size := sizeForVersion(version)
	fn := make([]bool, size*size)
	mark := func(x, y int) {
		if x >= 0 && y >= 0 && x < size && y < size {
			fn[y*size+x] = true
		}
	}

	// Timing patterns run the full width and height; the finder regions
	// overwrite their ends.
	for i := range size {
		mark(6, i)
		mark(i, 6)
	}

	// Finder patterns, taken as nine by nine so the separator ring around each
	// is included.
	for _, c := range [3][2]int{{3, 3}, {size - 4, 3}, {3, size - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				mark(c[0]+dx, c[1]+dy)
			}
		}
	}

	// Alignment patterns at every crossing of the position list except the
	// three corners already occupied by finders.
	positions := alignmentPatternPositions(version)
	n := len(positions)
	for i := range n {
		for j := range n {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					mark(positions[i]+dx, positions[j]+dy)
				}
			}
		}
	}

	first, second := formatBitPositions(size)
	for _, p := range first {
		mark(p[0], p[1])
	}
	for _, p := range second {
		mark(p[0], p[1])
	}
	mark(8, size-8) // the always-dark module

	if version >= 7 {
		for i := range 18 {
			a, b := size-11+i%3, i/3
			mark(a, b)
			mark(b, a)
		}
	}

	return fn
}

// maskBit reports whether the mask inverts the module at (x, y).
func maskBit(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	case 7:
		return ((x+y)%2+x*y%3)%2 == 0
	default:
		return false
	}
}

// readCodewords walks the data modules in the specification's order and
// assembles them into bytes, undoing the mask as it goes.
//
// The walk is two modules wide and alternates direction on each pair of
// columns, which is how a symbol keeps consecutive codewords physically
// adjacent: a smear across the image then damages a run of codewords that the
// block interleaving has already spread across different blocks.
func readCodewords(g *Grid, version, mask, total int) []byte {
	size := sizeForVersion(version)
	fn := functionModules(version)

	out := make([]byte, 0, total)
	var current byte
	bits := 0

	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			// Column six is a timing pattern, so the pairs step over it.
			right = 5
		}
		for vert := range size {
			for j := range 2 {
				x := right - j
				upward := (right+1)&2 == 0
				y := vert
				if upward {
					y = size - 1 - vert
				}
				if fn[y*size+x] || len(out) >= total {
					continue
				}
				dark := g.At(x, y)
				if maskBit(mask, x, y) {
					dark = !dark
				}
				current <<= 1
				if dark {
					current |= 1
				}
				bits++
				if bits == 8 {
					out = append(out, current)
					current, bits = 0, 0
				}
			}
		}
	}

	// A grid whose data area is smaller than the layout claims cannot happen
	// for a well-formed version, but the caller's `total` and the walk are
	// derived separately and a short read must not be silently padded.
	for len(out) < total {
		out = append(out, 0)
	}
	return out
}

// --- block structure ---

// deinterleaveAndCorrect undoes the interleaving that spreads each block across
// the symbol, then repairs each block.
func deinterleaveAndCorrect(codewords []byte, lay layout) ([]byte, error) {
	if len(codewords) < lay.totalCodewords {
		return nil, ErrUncorrectable
	}

	// Every block is held at the long length with a hole where a short block's
	// missing byte would be, which is how the encoder lays them out: the hole
	// keeps each block's error-correction bytes aligned with the others so the
	// interleave is a straight column-major walk.
	blocks := make([][]byte, lay.numBlocks)
	for i := range blocks {
		blocks[i] = make([]byte, lay.shortBlockLen+1)
	}

	k := 0
	for i := 0; i <= lay.shortBlockLen; i++ {
		for j := range lay.numBlocks {
			if i == lay.shortBlockDataLen && j < lay.numShortBlocks {
				continue
			}
			if k >= len(codewords) {
				return nil, ErrUncorrectable
			}
			blocks[j][i] = codewords[k]
			k++
		}
	}

	data := make([]byte, 0, lay.dataCodewords)
	for j, block := range blocks {
		dataLen := lay.shortBlockDataLen
		codeword := block
		if j < lay.numShortBlocks {
			// Close the hole: a short block's codeword is its data followed
			// directly by its error correction.
			codeword = make([]byte, 0, lay.shortBlockLen)
			codeword = append(codeword, block[:lay.shortBlockDataLen]...)
			codeword = append(codeword, block[lay.shortBlockDataLen+1:]...)
		} else {
			dataLen++
		}
		if err := correct(codeword, lay.eccLen); err != nil {
			return nil, fmt.Errorf("block %d: %w", j, err)
		}
		data = append(data, codeword[:dataLen]...)
	}
	return data, nil
}

// --- segment parsing ---

// bitReader reads big-endian bit fields out of the recovered data codewords.
type bitReader struct {
	data []byte
	pos  int // in bits
}

// remaining reports how many bits are left.
func (r *bitReader) remaining() int { return len(r.data)*8 - r.pos }

// read returns the next n bits, or reports that there are not that many.
func (r *bitReader) read(n int) (int, bool) {
	if n < 0 || n > 32 || r.remaining() < n {
		return 0, false
	}
	v := 0
	for range n {
		bit := (r.data[r.pos>>3] >> (7 - r.pos&7)) & 1
		v = v<<1 | int(bit)
		r.pos++
	}
	return v, true
}

// Segment mode indicators. Dhow only ever writes byte mode.
const (
	modeTerminator = 0x0
	modeByte       = 0x4
)

// modeName names a segment mode so a rejection says what was found rather than
// reporting an unnamed number. An operator seeing "alphanumeric" knows they are
// pointing the camera at somebody else's QR code; one seeing "0x2" does not.
func modeName(mode int) string {
	switch mode {
	case 0x1:
		return "numeric"
	case 0x2:
		return "alphanumeric"
	case 0x3:
		return "structured append"
	case 0x5:
		return "FNC1 first position"
	case 0x7:
		return "ECI"
	case 0x8:
		return "kanji"
	case 0x9:
		return "FNC1 second position"
	default:
		return "unassigned"
	}
}

// parseSegments walks the segment list and concatenates the byte-mode ones.
func parseSegments(data []byte, version int) ([]byte, error) {
	r := &bitReader{data: data}
	var out []byte

	for {
		// A symbol whose data is exhausted, or whose remaining bits are the
		// zero padding before a terminator that does not fit, ends here.
		if r.remaining() < 4 {
			return out, nil
		}
		mode, ok := r.read(4)
		if !ok {
			return out, nil
		}
		if mode == modeTerminator {
			return out, nil
		}
		if mode != modeByte {
			return nil, fmt.Errorf("%w: found %s (0x%x)", ErrUnsupportedMode, modeName(mode), mode)
		}

		countBits := charCountBits(version)
		count, ok := r.read(countBits)
		if !ok {
			return nil, fmt.Errorf("%w: character count field is truncated", ErrTruncated)
		}
		// Checked against what is actually left before anything is allocated,
		// so a symbol claiming sixty-five thousand bytes costs nothing.
		if count*8 > r.remaining() {
			return nil, fmt.Errorf("%w: %d bytes declared, %d bits left",
				ErrTruncated, count, r.remaining())
		}

		for range count {
			b, ok := r.read(8)
			if !ok {
				return nil, ErrTruncated
			}
			out = append(out, byte(b))
		}
	}
}
