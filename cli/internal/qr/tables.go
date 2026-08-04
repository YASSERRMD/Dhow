package qr

// The QR specification's two per-version tables, plus the arithmetic that
// derives everything else from them.
//
// # Why two tables and not five
//
// A decoder needs, for every version and error-correction level: how many
// blocks the codewords are split into, how long each block is, how many of
// those bytes are error correction, and where the alignment patterns sit.
// Printed references usually give all of that as one wide table of five
// columns per row, 160 rows long, and transcribing 800 numbers by hand is an
// invitation to a single wrong digit that breaks exactly one configuration.
//
// Only two of those columns are independent. The rest follow from the module
// geometry, which is arithmetic rather than data. So this file holds 328
// numbers instead of 800, and [blockLayout] computes the rest.
//
// Both tables are checked against the encoder this package decodes for, at
// every version and level, by `TestBlockLayoutMatchesEncoderCapacity`. A wrong
// digit there fails that test rather than one frame in production.

// Level is a QR error-correction level.
//
// The numbering is the specification's internal ordering (used to index the
// tables below), which is not the same as the two-bit value written into the
// format information. [Level.formatBits] converts.
type Level int

// The four error-correction levels, in the order the tables are indexed by.
const (
	Low Level = iota
	Medium
	Quartile
	High
)

// String returns the single-letter name operators use.
func (l Level) String() string {
	switch l {
	case Low:
		return "L"
	case Medium:
		return "M"
	case Quartile:
		return "Q"
	case High:
		return "H"
	default:
		return "?"
	}
}

// formatBits returns the two-bit encoding of the level used in format
// information, which is deliberately not the table ordering: the format bits
// are ordered so that a single bit error is less likely to turn one level into
// its neighbour.
func (l Level) formatBits() int {
	switch l {
	case Low:
		return 1
	case Medium:
		return 0
	case Quartile:
		return 3
	case High:
		return 2
	default:
		return -1
	}
}

// levelFromFormatBits inverts [Level.formatBits].
func levelFromFormatBits(b int) (Level, bool) {
	switch b {
	case 1:
		return Low, true
	case 0:
		return Medium, true
	case 3:
		return Quartile, true
	case 2:
		return High, true
	default:
		return 0, false
	}
}

// MinVersion and MaxVersion bound the QR versions this package handles.
const (
	MinVersion = 1
	MaxVersion = 40
)

// eccCodewordsPerBlock[level][version] is how many of each block's bytes are
// error correction. Index 0 of each row is unused so the version indexes
// directly.
var eccCodewordsPerBlock = [4][41]int{
	// L
	{0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	// M
	{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
	// Q
	{0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	// H
	{0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
}

// numErrorCorrectionBlocks[level][version] is how many blocks the codewords are
// split into. More blocks means a burst of damage is spread across several
// independent Reed-Solomon codewords instead of exhausting one.
var numErrorCorrectionBlocks = [4][41]int{
	// L
	{0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
	// M
	{0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
	// Q
	{0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
	// H
	{0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
}

// sizeForVersion returns the number of modules per side.
func sizeForVersion(version int) int {
	return version*4 + 17
}

// versionForSize inverts [sizeForVersion], reporting whether the size is one a
// QR code can have at all.
//
// This is how the version is established during decoding. Reading it from the
// version information block instead would be worse: versions 1 to 6 carry no
// version block, so the size has to be trusted for those anyway, and a decoder
// that trusts the size for small codes and a parity-protected field for large
// ones has two behaviours where one will do.
func versionForSize(size int) (int, bool) {
	if size < sizeForVersion(MinVersion) || size > sizeForVersion(MaxVersion) {
		return 0, false
	}
	if (size-17)%4 != 0 {
		return 0, false
	}
	return (size - 17) / 4, true
}

// rawDataModules returns the number of modules available for data and error
// correction at a version: the whole grid less every function pattern.
//
// Derived rather than tabulated. The subtractions are, in order: the finder
// patterns with their separators and the format information, the timing
// patterns, the alignment patterns and their overlap with the timing patterns,
// and the two version information blocks.
func rawDataModules(version int) int {
	result := (16*version + 128) * version // grid area less the three 8x8 finder regions
	result += 64
	if version >= 2 {
		numAlign := version/7 + 2
		// Each alignment pattern is 25 modules; those on the timing rows
		// overlap it, which is what the linear term corrects for.
		result -= (25*numAlign-10)*numAlign - 55
		if version >= 7 {
			result -= 36 // two 6x3 version information blocks
		}
	}
	return result
}

// alignmentPatternPositions returns the row and column centres of the alignment
// patterns. Every combination of two of them holds a pattern except the three
// that would land on a finder.
//
// Version 32 is a genuine special case in the specification rather than a
// rounding artefact: the general formula produces a spacing that does not
// divide the grid evenly there.
func alignmentPatternPositions(version int) []int {
	if version == 1 {
		return nil
	}
	numAlign := version/7 + 2
	step := 26
	if version != 32 {
		step = (version*4 + numAlign*2 + 1) / (numAlign*2 - 2) * 2
	}
	result := make([]int, numAlign)
	result[0] = 6
	for i, pos := numAlign-1, sizeForVersion(version)-7; i >= 1; i, pos = i-1, pos-step {
		result[i] = pos
	}
	return result
}

// layout describes how a version and level split their codewords into
// Reed-Solomon blocks.
//
// Blocks come in two lengths that differ by one byte. The short ones come
// first, which matters because the interleaving that spreads them across the
// grid has to skip a hole where the short blocks' missing byte would be.
type layout struct {
	// numBlocks is how many Reed-Solomon blocks the codewords form.
	numBlocks int
	// eccLen is how many error-correction bytes each block carries.
	eccLen int
	// shortBlockLen is the total length of a short block, data plus ecc.
	shortBlockLen int
	// shortBlockDataLen is the data length of a short block.
	shortBlockDataLen int
	// numShortBlocks is how many of the blocks are short.
	numShortBlocks int
	// totalCodewords is how many bytes the grid's data modules hold.
	totalCodewords int
	// dataCodewords is how many of those are payload rather than ecc.
	dataCodewords int
}

// blockLayout derives the block structure for a version and level.
func blockLayout(version int, level Level) (layout, bool) {
	if version < MinVersion || version > MaxVersion {
		return layout{}, false
	}
	if level < Low || level > High {
		return layout{}, false
	}

	numBlocks := numErrorCorrectionBlocks[level][version]
	eccLen := eccCodewordsPerBlock[level][version]
	total := rawDataModules(version) / 8

	shortLen := total / numBlocks
	return layout{
		numBlocks:         numBlocks,
		eccLen:            eccLen,
		shortBlockLen:     shortLen,
		shortBlockDataLen: shortLen - eccLen,
		numShortBlocks:    numBlocks - total%numBlocks,
		totalCodewords:    total,
		dataCodewords:     total - eccLen*numBlocks,
	}, true
}

// charCountBits returns the width of the character-count field for byte-mode
// segments, which widens once a version can hold more than 255 bytes.
func charCountBits(version int) int {
	if version <= 9 {
		return 8
	}
	return 16
}
