package optical

import (
	"errors"
	"fmt"
	"image"
	"math"

	"dhow/cli/internal/qr"
)

// Errors a caller may distinguish. Everything a capture does wrong ends at one
// of these, and an operator's next move differs for each: no finder patterns
// means the symbol is not in frame or not in focus, and a sampled symbol that
// will not decode means the framing is right and the picture is not good
// enough.
var (
	// ErrNoSymbol reports an image with no locatable QR symbol.
	ErrNoSymbol = errors.New("optical: no QR symbol found in the image")
	// ErrNotSampleable reports three located patterns that do not describe a
	// symbol of any valid size.
	ErrNotSampleable = errors.New("optical: located patterns do not form a QR symbol")
)

// Read finds the QR symbol in an image and decodes it.
//
// The two stages are separate on purpose. Locating gives an estimate of how
// many modules across the symbol is, derived from a measured module size, and
// that estimate can be one version out when the capture is poor. Rather than
// making the estimate more elaborate, Read tries the neighbouring sizes and
// lets the decoder arbitrate: a symbol sampled at the wrong dimension fails its
// format information or its error correction, and both of those are checks that
// already exist and are far stronger than any geometric confidence interval.
func Read(img image.Image) (qr.Result, error) {
	return ReadBitmap(Binarize(img))
}

// ReadBitmap is [Read] on an already-binarized image, so a caller that wants
// the binarization for diagnostics does not have to do it twice.
func ReadBitmap(b *Bitmap) (qr.Result, error) {
	grids, err := Sample(b)
	if err != nil {
		return qr.Result{}, err
	}
	var lastErr error
	for _, g := range grids {
		result, err := qr.Decode(g)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return qr.Result{}, fmt.Errorf("optical: symbol located but not readable: %w", lastErr)
}

// Sample locates the symbol and returns the module grids worth trying, most
// likely first.
func Sample(b *Bitmap) ([]*qr.Grid, error) {
	if b == nil || b.W <= 0 || b.H <= 0 {
		return nil, ErrNoSymbol
	}

	candidates := findFinderPatterns(b)
	trio, ok := selectThree(candidates)
	if !ok {
		return nil, fmt.Errorf("%w: %d finder pattern candidates", ErrNoSymbol, len(candidates))
	}
	topLeft, topRight, bottomLeft, _ := orderPatterns(&trio)

	// Measured along the symbol's own axes rather than taken from the scan
	// lines that found the patterns, because a scan line crosses a rotated
	// symbol at an angle and reports everything too wide. The scan-line
	// estimate is the fallback for a capture where the run measurement runs
	// off the edge of the image.
	moduleSize := (moduleSizeBetween(b, topLeft, topRight) + moduleSizeBetween(b, topLeft, bottomLeft)) / 2
	if math.IsNaN(moduleSize) || moduleSize <= 0 {
		moduleSize = (topLeft.moduleSize + topRight.moduleSize + bottomLeft.moduleSize) / 3
	}
	if moduleSize <= 0 {
		return nil, ErrNotSampleable
	}

	dimension, ok := estimateDimension(topLeft, topRight, bottomLeft, moduleSize)
	if !ok {
		return nil, ErrNotSampleable
	}

	// Two independent guesses have to be made and neither is reliable enough
	// to bet the capture on, so both are offered and the decoder arbitrates.
	//
	// The dimension comes from a measured module size and can be a version
	// out on a poor capture. And the fourth corner is either an alignment
	// pattern found in the image - better, when it is the right one - or the
	// corner of the parallelogram the other three imply, which is exact only
	// if the projection is affine. A false alignment pattern and an assumed
	// corner fail in different ways, so trying both costs one decode attempt
	// and recovers captures that either alone would lose.
	//
	// Arbitration is free and far stronger than any geometric confidence
	// interval: a symbol sampled on the wrong grid fails its format
	// information or its error correction, both of which are already checked.
	var grids []*qr.Grid
	for _, d := range []int{dimension, dimension - 4, dimension + 4} {
		if d < 21 || d > 177 {
			continue
		}
		for _, useAlignment := range []bool{true, false} {
			g, err := sampleAt(b, topLeft, topRight, bottomLeft, moduleSize, d, useAlignment)
			if err != nil {
				continue
			}
			grids = append(grids, g)
		}
	}
	if len(grids) == 0 {
		return nil, ErrNotSampleable
	}
	return grids, nil
}

// estimateDimension works out how many modules across the symbol is.
//
// The two legs between finder pattern centres span the symbol less seven
// modules - three and a half at each end, from centre to outer edge - so the
// count follows from the leg length divided by the module size. The result is
// rounded to a valid symbol size, since every QR symbol is one more than a
// multiple of four and no other number is worth trying.
func estimateDimension(topLeft, topRight, bottomLeft pattern, moduleSize float64) (int, bool) {
	across := math.Round(distance(topLeft, topRight)/moduleSize) + 7
	down := math.Round(distance(topLeft, bottomLeft)/moduleSize) + 7
	dimension := int(math.Round((across + down) / 2))

	switch dimension % 4 {
	case 1:
		// Already a valid size.
	case 0:
		dimension++
	case 2:
		dimension--
	default:
		// Three away from a valid size in either direction. Rounding it
		// either way is a coin toss, so both neighbours are offered and the
		// decoder decides.
		dimension++
	}
	if dimension < 21 || dimension > 177 {
		return 0, false
	}
	return dimension, true
}

// sampleAt maps every module centre through the perspective transform and
// reads the pixel it lands on.
func sampleAt(b *Bitmap, topLeft, topRight, bottomLeft pattern, moduleSize float64, dimension int, useAlignment bool) (*qr.Grid, error) {
	edge := float64(dimension) - 3.5

	// The fourth corner. When the symbol is large enough to carry an alignment
	// pattern, finding it measures the corner instead of assuming it, which is
	// what keeps a big symbol readable when the screen is not flat to the lens:
	// the assumed corner is only correct if the projection is affine, and a
	// camera off the screen's normal is exactly the case where it is not.
	cornerX := topRight.x - topLeft.x + bottomLeft.x
	cornerY := topRight.y - topLeft.y + bottomLeft.y
	sourceX, sourceY := edge, edge

	if version := (dimension - 17) / 4; useAlignment && version >= 2 {
		between := float64(dimension - 7)
		toward := 1 - 3/between
		estX := topLeft.x + toward*(cornerX-topLeft.x)
		estY := topLeft.y + toward*(cornerY-topLeft.y)
		// Widening allowances: a tight window first, so a nearby coincidence
		// is not preferred over the real pattern, then wider ones for a
		// capture whose geometry is further off than the estimate assumed.
		for _, allowance := range []float64{4, 8, 16} {
			if p, ok := findAlignment(b, estX, estY, moduleSize, allowance*moduleSize); ok {
				cornerX, cornerY = p.x, p.y
				sourceX, sourceY = edge-3, edge-3
				break
			}
		}
	}

	t := quadToQuad(
		3.5, 3.5, edge, 3.5, sourceX, sourceY, 3.5, edge,
		topLeft.x, topLeft.y, topRight.x, topRight.y, cornerX, cornerY, bottomLeft.x, bottomLeft.y,
	)
	if t == nil {
		return nil, ErrNotSampleable
	}

	// A module five pixels or wider is worth averaging over: a single pixel
	// carries whatever sensor noise landed on it, and a three-by-three
	// majority costs nine lookups per module on an already-binarized image.
	// Below five the neighbourhood reaches into the adjacent modules and the
	// vote makes things worse rather than better - measured, not assumed: at
	// three pixels per module a clean rendering of every version tested failed
	// with voting on, on format information for the small ones and on error
	// correction for the rest, and decoded with it off.
	vote := moduleSize >= 5

	g := qr.NewGrid(dimension)
	for y := range dimension {
		for x := range dimension {
			px, py := t.apply(float64(x)+0.5, float64(y)+0.5)
			if math.IsNaN(px) || math.IsNaN(py) || math.IsInf(px, 0) || math.IsInf(py, 0) {
				continue
			}
			ix, iy := int(math.Round(px)), int(math.Round(py))
			if ix < 0 || iy < 0 || ix >= b.W || iy >= b.H {
				// A module mapping outside the image means the symbol runs off
				// the frame. Sampling it as light lets error correction try;
				// failing here would give up on a capture that clipped one
				// corner and is otherwise fine.
				continue
			}
			g.Set(x, y, sampleModule(b, ix, iy, vote))
		}
	}
	return g, nil
}

// sampleModule reads one module, optionally by majority vote over its
// neighbourhood.
func sampleModule(b *Bitmap, x, y int, vote bool) bool {
	if !vote {
		return b.At(x, y)
	}
	dark := 0
	for dy := -1; dy <= 1; dy++ {
		for dx := -1; dx <= 1; dx++ {
			if b.At(x+dx, y+dy) {
				dark++
			}
		}
	}
	return dark >= 5
}
