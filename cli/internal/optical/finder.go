package optical

import (
	"math"
	"sort"
)

// Locating a QR symbol in an image comes down to finding its three finder
// patterns: the concentric squares in three corners, whose module widths run
// 1:1:3:1:1 along any line through the centre. That ratio is the whole trick.
// It is scale-invariant, so it works at any distance; it is preserved by
// rotation, so the camera need not be upright; and it survives moderate
// perspective, because a line through the centre of a projected square is
// still a line.
//
// The fourth corner has no finder pattern, which is why a QR symbol can be
// told apart from its own reflection. For versions above 1 an alignment
// pattern sits near that corner instead, and finding it is what lets the
// sampler follow a screen that is not flat to the lens.

// pattern is a located finder or alignment pattern.
type pattern struct {
	// x and y are the centre in image pixels.
	x, y float64
	// moduleSize is the estimated module width in pixels at that point.
	moduleSize float64
	// count is how many independent scan lines agreed on this centre. A
	// pattern seen once is usually noise; one seen five times is a pattern.
	count int
}

// distance returns the pixel distance between two pattern centres.
func distance(a, b pattern) float64 {
	return math.Hypot(a.x-b.x, a.y-b.y)
}

// run is a maximal horizontal or vertical stretch of one colour.
type run struct {
	start  int
	length int
	dark   bool
}

// rowRuns returns the runs along one row of the bitmap.
func rowRuns(b *Bitmap, y int) []run {
	return runsAlong(b.W, func(x int) bool { return b.At(x, y) })
}

// columnRuns returns the runs down one column of the bitmap.
func columnRuns(b *Bitmap, x int) []run {
	return runsAlong(b.H, func(y int) bool { return b.At(x, y) })
}

func runsAlong(n int, dark func(int) bool) []run {
	if n <= 0 {
		return nil
	}
	runs := make([]run, 0, 32)
	current := run{start: 0, length: 1, dark: dark(0)}
	for i := 1; i < n; i++ {
		if d := dark(i); d == current.dark {
			current.length++
		} else {
			runs = append(runs, current)
			current = run{start: i, length: 1, dark: d}
		}
	}
	return append(runs, current)
}

// isFinderRatio reports whether five consecutive runs have the 1:1:3:1:1
// proportions of a finder pattern, and returns the implied module size.
//
// The tolerance is half a module on the single-width rings and one and a half
// on the centre. That is generous on purpose: a blurred capture spreads each
// edge over a pixel or two, and a threshold that lands on the wrong side of
// one edge shifts a ring's width by a whole pixel. Tightening this is the
// fastest way to make a detector that works on renderings and fails on
// photographs.
func isFinderRatio(counts [5]int) (moduleSize float64, ok bool) {
	total := 0
	for _, c := range counts {
		if c == 0 {
			return 0, false
		}
		total += c
	}
	if total < 7 {
		return 0, false
	}
	moduleSize = float64(total) / 7
	variance := moduleSize / 2
	if math.Abs(moduleSize-float64(counts[0])) >= variance ||
		math.Abs(moduleSize-float64(counts[1])) >= variance ||
		math.Abs(3*moduleSize-float64(counts[2])) >= 3*variance ||
		math.Abs(moduleSize-float64(counts[3])) >= variance ||
		math.Abs(moduleSize-float64(counts[4])) >= variance {
		return 0, false
	}
	return moduleSize, true
}

// centreOfRun returns the middle of a run in continuous coordinates.
func centreOfRun(r run) float64 {
	return float64(r.start) + float64(r.length)/2
}

// findFinderPatterns scans the image for finder patterns.
//
// Rows are scanned at a stride rather than exhaustively. The smallest feature
// being looked for is three modules tall, so a stride of a third of the
// smallest plausible module height cannot step over one, and the saving is
// most of the work.
func findFinderPatterns(b *Bitmap) []pattern {
	var found []pattern

	stride := max(b.H/(4*57)*3, 3)
	for y := stride - 1; y < b.H; y += stride {
		runs := rowRuns(b, y)
		for k := 0; k+4 < len(runs); k++ {
			if !runs[k].dark {
				continue
			}
			counts := [5]int{
				runs[k].length, runs[k+1].length, runs[k+2].length,
				runs[k+3].length, runs[k+4].length,
			}
			if _, ok := isFinderRatio(counts); !ok {
				continue
			}
			// The centre ring is the middle run; its midpoint is the
			// horizontal centre of the candidate.
			cx := centreOfRun(runs[k+2])
			if p, ok := confirmFinder(b, cx, float64(y), counts); ok {
				found = merge(found, p)
			}
		}
	}

	return found
}

// confirmFinder checks a horizontal candidate vertically and then horizontally
// again through the refined centre.
//
// A horizontal scan alone finds every stripe in the image whose widths happen
// to run 1:1:3:1:1, which in a photograph of a room is a great many of them.
// Requiring the same proportions through the same point in the other direction
// is what distinguishes a square from a coincidence.
func confirmFinder(b *Bitmap, cx, cy float64, horizontal [5]int) (pattern, bool) {
	total := 0
	for _, c := range horizontal {
		total += c
	}

	centreY, vertical, ok := crossCheck(columnRuns(b, int(cx)), cy, horizontal[2], total)
	if !ok {
		return pattern{}, false
	}
	centreX, _, ok := crossCheck(rowRuns(b, int(centreY)), cx, vertical[2], total)
	if !ok {
		return pattern{}, false
	}

	return pattern{x: centreX, y: centreY, moduleSize: float64(total) / 7, count: 1}, true
}

// crossCheck looks for the finder proportions along a perpendicular line
// through a candidate centre.
//
// It returns the refined centre on that line and the run lengths it found, so
// the caller can use the measured centre ring width for the next check rather
// than the one it started with.
func crossCheck(runs []run, at float64, maxCentre, originalTotal int) (centre float64, counts [5]int, ok bool) {
	// Find the run containing the candidate centre. It has to be dark: the
	// centre of a finder pattern is inside its dark middle square.
	index := -1
	for i, r := range runs {
		if float64(r.start) <= at && at < float64(r.start+r.length) {
			index = i
			break
		}
	}
	if index < 0 || !runs[index].dark || index < 2 || index+2 >= len(runs) {
		return 0, counts, false
	}

	counts = [5]int{
		runs[index-2].length, runs[index-1].length, runs[index].length,
		runs[index+1].length, runs[index+2].length,
	}
	// A centre ring wildly wider than the one measured in the other direction
	// means the two scans crossed different features.
	if counts[2] > 2*maxCentre+2 {
		return 0, counts, false
	}
	if _, ok := isFinderRatio(counts); !ok {
		return 0, counts, false
	}

	total := 0
	for _, c := range counts {
		total += c
	}
	// The two directions must agree on the pattern's overall size to within
	// forty per cent. Perspective can stretch one axis relative to the other;
	// it cannot double it without also destroying the ratios above.
	if 5*abs(total-originalTotal) >= 2*originalTotal {
		return 0, counts, false
	}

	return centreOfRun(runs[index]), counts, true
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// merge folds a new sighting into the list, combining it with an existing
// pattern when the two describe the same place at the same scale.
//
// Combining rather than replacing matters: the centre estimate improves with
// every scan line that agrees, and the count is what later tells a real
// pattern from a single-line coincidence.
func merge(found []pattern, p pattern) []pattern {
	for i := range found {
		f := &found[i]
		if math.Abs(f.x-p.x) > f.moduleSize || math.Abs(f.y-p.y) > f.moduleSize {
			continue
		}
		diff := math.Abs(f.moduleSize - p.moduleSize)
		if diff > 1 && diff > f.moduleSize {
			continue
		}
		n := float64(f.count)
		f.x = (f.x*n + p.x) / (n + 1)
		f.y = (f.y*n + p.y) / (n + 1)
		f.moduleSize = (f.moduleSize*n + p.moduleSize) / (n + 1)
		f.count++
		return found
	}
	return append(found, p)
}

// selectThree picks the three patterns most likely to be one symbol's corners.
//
// A photograph of a screen frequently contains more than three candidates: the
// alignment pattern of a large symbol can pass the ratio test, and so can
// anything else square in the frame. Rather than trimming outliers by a
// heuristic, every combination of three is scored and the best is taken. The
// candidate list is small enough that this is cheaper than the reasoning
// needed to justify a shortcut.
func selectThree(candidates []pattern) ([3]pattern, bool) {
	var best [3]pattern
	if len(candidates) < 3 {
		return best, false
	}

	// Strongest sightings first, and never consider more than a handful:
	// beyond that the extras are noise and the combinatorics stop being free.
	sorted := make([]pattern, len(candidates))
	copy(sorted, candidates)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })
	if len(sorted) > 8 {
		sorted = sorted[:8]
	}

	bestScore := math.Inf(1)
	for i := range sorted {
		for j := i + 1; j < len(sorted); j++ {
			for k := j + 1; k < len(sorted); k++ {
				trio := [3]pattern{sorted[i], sorted[j], sorted[k]}
				if score, ok := scoreTrio(trio); ok && score < bestScore {
					bestScore, best = score, trio
				}
			}
		}
	}
	return best, !math.IsInf(bestScore, 1)
}

// scoreTrio rates three patterns as the corners of one symbol. Lower is
// better; the second return reports whether they are plausible at all.
//
// Two properties are scored. The three finder patterns of a symbol are printed
// at one scale, so their module sizes should agree. And they sit at three
// corners of a square, so the two legs from the corner nearest the other two
// should be of equal length and at a right angle - which perspective distorts
// but does not abolish.
func scoreTrio(trio [3]pattern) (float64, bool) {
	sizes := [3]float64{trio[0].moduleSize, trio[1].moduleSize, trio[2].moduleSize}
	mean := (sizes[0] + sizes[1] + sizes[2]) / 3
	if mean <= 0 {
		return 0, false
	}
	sizeSpread := 0.0
	for _, s := range sizes {
		sizeSpread += math.Abs(s-mean) / mean
	}
	if sizeSpread > 1.5 {
		return 0, false
	}

	topLeft, topRight, bottomLeft, ok := orderPatterns(trio)
	if !ok {
		return 0, false
	}
	legA := distance(topLeft, topRight)
	legB := distance(topLeft, bottomLeft)
	if legA < 3*mean || legB < 3*mean {
		// Closer than three modules apart is not two corners of a symbol.
		return 0, false
	}
	legRatio := math.Abs(legA-legB) / math.Max(legA, legB)
	if legRatio > 0.5 {
		return 0, false
	}

	// The diagonal of a right isosceles triangle is the leg times root two.
	diagonal := distance(topRight, bottomLeft)
	expected := math.Max(legA, legB) * math.Sqrt2
	squareness := math.Abs(diagonal-expected) / expected
	if squareness > 0.4 {
		return 0, false
	}

	return sizeSpread + legRatio + squareness, true
}

// orderPatterns labels three corners as top-left, top-right, and bottom-left.
//
// The top-left corner is the one opposite the longest side, because that side
// is the symbol's diagonal. Which of the remaining two is the top-right then
// depends on handedness, which a cross product answers - and getting it wrong
// would sample the symbol mirrored, which decodes to nothing rather than to
// something subtly wrong.
func orderPatterns(trio [3]pattern) (topLeft, topRight, bottomLeft pattern, ok bool) {
	d01 := distance(trio[0], trio[1])
	d12 := distance(trio[1], trio[2])
	d02 := distance(trio[0], trio[2])

	var a, b pattern
	switch {
	case d12 >= d01 && d12 >= d02:
		topLeft, a, b = trio[0], trio[1], trio[2]
	case d02 >= d12 && d02 >= d01:
		topLeft, a, b = trio[1], trio[0], trio[2]
	default:
		topLeft, a, b = trio[2], trio[0], trio[1]
	}

	if cross(a, topLeft, b) < 0 {
		a, b = b, a
	}
	return topLeft, b, a, true
}

// cross returns the z component of the cross product of the vectors from b to
// a and from b to c, whose sign is the handedness of the three points.
func cross(a, b, c pattern) float64 {
	return (c.x-b.x)*(a.y-b.y) - (c.y-b.y)*(a.x-b.x)
}

// moduleSizeBetween measures the module width along the line joining two
// finder pattern centres.
//
// The obvious estimate - the module size each pattern reported when it was
// found - is wrong whenever the symbol is rotated. A horizontal scan line
// through a square rotated by 45 degrees crosses it along its diagonal, so
// every ring reads root-two too wide; the 1:1:3:1:1 ratio still holds, which
// is why the pattern is still found, but the scale is inflated. Feeding that
// into the dimension estimate makes a large symbol look like a small one, and
// the symbol is then sampled on the wrong grid and decodes to nothing.
//
// Measuring along the symbol's own axis instead removes the dependence on the
// scan direction entirely. Each side reads the black-white-black run outward
// from a centre in both directions, which spans exactly seven modules.
func moduleSizeBetween(b *Bitmap, a, c pattern) float64 {
	one := blackWhiteBlackBothWays(b, a.x, a.y, c.x, c.y)
	other := blackWhiteBlackBothWays(b, c.x, c.y, a.x, a.y)
	switch {
	case math.IsNaN(one) && math.IsNaN(other):
		return math.NaN()
	case math.IsNaN(one):
		return other / 7
	case math.IsNaN(other):
		return one / 7
	default:
		return (one + other) / 14
	}
}

// blackWhiteBlackBothWays measures the run through a centre in both
// directions along a line.
func blackWhiteBlackBothWays(b *Bitmap, fromX, fromY, toX, toY float64) float64 {
	forward := blackWhiteBlackRun(b, fromX, fromY, toX, toY)

	// The same distance the other way, clipped to the image. Clipping scales
	// both axes together so the direction is preserved: a run measured along a
	// different line than the forward one would not be the same measurement.
	scale := 1.0
	otherX := fromX - (toX - fromX)
	if otherX < 0 {
		scale = fromX / (fromX - otherX)
		otherX = 0
	} else if otherX >= float64(b.W) {
		scale = (float64(b.W) - 1 - fromX) / (otherX - fromX)
		otherX = float64(b.W) - 1
	}
	otherY := fromY - (toY-fromY)*scale

	scale = 1.0
	if otherY < 0 {
		scale = fromY / (fromY - otherY)
		otherY = 0
	} else if otherY >= float64(b.H) {
		scale = (float64(b.H) - 1 - fromY) / (otherY - fromY)
		otherY = float64(b.H) - 1
	}
	otherX = fromX + (otherX-fromX)*scale

	backward := blackWhiteBlackRun(b, fromX, fromY, otherX, otherY)
	if math.IsNaN(forward) || math.IsNaN(backward) {
		return math.NaN()
	}
	// The centre pixel was counted in both directions.
	return forward + backward - 1
}

// blackWhiteBlackRun walks from a point towards another and returns how far it
// travelled before leaving the second black region.
//
// Starting inside the dark centre of a finder pattern, that is the centre
// square's half-width, the light ring, and the dark ring: three and a half
// modules, whatever the symbol's orientation.
func blackWhiteBlackRun(b *Bitmap, fromXf, fromYf, toXf, toYf float64) float64 {
	fromX, fromY := int(fromXf), int(fromYf)
	toX, toY := int(toXf), int(toYf)

	steep := abs(toY-fromY) > abs(toX-fromX)
	if steep {
		fromX, fromY = fromY, fromX
		toX, toY = toY, toX
	}

	dx, dy := abs(toX-fromX), abs(toY-fromY)
	err := -dx / 2
	xStep, yStep := 1, 1
	if fromX >= toX {
		xStep = -1
	}
	if fromY >= toY {
		yStep = -1
	}

	// state 0: inside the dark centre, waiting for light
	// state 1: inside the light ring, waiting for dark
	// state 2: inside the dark ring, waiting for light again
	state := 0
	limit := toX + xStep
	y := fromY
	for x := fromX; x != limit; x += xStep {
		realX, realY := x, y
		if steep {
			realX, realY = y, x
		}
		if (state == 1) == b.At(realX, realY) {
			if state == 2 {
				return math.Hypot(float64(x-fromX), float64(y-fromY))
			}
			state++
		}
		err += dy
		if err > 0 {
			if y == toY {
				break
			}
			y += yStep
			err -= dx
		}
	}
	if state == 2 {
		return math.Hypot(float64(limit-fromX), float64(toY-fromY))
	}
	return math.NaN()
}

// findAlignment searches a window of the image for an alignment pattern.
//
// Alignment patterns are three modules across with 1:1:1 proportions, which is
// far weaker evidence than a finder pattern's 1:1:3:1:1 - almost any small dark
// square passes it. That is acceptable only because the search window is
// derived from the three finder patterns and is a few modules wide: the
// question is not "is there an alignment pattern in this image" but "is the one
// this symbol must have exactly here".
func findAlignment(b *Bitmap, cx, cy, moduleSize, allowance float64) (pattern, bool) {
	left := max(int(cx-allowance), 0)
	right := min(int(cx+allowance), b.W-1)
	top := max(int(cy-allowance), 0)
	bottom := min(int(cy+allowance), b.H-1)
	if float64(right-left) < 3*moduleSize || float64(bottom-top) < 3*moduleSize {
		return pattern{}, false
	}

	variance := moduleSize / 2
	within := func(n int) bool { return math.Abs(float64(n)-moduleSize) < variance }

	var best pattern
	bestDistance := math.Inf(1)

	for y := top; y <= bottom; y++ {
		runs := rowRuns(b, y)
		for k := 0; k+2 < len(runs); k++ {
			// Light, dark, light. A line through the centre of an alignment
			// pattern reads dark-light-dark-light-dark across its five
			// modules, and it is the middle dark run that is the centre; a
			// dark-light-dark triple would centre one module off.
			if runs[k].dark || !runs[k+1].dark || runs[k+2].dark {
				continue
			}
			if runs[k+1].start < left-int(moduleSize) || runs[k+1].start > right+int(moduleSize) {
				continue
			}
			if !within(runs[k].length) || !within(runs[k+1].length) || !within(runs[k+2].length) {
				continue
			}
			px := centreOfRun(runs[k+1])
			py, ok := verifyAlignmentColumn(b, int(px), y, moduleSize)
			if !ok {
				continue
			}
			if !looksLikeAlignment(b, px, py, moduleSize) {
				continue
			}
			d := math.Hypot(px-cx, py-cy)
			if d < bestDistance {
				bestDistance, best = d, pattern{x: px, y: py, moduleSize: moduleSize, count: 1}
			}
		}
	}

	return best, !math.IsInf(bestDistance, 1)
}

// looksLikeAlignment checks the whole five-by-five structure rather than one
// line through it.
//
// A light-dark-light run of single modules is weak evidence: a data area
// produces them constantly, and the search window around a large symbol's
// estimated corner is wide enough to contain many. An alignment pattern is a
// dark five-by-five border, a light ring inside it, and a dark centre, which
// is seventeen sampled modules of evidence rather than three.
//
// Three of the seventeen are allowed to disagree, because the sample points
// are placed on an axis-aligned grid and a symbol under perspective is not.
func looksLikeAlignment(b *Bitmap, cx, cy, moduleSize float64) bool {
	agree, total := 0, 0
	check := func(dx, dy int, wantDark bool) {
		total++
		x := int(cx + float64(dx)*moduleSize)
		y := int(cy + float64(dy)*moduleSize)
		if b.At(x, y) == wantDark {
			agree++
		}
	}

	check(0, 0, true)
	for dy := -1; dy <= 1; dy++ {
		for dx := -1; dx <= 1; dx++ {
			if dx == 0 && dy == 0 {
				continue
			}
			check(dx, dy, false) // the light ring
		}
	}
	// Eight points on the dark border: its four corners and four edge
	// midpoints. Enough of the ring to distinguish it without sampling all
	// sixteen of its modules.
	for _, p := range [8][2]int{
		{-2, -2}, {0, -2}, {2, -2},
		{-2, 0}, {2, 0},
		{-2, 2}, {0, 2}, {2, 2},
	} {
		check(p[0], p[1], true)
	}

	return total-agree <= 3
}

// verifyAlignmentColumn checks the 1:1:1 proportions vertically through a
// horizontal candidate and returns the refined centre.
func verifyAlignmentColumn(b *Bitmap, x, y int, moduleSize float64) (float64, bool) {
	runs := columnRuns(b, x)
	variance := moduleSize / 2
	for k := 0; k+2 < len(runs); k++ {
		mid := runs[k+1]
		if runs[k].dark || !mid.dark || runs[k+2].dark {
			continue
		}
		if mid.start > y || mid.start+mid.length <= y {
			continue
		}
		if math.Abs(float64(runs[k].length)-moduleSize) >= variance ||
			math.Abs(float64(mid.length)-moduleSize) >= variance ||
			math.Abs(float64(runs[k+2].length)-moduleSize) >= variance {
			return 0, false
		}
		return centreOfRun(mid), true
	}
	return 0, false
}
