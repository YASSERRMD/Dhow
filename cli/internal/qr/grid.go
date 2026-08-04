package qr

import "fmt"

// Grid is a sampled QR symbol: one bit per module, row-major, true for dark.
//
// It is deliberately the same shape as the module grid the encoder produces,
// so a rendered frame and a captured one are the same kind of object and the
// decoder cannot tell them apart. That is what makes it possible to test the
// decoder against the encoder directly, without a camera anywhere in the loop.
type Grid struct {
	// Size is the number of modules per side.
	Size int
	// Dark holds the modules, row-major, true for dark.
	Dark []bool
}

// NewGrid returns an all-light grid of the given size.
func NewGrid(size int) *Grid {
	return &Grid{Size: size, Dark: make([]bool, size*size)}
}

// GridFromModules wraps the one-byte-per-module form the encoder emits.
func GridFromModules(size int, modules []byte) (*Grid, error) {
	if size <= 0 || len(modules) != size*size {
		return nil, fmt.Errorf("qr: %d modules do not form a %dx%d grid", len(modules), size, size)
	}
	g := NewGrid(size)
	for i, m := range modules {
		g.Dark[i] = m != 0
	}
	return g, nil
}

// At reports whether the module at (x, y) is dark. Coordinates outside the
// grid read as light, matching the encoder, so a caller walking a quiet zone
// needs no bounds check.
func (g *Grid) At(x, y int) bool {
	if x < 0 || y < 0 || x >= g.Size || y >= g.Size {
		return false
	}
	return g.Dark[y*g.Size+x]
}

// Set writes the module at (x, y). Coordinates outside the grid are ignored.
func (g *Grid) Set(x, y int, dark bool) {
	if x < 0 || y < 0 || x >= g.Size || y >= g.Size {
		return
	}
	g.Dark[y*g.Size+x] = dark
}
