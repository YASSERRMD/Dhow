package qr

import "errors"

// Reed-Solomon decoding over GF(256), the code QR uses for error correction.
//
// # Why this is here and not in the Rust core
//
// The architecture puts correctness-critical logic in Rust and QR detection in
// Go. This is QR detection: it turns a grid of light and dark squares back
// into the bytes the sender rendered, which is the inverse of a thing the
// renderer does, and it happens before the frame reaches the FFI at all. The
// per-frame CRC check that follows it is the boundary; nothing this file
// produces is trusted until that CRC and then the frame's session MAC agree.
//
// # What it corrects
//
// A block with 2t error-correction bytes and no known erasure positions
// corrects up to t byte errors wherever they fall. A byte is wrong or right as
// a whole, so a single flipped module and a completely obliterated byte cost
// the same. That is the property that makes QR survive a camera: damage in a
// photograph is spatial, and the interleaving that precedes this spreads a
// contiguous smear across many blocks so that no one block sees more than t.

// ErrUncorrectable reports a block with more damage than its error-correction
// bytes can repair.
//
// The receiver's answer to this is to discard the frame and wait for another
// showing of it, which the sender is looping. It is an expected outcome of a
// bad capture, not a fault.
var ErrUncorrectable = errors.New("qr: block has more errors than can be corrected")

// GF(256) with the QR specification's primitive polynomial x^8+x^4+x^3+x^2+1.
const gfPrimitive = 0x11d

// Log and antilog tables. Multiplication in the field is addition of
// logarithms, which turns the inner loop of every polynomial operation into a
// pair of table lookups.
var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	x := 1
	for i := range 255 {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= gfPrimitive
		}
	}
	// The table is doubled so that an exponent sum up to 508 needs no modulo.
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

// gfMul multiplies two field elements.
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfDiv divides a by b. b must not be zero; callers check.
func gfDiv(a, b byte) byte {
	if a == 0 {
		return 0
	}
	// +255 keeps the index non-negative without a branch on the difference.
	return gfExp[int(gfLog[a])-int(gfLog[b])+255]
}

// gfPow returns the generator raised to e, for any integer exponent.
func gfPow(e int) byte {
	e %= 255
	if e < 0 {
		e += 255
	}
	return gfExp[e]
}

// Polynomials are slices of coefficients with index 0 holding the constant
// term. Codewords, by contrast, arrive with the highest-degree coefficient
// first, because that is the order they are transmitted in; the conversion
// happens where the two meet rather than being carried around.

// polyEval evaluates p at x by Horner's method.
func polyEval(p []byte, x byte) byte {
	var acc byte
	for i := len(p) - 1; i >= 0; i-- {
		acc = gfMul(acc, x) ^ p[i]
	}
	return acc
}

// polyMul multiplies two polynomials.
func polyMul(a, b []byte) []byte {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	out := make([]byte, len(a)+len(b)-1)
	for i, av := range a {
		if av == 0 {
			continue
		}
		for j, bv := range b {
			out[i+j] ^= gfMul(av, bv)
		}
	}
	return out
}

// syndromes evaluates the received codeword at the generator's roots.
//
// Every syndrome is zero exactly when the codeword is a valid one. QR's
// generator has consecutive roots starting at the generator's zeroth power, so
// the j-th syndrome is the codeword evaluated at the generator raised to j.
func syndromes(codeword []byte, eccLen int) []byte {
	out := make([]byte, eccLen)
	for j := range eccLen {
		x := gfPow(j)
		var acc byte
		for _, c := range codeword {
			acc = gfMul(acc, x) ^ c
		}
		out[j] = acc
	}
	return out
}

// berlekampMassey finds the shortest error-locator polynomial consistent with
// the syndromes.
//
// The returned polynomial's roots are the inverses of the error positions,
// expressed as powers of the generator.
func berlekampMassey(synd []byte) []byte {
	lambda := []byte{1}
	prev := []byte{1}
	var prevDiscrepancy byte = 1
	length := 0 // current register length
	shift := 1  // how far prev has to be shifted before it is folded in

	for n := range synd {
		// Discrepancy between the syndrome and what the current locator
		// predicts.
		d := synd[n]
		for i := 1; i <= length && i < len(lambda); i++ {
			d ^= gfMul(lambda[i], synd[n-i])
		}

		switch {
		case d == 0:
			shift++
		case 2*length <= n:
			saved := lambda
			lambda = polyAddShifted(lambda, prev, shift, gfDiv(d, prevDiscrepancy))
			length = n + 1 - length
			prev = saved
			prevDiscrepancy = d
			shift = 1
		default:
			lambda = polyAddShifted(lambda, prev, shift, gfDiv(d, prevDiscrepancy))
			shift++
		}
	}
	return lambda
}

// polyAddShifted returns a + scale * x^shift * b.
func polyAddShifted(a, b []byte, shift int, scale byte) []byte {
	size := max(len(a), len(b)+shift)
	out := make([]byte, size)
	copy(out, a)
	for i, bv := range b {
		out[i+shift] ^= gfMul(bv, scale)
	}
	return out
}

// findErrorPositions searches for the roots of the locator polynomial.
//
// A root at the generator raised to minus j means the codeword coefficient of
// degree j is wrong. The search is exhaustive over the codeword's length,
// which is at most 255 elements, so it costs nothing worth optimising.
func findErrorPositions(lambda []byte, codewordLen int) ([]int, bool) {
	degree := len(lambda) - 1
	for degree > 0 && lambda[degree] == 0 {
		degree--
	}
	if degree == 0 {
		return nil, true
	}

	positions := make([]int, 0, degree)
	for j := range codewordLen {
		if polyEval(lambda, gfPow(-j)) == 0 {
			positions = append(positions, j)
		}
	}
	// Fewer roots inside the codeword than the locator's degree means the
	// locator describes errors outside it, which means the received block is
	// not within correcting distance of any codeword. Correcting it anyway
	// would produce confident nonsense.
	return positions, len(positions) == degree
}

// correct repairs a codeword in place, or reports that it cannot.
//
// codeword arrives with the highest-degree coefficient first, which is the
// order the bytes were transmitted in.
func correct(codeword []byte, eccLen int) error {
	if eccLen <= 0 || len(codeword) <= eccLen || len(codeword) > 255 {
		return ErrUncorrectable
	}

	synd := syndromes(codeword, eccLen)
	clean := true
	for _, s := range synd {
		if s != 0 {
			clean = false
			break
		}
	}
	if clean {
		return nil
	}

	lambda := berlekampMassey(synd)
	positions, ok := findErrorPositions(lambda, len(codeword))
	if !ok {
		return ErrUncorrectable
	}
	if len(positions) == 0 {
		// Non-zero syndromes with no locatable error: the received block is
		// not a codeword and is not close to one.
		return ErrUncorrectable
	}
	if len(positions) > eccLen/2 {
		return ErrUncorrectable
	}

	// Forney's algorithm gives each error's magnitude from the error evaluator
	// polynomial and the formal derivative of the locator.
	omega := polyMul(synd, lambda)
	if len(omega) > eccLen {
		omega = omega[:eccLen]
	}
	derivative := formalDerivative(lambda)

	for _, j := range positions {
		xInv := gfPow(-j)
		denom := polyEval(derivative, xInv)
		if denom == 0 {
			return ErrUncorrectable
		}
		magnitude := gfMul(gfPow(j), gfDiv(polyEval(omega, xInv), denom))
		// Degree j counted from the end of the codeword, because the highest
		// degree is transmitted first.
		codeword[len(codeword)-1-j] ^= magnitude
	}

	// Correcting a block that was outside the code's reach can leave a result
	// that is still not a codeword. Checking rather than assuming is the
	// difference between rejecting a bad capture and handing the frame parser
	// bytes that were invented here.
	for _, s := range syndromes(codeword, eccLen) {
		if s != 0 {
			return ErrUncorrectable
		}
	}
	return nil
}

// formalDerivative returns the derivative of p over a field of characteristic
// two, where every even-degree term differentiates away.
func formalDerivative(p []byte) []byte {
	if len(p) <= 1 {
		return []byte{0}
	}
	out := make([]byte, len(p)-1)
	for i := 1; i < len(p); i++ {
		if i%2 == 1 {
			out[i-1] = p[i]
		}
	}
	return out
}
