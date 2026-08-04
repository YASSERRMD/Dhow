package optical

// Perspective transforms between module coordinates and image pixels.
//
// A camera pointed at a screen almost never sits on the screen's normal, so
// the symbol in the image is a general quadrilateral rather than a square. An
// affine transform - translate, rotate, scale, shear - cannot express that: it
// keeps parallel lines parallel, and the two vertical edges of a photographed
// square are not parallel. The projective transform below is the smallest one
// that can, at the cost of a division per point.
//
// The mapping is built from four correspondences: three finder pattern centres
// and either the alignment pattern near the fourth corner or, when that cannot
// be found, the corner where two straight edges would meet. The alignment
// pattern is much the better fourth point, because it is measured in the image
// rather than assumed from the other three, which is exactly what makes a
// large symbol readable when the screen is not flat to the lens.

// transform is a 3x3 projective matrix in column-major order, named the way
// the geometry is usually written: aRC for row R, column C.
type transform struct {
	a11, a21, a31 float64
	a12, a22, a32 float64
	a13, a23, a33 float64
}

// apply maps a point through the transform.
func (t *transform) apply(x, y float64) (float64, float64) {
	denominator := t.a13*x + t.a23*y + t.a33
	if denominator == 0 {
		// A point on the horizon of the projection. It has no image; the
		// caller treats the sample as light rather than dividing by zero.
		return 0, 0
	}
	return (t.a11*x + t.a21*y + t.a31) / denominator,
		(t.a12*x + t.a22*y + t.a32) / denominator
}

// squareToQuad maps the unit square's corners onto four points, in the order
// (0,0), (1,0), (1,1), (0,1).
func squareToQuad(x0, y0, x1, y1, x2, y2, x3, y3 float64) *transform {
	dx3 := x0 - x1 + x2 - x3
	dy3 := y0 - y1 + y2 - y3
	if dx3 == 0 && dy3 == 0 {
		// The quadrilateral is a parallelogram, so the projection degenerates
		// to an affine map and the general formula would divide by zero.
		return &transform{
			a11: x1 - x0, a21: x2 - x1, a31: x0,
			a12: y1 - y0, a22: y2 - y1, a32: y0,
			a13: 0, a23: 0, a33: 1,
		}
	}
	dx1, dx2 := x1-x2, x3-x2
	dy1, dy2 := y1-y2, y3-y2
	denominator := dx1*dy2 - dx2*dy1
	if denominator == 0 {
		return nil
	}
	a13 := (dx3*dy2 - dx2*dy3) / denominator
	a23 := (dx1*dy3 - dx3*dy1) / denominator
	return &transform{
		a11: x1 - x0 + a13*x1, a21: x3 - x0 + a23*x3, a31: x0,
		a12: y1 - y0 + a13*y1, a22: y3 - y0 + a23*y3, a32: y0,
		a13: a13, a23: a23, a33: 1,
	}
}

// adjoint returns the adjugate matrix, which inverts the transform up to a
// scale factor. Scale is irrelevant in homogeneous coordinates, so this is the
// inverse for our purposes and needs no determinant.
func (t *transform) adjoint() *transform {
	return &transform{
		a11: t.a22*t.a33 - t.a23*t.a32,
		a21: t.a23*t.a31 - t.a21*t.a33,
		a31: t.a21*t.a32 - t.a22*t.a31,
		a12: t.a13*t.a32 - t.a12*t.a33,
		a22: t.a11*t.a33 - t.a13*t.a31,
		a32: t.a12*t.a31 - t.a11*t.a32,
		a13: t.a12*t.a23 - t.a13*t.a22,
		a23: t.a13*t.a21 - t.a11*t.a23,
		a33: t.a11*t.a22 - t.a12*t.a21,
	}
}

// times composes two transforms.
func (t *transform) times(o *transform) *transform {
	return &transform{
		a11: t.a11*o.a11 + t.a21*o.a12 + t.a31*o.a13,
		a21: t.a11*o.a21 + t.a21*o.a22 + t.a31*o.a23,
		a31: t.a11*o.a31 + t.a21*o.a32 + t.a31*o.a33,
		a12: t.a12*o.a11 + t.a22*o.a12 + t.a32*o.a13,
		a22: t.a12*o.a21 + t.a22*o.a22 + t.a32*o.a23,
		a32: t.a12*o.a31 + t.a22*o.a32 + t.a32*o.a33,
		a13: t.a13*o.a11 + t.a23*o.a12 + t.a33*o.a13,
		a23: t.a13*o.a21 + t.a23*o.a22 + t.a33*o.a23,
		a33: t.a13*o.a31 + t.a23*o.a32 + t.a33*o.a33,
	}
}

// quadToQuad builds the transform taking the first quadrilateral onto the
// second, by routing both through the unit square.
func quadToQuad(
	x0, y0, x1, y1, x2, y2, x3, y3 float64,
	u0, v0, u1, v1, u2, v2, u3, v3 float64,
) *transform {
	source := squareToQuad(x0, y0, x1, y1, x2, y2, x3, y3)
	destination := squareToQuad(u0, v0, u1, v1, u2, v2, u3, v3)
	if source == nil || destination == nil {
		return nil
	}
	return destination.times(source.adjoint())
}
