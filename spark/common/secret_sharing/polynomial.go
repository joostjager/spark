package secretsharing

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

// ScalarEval represents the evaluation of polynomial whose coefficients are scalars.
type ScalarEval struct {
	X *secp256k1.ModNScalar
	Y *secp256k1.ModNScalar
}

// PointEval represents the evaluation of a polynomial whose coefficients are curve points.
type PointEval struct {
	X *secp256k1.ModNScalar
	Y *secp256k1.JacobianPoint
}

// Helper function to create a scalar from an integer
func scalarFromInt(n uint32) *secp256k1.ModNScalar {
	s := new(secp256k1.ModNScalar)
	s.SetInt(n)
	return s
}

// lagrangeBasisAtZero computes the Lagrange basis polynomial for index i evaluated at 0:
// L_i(0) = prod_{j≠i} (0 - x_j)/(x_i - x_j).
func lagrangeBasisAtZero(xs []*secp256k1.ModNScalar, i int) *secp256k1.ModNScalar {
	var result secp256k1.ModNScalar
	result.SetInt(1)

	for j, xj := range xs {
		if i == j {
			continue
		}

		var numerator, denominator, ratio secp256k1.ModNScalar

		// numerator = -x_j
		numerator.NegateVal(xj)

		// denominator = x_i - x_j
		denominator.NegateVal(xj).Add(xs[i])

		// ratio = numerator / denominator
		ratio.InverseValNonConst(&denominator)
		ratio.Mul(&numerator)

		// result *= temp
		result.Mul(&ratio)
	}

	return &result
}

// ReconstructScalar returns P(0) where P is the unique polynomial
// of least degree that passes through the given evaluation points.
func ReconstructScalar(points []*ScalarEval) *secp256k1.ModNScalar {
	var result secp256k1.ModNScalar
	result.SetInt(0)

	// Extract x coordinates
	xs := make([]*secp256k1.ModNScalar, len(points))
	for i := range points {
		xs[i] = points[i].X
	}

	// P(0) = sum_i y_i * L_i(0)
	for i := range points {
		weight := lagrangeBasisAtZero(xs, i)

		// Compute y_i * L_i(0)
		var term secp256k1.ModNScalar
		term.Set(points[i].Y)
		term.Mul(weight)

		// Add to result
		result.Add(&term)
	}

	return &result
}

// ReconstructPoint returns P(0) where P is the unique polynomial
// of least degree that passes through the given evaluation points.
func ReconstructPoint(points []*PointEval) *secp256k1.JacobianPoint {
	var result secp256k1.JacobianPoint // Zero value is identity point.

	// Extract x coordinates
	xs := make([]*secp256k1.ModNScalar, len(points))
	for i := range points {
		xs[i] = points[i].X
	}

	// P(0) = sum_i y_i * L_i(0)
	for i := range points {
		weight := lagrangeBasisAtZero(xs, i)

		// Compute y_i * L_i(0)
		var term secp256k1.JacobianPoint
		secp256k1.ScalarMultNonConst(weight, points[i].Y, &term)

		// Add to result
		secp256k1.AddNonConst(&result, &term, &result)
	}

	return &result
}

// ScalarPolynomial represents a polynomial with scalar coefficients.
type ScalarPolynomial struct {
	Coefs []*secp256k1.ModNScalar
}

// PointPolynomial represents a polynomial with curve point coefficients.
type PointPolynomial struct {
	Coefs []*secp256k1.JacobianPoint
}

// NewScalarPolynomialSharing returns a polynomial with random scalar coefficients
// and the passed secret as constant term.
func NewScalarPolynomialSharing(secret *secp256k1.ModNScalar, degree int) (*ScalarPolynomial, error) {
	coefs := make([]*secp256k1.ModNScalar, degree+1)

	for i := range coefs {
		coefKey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}

		coefs[i] = &coefKey.Key
	}

	coefs[0] = secret

	poly := ScalarPolynomial{Coefs: coefs}
	return &poly, nil
}

// ToPointPolynomial creates a polynomial whose coefficients are the original scalars times the base point.
func (p *ScalarPolynomial) ToPointPolynomial() *PointPolynomial {
	pointCoefs := make([]*Point, len(p.Coefs))

	for i, coef := range p.Coefs {
		pointCoefs[i] = new(Point)
		secp256k1.ScalarBaseMultNonConst(coef, pointCoefs[i])
	}

	return &PointPolynomial{Coefs: pointCoefs}
}

// Eval evaluates the polynomial at x.
func (p *ScalarPolynomial) Eval(x *secp256k1.ModNScalar) *secp256k1.ModNScalar {
	var result secp256k1.ModNScalar
	result.SetInt(0)

	if len(p.Coefs) == 0 {
		return &result
	}

	// Use Horner's method: a + b x + c x^2 + d x^3 = ((d x + c) x + b) x + a.
	result.Set(p.Coefs[len(p.Coefs)-1])

	for i := len(p.Coefs) - 2; i >= 0; i-- {
		result.Mul(x)
		result.Add(p.Coefs[i])
	}

	return &result
}

// Eval evaluates the polynomial at x.
func (p *PointPolynomial) Eval(x *secp256k1.ModNScalar) *secp256k1.JacobianPoint {
	var result secp256k1.JacobianPoint // Zero value is identity point.

	if len(p.Coefs) == 0 {
		return &result
	}

	// Use Horner's method: a + b x + c x^2 + d x^3 = ((d x + c) x + b) x + a.
	result = *p.Coefs[len(p.Coefs)-1]

	for i := len(p.Coefs) - 2; i >= 0; i-- {
		secp256k1.ScalarMultNonConst(x, &result, &result)
		secp256k1.AddNonConst(&result, p.Coefs[i], &result)
	}

	return &result
}
