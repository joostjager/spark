package secretsharing

import (
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Helper function to create a point from a scalar (g^scalar)
func pointFromScalar(scalar *secp256k1.ModNScalar) *secp256k1.JacobianPoint {
	point := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(scalar, point)
	return point
}

// Test basic ScalarPolynomial creation and evaluation
func TestScalarPolynomialBasic(t *testing.T) {
	// Test constant polynomial (degree 0)
	secret := scalarFromInt(42)
	poly, err := NewScalarPolynomialSharing(secret, 0)
	if err != nil {
		t.Fatalf("Failed to create constant polynomial: %v", err)
	}

	if len(poly.Coefs) != 1 {
		t.Errorf("Expected 1 coefficient for degree 0, got %d", len(poly.Coefs))
	}

	if !poly.Coefs[0].Equals(secret) {
		t.Errorf("Constant term should equal secret")
	}

	// Test evaluation at various points
	testPoints := []uint32{0, 1, 5, 100}
	for _, x := range testPoints {
		xScalar := scalarFromInt(x)
		result := poly.Eval(xScalar)
		if !result.Equals(secret) {
			t.Errorf("Constant polynomial should return %s at x=%d, got %s",
				secret.String(), x, result.String())
		}
	}
}

// Test ScalarPolynomial with higher degrees
func TestScalarPolynomialDegrees(t *testing.T) {
	secret := scalarFromInt(123)

	// Test polynomials of various degrees
	degrees := []int{1, 2, 5, 10}

	for _, degree := range degrees {
		poly, err := NewScalarPolynomialSharing(secret, degree)
		if err != nil {
			t.Fatalf("Failed to create polynomial of degree %d: %v", degree, err)
		}

		if len(poly.Coefs) != degree+1 {
			t.Errorf("Expected %d coefficients for degree %d, got %d",
				degree+1, degree, len(poly.Coefs))
		}

		// Constant term should be the secret
		if !poly.Coefs[0].Equals(secret) {
			t.Errorf("Constant term should equal secret for degree %d", degree)
		}

		// Evaluation at x=0 should return the secret
		zero := scalarFromInt(0)
		result := poly.Eval(zero)
		if !result.Equals(secret) {
			t.Errorf("P(0) should equal secret for degree %d, got %s",
				degree, result.String())
		}
	}
}

// Test manual polynomial creation and evaluation
func TestManualScalarPolynomial(t *testing.T) {
	// Create polynomial: 5 + 3x + 2x^2
	coefs := []*secp256k1.ModNScalar{
		scalarFromInt(5), // constant term
		scalarFromInt(3), // x coefficient
		scalarFromInt(2), // x^2 coefficient
	}

	poly := &ScalarPolynomial{Coefs: coefs}

	// Test known evaluations
	testCases := []struct {
		x        uint32
		expected uint32
	}{
		{0, 5},  // 5 + 3*0 + 2*0^2 = 5
		{1, 10}, // 5 + 3*1 + 2*1^2 = 10
		{2, 19}, // 5 + 3*2 + 2*2^2 = 19
		{3, 32}, // 5 + 3*3 + 2*3^2 = 32
	}

	for _, tc := range testCases {
		x := scalarFromInt(tc.x)
		expected := scalarFromInt(tc.expected)
		result := poly.Eval(x)

		if !result.Equals(expected) {
			t.Errorf("P(%d) expected %d, got %s", tc.x, tc.expected, result.String())
		}
	}
}

// Test PointPolynomial creation and evaluation
func TestPointPolynomial(t *testing.T) {
	// Create polynomial with point coefficients: G*5 + G*3*x + G*2*x^2
	coefs := []*secp256k1.JacobianPoint{
		pointFromScalar(scalarFromInt(5)), // G*5
		pointFromScalar(scalarFromInt(3)), // G*3
		pointFromScalar(scalarFromInt(2)), // G*2
	}

	poly := &PointPolynomial{Coefs: coefs}

	// Test evaluation - should give same results as scalar version but as points
	testCases := []struct {
		x        uint32
		expected uint32
	}{
		{0, 5},
		{1, 10},
		{2, 19},
		{3, 32},
	}

	for _, tc := range testCases {
		x := scalarFromInt(tc.x)
		expectedPoint := pointFromScalar(scalarFromInt(tc.expected))
		result := poly.Eval(x)

		if !PointEqual(result, expectedPoint) {
			t.Errorf("Point polynomial P(%d) gave incorrect result", tc.x)
		}
	}
}

// Test Lagrange interpolation for scalars
func TestScalarLagrangeInterpolation(t *testing.T) {
	// Test with known polynomial: 7 + 4x + 2x^2
	secret := scalarFromInt(7)
	coefs := []*secp256k1.ModNScalar{
		secret,
		scalarFromInt(4),
		scalarFromInt(2),
	}
	poly := &ScalarPolynomial{Coefs: coefs}

	// Generate evaluation points
	points := []*ScalarEval{
		{X: scalarFromInt(1), Y: poly.Eval(scalarFromInt(1))}, // P(1) = 13
		{X: scalarFromInt(2), Y: poly.Eval(scalarFromInt(2))}, // P(2) = 23
		{X: scalarFromInt(3), Y: poly.Eval(scalarFromInt(3))}, // P(3) = 37
	}

	// Reconstruct at x=0 (should give us the secret)
	reconstructed := ReconstructScalar(points)

	if !reconstructed.Equals(secret) {
		t.Errorf("Scalar Lagrange interpolation failed")
		t.Errorf("Expected: %s", secret.String())
		t.Errorf("Got: %s", reconstructed.String())
	}
}

// Test Lagrange interpolation for points
func TestPointLagrangeInterpolation(t *testing.T) {
	// Test with known polynomial over points: G*7 + G*4*x + G*2*x^2
	secret := scalarFromInt(7)
	secretPoint := pointFromScalar(secret)

	coefs := []*secp256k1.JacobianPoint{
		secretPoint,
		pointFromScalar(scalarFromInt(4)),
		pointFromScalar(scalarFromInt(2)),
	}
	poly := &PointPolynomial{Coefs: coefs}

	// Generate evaluation points
	points := []*PointEval{
		{X: scalarFromInt(1), Y: poly.Eval(scalarFromInt(1))},
		{X: scalarFromInt(2), Y: poly.Eval(scalarFromInt(2))},
		{X: scalarFromInt(3), Y: poly.Eval(scalarFromInt(3))},
	}

	// Reconstruct at x=0 (should give us the secret point)
	reconstructed := ReconstructPoint(points)

	if !PointEqual(reconstructed, secretPoint) {
		t.Errorf("Point Lagrange interpolation failed to reconstruct secret point")
	}
}

// Test threshold secret sharing scenario
func TestThresholdSecretSharing(t *testing.T) {
	secret := scalarFromInt(999)
	threshold := 3
	numShares := 5

	// Create polynomial for (3,5) threshold scheme
	poly, err := NewScalarPolynomialSharing(secret, threshold-1)
	if err != nil {
		t.Fatalf("Failed to create polynomial: %v", err)
	}

	// Generate shares
	shares := make([]*ScalarEval, numShares)
	for i := range numShares {
		x := scalarFromInt(uint32(i + 1)) // Party IDs 1,2,3,4,5
		y := poly.Eval(x)
		shares[i] = &ScalarEval{X: x, Y: y}
	}

	// Test that any 3 shares can reconstruct the secret
	for i := 0; i <= numShares-threshold; i++ {
		subset := shares[i : i+threshold]
		reconstructed := ReconstructScalar(subset)

		if !reconstructed.Equals(secret) {
			t.Errorf("Failed to reconstruct secret with shares %d-%d",
				i+1, i+threshold)
		}
	}

	// Test that 2 shares cannot reconstruct (should give wrong result)
	twoShares := shares[0:2]
	wrongReconstruction := ReconstructScalar(twoShares)

	if wrongReconstruction.Equals(secret) {
		t.Errorf("Two shares should not be able to reconstruct the secret")
	}
}

// Test edge cases and error conditions
func TestPolynomialEdgeCases(t *testing.T) {
	// Test empty polynomial
	emptyPoly := &ScalarPolynomial{Coefs: []*secp256k1.ModNScalar{}}
	x := scalarFromInt(5)
	result := emptyPoly.Eval(x)
	zero := scalarFromInt(0)

	if !result.Equals(zero) {
		t.Errorf("Empty polynomial should evaluate to zero")
	}

	// Test single point interpolation
	singlePoint := []*ScalarEval{
		{X: scalarFromInt(5), Y: scalarFromInt(42)},
	}

	// This should reconstruct a constant polynomial
	reconstructed := ReconstructScalar(singlePoint)
	expected := scalarFromInt(42)

	if !reconstructed.Equals(expected) {
		t.Errorf("Single point interpolation failed")
	}
}

// Test Lagrange basis function
func TestLagrangeBasis(t *testing.T) {
	// Test with known x values
	xs := []*secp256k1.ModNScalar{
		scalarFromInt(1),
		scalarFromInt(2),
		scalarFromInt(3),
	}

	// Test L_0(0) for first basis polynomial
	// L_0(0) = (0-2)(0-3) / ((1-2)(1-3)) = 6/2 = 3
	basis0 := lagrangeBasisAtZero(xs, 0)
	expected0 := scalarFromInt(3)

	if !basis0.Equals(expected0) {
		t.Errorf("L_0(0) expected 3, got %s", basis0.String())
	}

	// Test L_1(0) for second basis polynomial
	// L_1(0) = (0-1)(0-3) / ((2-1)(2-3)) = 3/(-1) = -3
	basis1 := lagrangeBasisAtZero(xs, 1)
	expected1 := new(secp256k1.ModNScalar)
	expected1.NegateVal(scalarFromInt(3))

	if !basis1.Equals(expected1) {
		t.Errorf("L_1(0) expected -3, got %s", basis1.String())
	}

	// Test L_2(0) for third basis polynomial
	// L_2(0) = (0-1)(0-2) / ((3-1)(3-2)) = 2/2 = 1
	basis2 := lagrangeBasisAtZero(xs, 2)
	expected2 := scalarFromInt(1)

	if !basis2.Equals(expected2) {
		t.Errorf("L_2(0) expected 1, got %s", basis2.String())
	}

	// Verify that basis polynomials sum to 1 at x=0
	sum := new(secp256k1.ModNScalar)
	sum.Add(basis0).Add(basis1).Add(basis2)
	one := scalarFromInt(1)

	if !sum.Equals(one) {
		t.Errorf("Lagrange basis polynomials should sum to 1, got %s", sum.String())
	}
}

// Benchmark polynomial evaluation
func BenchmarkScalarPolynomialEval(b *testing.B) {
	secret := scalarFromInt(12345)
	poly, err := NewScalarPolynomialSharing(secret, 10) // degree 10
	if err != nil {
		b.Fatalf("Failed to create polynomial: %v", err)
	}

	x := scalarFromInt(7)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = poly.Eval(x)
	}
}

// Benchmark Lagrange interpolation
func BenchmarkLagrangeInterpolation(b *testing.B) {
	// Create test data
	secret := scalarFromInt(54321)
	poly, err := NewScalarPolynomialSharing(secret, 9) // degree 9, threshold 10
	if err != nil {
		b.Fatalf("Failed to create polynomial: %v", err)
	}

	// Generate 10 points
	points := make([]*ScalarEval, 10)
	for i := range 10 {
		x := scalarFromInt(uint32(i + 1))
		y := poly.Eval(x)
		points[i] = &ScalarEval{X: x, Y: y}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ReconstructScalar(points)
	}
}

// Test consistency between scalar and point polynomials
func TestScalarPointConsistency(t *testing.T) {
	// Create matching scalar and point polynomials
	scalarCoefs := []*secp256k1.ModNScalar{
		scalarFromInt(10),
		scalarFromInt(20),
		scalarFromInt(30),
	}

	pointCoefs := make([]*secp256k1.JacobianPoint, len(scalarCoefs))
	for i, coef := range scalarCoefs {
		pointCoefs[i] = pointFromScalar(coef)
	}

	scalarPoly := &ScalarPolynomial{Coefs: scalarCoefs}
	pointPoly := &PointPolynomial{Coefs: pointCoefs}

	// Test that evaluations are consistent
	testPoints := []uint32{0, 1, 2, 5, 10}

	for _, xVal := range testPoints {
		x := scalarFromInt(xVal)

		scalarResult := scalarPoly.Eval(x)
		pointResult := pointPoly.Eval(x)
		expectedPoint := pointFromScalar(scalarResult)

		if !PointEqual(pointResult, expectedPoint) {
			t.Errorf("Inconsistency at x=%d between scalar and point polynomial", xVal)
		}
	}
}
