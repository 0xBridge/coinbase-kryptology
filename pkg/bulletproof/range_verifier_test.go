package bulletproof

import (
	crand "crypto/rand"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestRangeVerifyHappyPath(t *testing.T) {
	curve := curves.ED25519()
	n := 256
	prover, err := NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.Random(crand.Reader)
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)
	proofGenerators := RangeProofGenerators{
		g: g,
		h: h,
		u: u,
	}
	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.NoError(t, err)

	verifier, err := NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := getcapV(v, gamma, g, h)
	verified, err := verifier.Verify(proof, capV, proofGenerators, n, transcriptVerifier)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestRangeVerifyNotInRange(t *testing.T) {
	curve := curves.ED25519()
	n := 2
	prover, err := NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.Random(crand.Reader)
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)
	proofGenerators := RangeProofGenerators{
		g: g,
		h: h,
		u: u,
	}
	transcript := merlin.NewTranscript("test")
	_, err = prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.Error(t, err)
}

func TestRangeVerifyNonRandom(t *testing.T) {
	curve := curves.ED25519()
	n := 2
	prover, err := NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.One()
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)
	proofGenerators := RangeProofGenerators{
		g: g,
		h: h,
		u: u,
	}
	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.NoError(t, err)

	verifier, err := NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := getcapV(v, gamma, g, h)
	verified, err := verifier.Verify(proof, capV, proofGenerators, n, transcriptVerifier)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestRangeVerifyFailsWithTooLargeVectors(t *testing.T) {
	curve := curves.ED25519()
	n := 128
	prover, err := NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.One()
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	proofGenerators := getProofGenerators(*curve)

	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.NoError(t, err)

	// Increase the size of one of the proof vectors
	proof.ipp.capRs = append(proof.ipp.capRs, curve.Point.Random(crand.Reader))
	proof.ipp.capLs = append(proof.ipp.capLs, curve.Point.Random(crand.Reader))

	verifier, err := NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := getcapV(v, gamma, g, h)
	verified, err := verifier.Verify(proof, capV, proofGenerators, n, transcriptVerifier)
	require.False(t, verified)
	require.Error(t, err)
	require.Equal(t, "ipp point arrays are too large", err.Error())
}

func TestRangeVerifyFailsWithVectorsOfDiffSize(t *testing.T) {
	curve := curves.ED25519()
	n := 128
	prover, err := NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.One()
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	proofGenerators := getProofGenerators(*curve)

	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.NoError(t, err)

	// Modify the size of one of the proof vectors
	proof.ipp.capRs = append(proof.ipp.capRs, curve.Point.Random(crand.Reader))

	verifier, err := NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := getcapV(v, gamma, g, h)
	verified, err := verifier.Verify(proof, capV, proofGenerators, n, transcriptVerifier)
	require.False(t, verified)
	require.Error(t, err)
	require.Equal(t, "ipp capLs and capRs must be same length", err.Error())
}

func TestRangeVerifyFailsWithNilVectors(t *testing.T) {
	curve := curves.ED25519()
	n := 128
	prover, err := NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.One()
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	proofGenerators := getProofGenerators(*curve)

	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.NoError(t, err)

	verifier, err := NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := getcapV(v, gamma, g, h)

	// Modify the size of one of the proof vectors
	proof.ipp.capRs = nil
	verified, err := verifier.Verify(proof, capV, proofGenerators, n, transcriptVerifier)
	require.False(t, verified)
	require.Error(t, err)
	require.Equal(t, "proof does not contain IPP capRs", err.Error())

	proof.ipp.capLs = nil
	verified, err = verifier.Verify(proof, capV, proofGenerators, n, transcriptVerifier)
	require.False(t, verified)
	require.Error(t, err)
	require.Equal(t, "proof does not contain IPP capLs", err.Error())

	proof.ipp = nil
	verified, err = verifier.Verify(proof, capV, proofGenerators, n, transcriptVerifier)
	require.False(t, verified)
	require.Error(t, err)
	require.Equal(t, "proof does not contain IPP", err.Error())
}

func getProofGenerators(curve curves.Curve) RangeProofGenerators {
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)
	return RangeProofGenerators{
		g: g,
		h: h,
		u: u,
	}
}
