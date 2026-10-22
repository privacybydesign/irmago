package openid4vci

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// batchInstancesToRequest is the only thing standing between an issuer's
// advertised ceiling and how many keypairs the device generates, so the bound
// matters more than the arithmetic.
func TestBatchInstancesToRequest(t *testing.T) {
	tests := []struct {
		name       string
		advertised uint
		want       uint
	}{
		{
			// The EUDI reference issuer's current value, which is its ceiling and
			// not a demand. Taking it literally meant a hundred enclave keygens
			// per issuance; the Blueprint recommends thirty.
			name:       "the reference issuer's ceiling of 100 is clamped to the Blueprint's thirty",
			advertised: 100,
			want:       30,
		},
		{
			// batch_size is a maximum, not an instruction: an issuer willing to
			// sign more does not oblige the wallet to ask for more.
			name:       "an issuer ceiling above the wallet's limit is clamped, not refused",
			advertised: 5000,
			want:       maxBatchInstances,
		},
		{
			// The case that motivated this: unbounded before, the device would
			// have tried to mint a million keypairs.
			name:       "an implausible ceiling cannot make the device mint unboundedly",
			advertised: 1_000_000,
			want:       maxBatchInstances,
		},
		{
			// An issuer whose ceiling is exactly the Blueprint's recommendation
			// is honoured in full, with nothing clamped.
			name:       "a ceiling equal to the Blueprint recommendation is taken as-is",
			advertised: 30,
			want:       30,
		},
		{
			// A ceiling below the recommendation still governs: the wallet must
			// never ask for more proofs than the issuer said it would accept.
			name:       "a ceiling below the recommendation still governs",
			advertised: 5,
			want:       5,
		},
		{
			name:       "one instance stays one",
			advertised: 1,
			want:       1,
		},
		{
			// Metadata validation already refuses batch_size <= 1, so this is
			// belt-and-braces: it must degrade to the non-batch case rather than
			// to zero, which would request no proofs at all.
			name:       "zero degrades to a single instance rather than none",
			advertised: 0,
			want:       1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, batchInstancesToRequest(test.advertised))
		})
	}
}

// Whatever the cap is set to, the two properties that make it a safety bound have
// to hold for every input, not just the tabulated ones.
func TestBatchInstancesToRequest_IsAlwaysBoundedAndNonZero(t *testing.T) {
	for _, advertised := range []uint{0, 1, 2, 29, 30, 31, 99, 100, 101, 4095, 1 << 20, ^uint(0)} {
		t.Run(fmt.Sprintf("advertised=%d", advertised), func(t *testing.T) {
			got := batchInstancesToRequest(advertised)

			require.LessOrEqual(t, got, maxBatchInstances,
				"the wallet must never generate more keypairs than its own limit")
			require.GreaterOrEqual(t, got, uint(1),
				"a credential request with no proofs would be issued no instances at all")
			require.LessOrEqual(t, got, max(advertised, 1),
				"the wallet must never ask for more than the issuer said it would accept")
		})
	}
}
