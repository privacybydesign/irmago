package vcdmsdjwt

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func verifiedWithCnf(cnf *sdjwt.CnfField) *VerifiedSdJwtVcdm {
	return &VerifiedSdJwtVcdm{
		RegisteredClaims: sdjwt.RegisteredClaims{Confirm: cnf},
	}
}

func TestCheckKeyBindingConfirmationUniqueness_DistinctKidsSucceed(t *testing.T) {
	kid1, kid2 := "did:jwk:one#0", "did:jwk:two#0"
	err := CheckKeyBindingConfirmationUniqueness([]*VerifiedSdJwtVcdm{
		verifiedWithCnf(&sdjwt.CnfField{Kid: &kid1}),
		verifiedWithCnf(&sdjwt.CnfField{Kid: &kid2}),
	})
	require.NoError(t, err)
}

func TestCheckKeyBindingConfirmationUniqueness_DuplicateKidFails(t *testing.T) {
	kid := "did:jwk:one#0"
	err := CheckKeyBindingConfirmationUniqueness([]*VerifiedSdJwtVcdm{
		verifiedWithCnf(&sdjwt.CnfField{Kid: &kid}),
		verifiedWithCnf(&sdjwt.CnfField{Kid: &kid}),
	})
	require.Error(t, err)
}

func TestCheckKeyBindingConfirmationUniqueness_DuplicateJwkFails(t *testing.T) {
	key := testdata.ParseHolderPubJwk()
	var jwkKey jwk.Key = key
	err := CheckKeyBindingConfirmationUniqueness([]*VerifiedSdJwtVcdm{
		verifiedWithCnf(&sdjwt.CnfField{Jwk: &jwkKey}),
		verifiedWithCnf(&sdjwt.CnfField{Jwk: &jwkKey}),
	})
	require.Error(t, err)
}

func TestCheckKeyBindingConfirmationUniqueness_MissingCnfIsAllowed(t *testing.T) {
	err := CheckKeyBindingConfirmationUniqueness([]*VerifiedSdJwtVcdm{
		verifiedWithCnf(nil),
		verifiedWithCnf(nil),
	})
	require.NoError(t, err)
}
