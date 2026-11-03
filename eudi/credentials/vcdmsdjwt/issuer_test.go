package vcdmsdjwt

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/stretchr/testify/require"
)

// The issuer-side generator and the holder-side verifier round-trip: minting a
// fixture and verifying it end-to-end (in Go) is the M1 acceptance check.
func TestIssueTestSdJwtVcdm_RoundTrips(t *testing.T) {
	cases := map[string]func(*testing.T) []*sdjwt.ClaimElement{
		"AcademicBaseCredential": AcademicBaseCredentialClaims,
		"W3CExampleCredential":   W3CExampleCredentialClaims,
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			credential := SdJwtVcdmKb(IssueTestSdJwtVcdm(t, claims(t)))

			verified, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).
				ParseAndVerifySdJwtVcdm(credential)
			require.NoError(t, err)

			require.NoError(t, verified.Document.Validate())
			require.True(t, vcdm.IsVCDM(verified.Document))
			iss, err := verified.Document.IssuerID()
			require.NoError(t, err)
			require.Equal(t, TestIssuerURL, iss)
		})
	}
}

func TestIssueTestSdJwtVcdm_AcademicClaimsDisclosed(t *testing.T) {
	credential := SdJwtVcdmKb(IssueTestSdJwtVcdm(t, AcademicBaseCredentialClaims(t)))
	verified, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).
		ParseAndVerifySdJwtVcdm(credential)
	require.NoError(t, err)

	subs, err := verified.Document.CredentialSubjects()
	require.NoError(t, err)
	require.Equal(t, "b2c3d4e5@university.example", subs[0]["eduperson_unique_id"])
	require.Equal(t, "university.example", subs[0]["schac_home_organization"])
	require.True(t, verified.Document.HasType("AcademicBaseCredential"))
}

func TestSdJwtVcdmBuilder_RequiresContextAndType(t *testing.T) {
	creator := sdjwt.NewJwtCreator(testIssuerKey(t))

	missingContext := []*sdjwt.ClaimElement{
		sdjwt.Array(vcdm.TypeKey, sdjwt.Item(vcdm.TypeVerifiableCredential)),
		sdjwt.Object(vcdm.CredentialSubjectKey, sdjwt.Claim("id", "did:example:1")),
	}
	_, err := NewSdJwtVcdmBuilder().WithPayload(missingContext...).Build(creator)
	require.Error(t, err)
	require.Contains(t, err.Error(), vcdm.ContextKey)

	missingType := []*sdjwt.ClaimElement{
		sdjwt.Array(vcdm.ContextKey, sdjwt.Item(vcdm.ContextV2)),
		sdjwt.Object(vcdm.CredentialSubjectKey, sdjwt.Claim("id", "did:example:1")),
	}
	_, err = NewSdJwtVcdmBuilder().WithPayload(missingType...).Build(creator)
	require.Error(t, err)
	require.Contains(t, err.Error(), vcdm.TypeKey)
}

// The JSON fixtures are conforming VCDM 2.0 documents — the structural-
// validation vectors the acceptance harness checks against.
func TestW3CFixtures_PassStructuralValidation(t *testing.T) {
	for name, js := range map[string]string{
		"AcademicBaseCredential": AcademicBaseCredentialJSON,
		"W3CExampleCredential":   W3CExampleCredentialJSON,
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			require.NoError(t, json.Unmarshal([]byte(js), &m))
			require.True(t, vcdm.IsVCDM(m))
			require.NoError(t, vcdm.Document(m).Validate())
		})
	}
}
