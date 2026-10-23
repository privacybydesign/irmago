package vcdmsdjwt

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// Test helpers (test issuer key/cert, CreateTestVerificationContext, the fixture
// claim-tree builders, signCredential) live in test_utils.go.

func TestHolder_ValidVcSdJwt_Succeeds(t *testing.T) {
	credential := signCredential(t, MediaTypeVcSdJwt, vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"))

	verified, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
	require.NoError(t, err)

	// The disclosed document is a conforming VCDM credential.
	require.NoError(t, verified.Document.Validate())
	require.True(t, vcdm.IsVCDM(verified.Document))

	iss, err := verified.Document.IssuerID()
	require.NoError(t, err)
	require.Equal(t, TestIssuerURL, iss)

	// Both selectively-disclosed leaves were merged into credentialSubject.
	subs, err := verified.Document.CredentialSubjects()
	require.NoError(t, err)
	require.Equal(t, "Alice", subs[0]["given_name"])
	require.Equal(t, "Smith", subs[0]["family_name"])
	require.Len(t, verified.Disclosures, 2)

	// No KB-JWT on receipt; holder cnf key retained and resolvable.
	require.Nil(t, verified.KeyBindingJwt)
	require.NotNil(t, verified.RegisteredClaims.Confirm)
	key, err := verified.HolderPublicKey()
	require.NoError(t, err)
	require.NotNil(t, key)

	// The raw credential is retained for storage.
	require.NotEmpty(t, verified.GetRawSdJwtVcdm())
}

// dc+sd-jwt is content-dispatched: a VCDM payload under it is accepted.
func TestHolder_ValidDcSdJwtCarryingVcdm_Succeeds(t *testing.T) {
	credential := signCredential(t, MediaTypeDcSdJwt, vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"))
	_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
	require.NoError(t, err)
}

// dc+sd-jwt carrying an IETF SD-JWT VC (a `vct` payload) verifies its signature
// but is not VCDM: the cornerstone dispatch must reject it here.
func TestHolder_DcSdJwtCarryingSdJwtVc_Rejected(t *testing.T) {
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)
	credential := signCredential(t, MediaTypeDcSdJwt, []*sdjwt.ClaimElement{
		sdjwt.Claim("vct", "https://example.com/credentials/identity"),
		sdjwt.Claim("iss", TestIssuerURL),
		sdjwt.SdClaim("given_name", "Alice"),
		cnf,
	})

	_, err = NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an SD-JWT-secured VCDM")
	require.Contains(t, err.Error(), vcdm.DataModelSdJwtVc.String())
}

func TestHolder_UnsupportedTypHeader_Rejected(t *testing.T) {
	credential := signCredential(t, "application/nonsense", vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"))
	_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
	require.Error(t, err)
}

func TestHolder_KeyBindingJwtPresent_Rejected(t *testing.T) {
	credential := signCredential(t, MediaTypeVcSdJwt, vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"))
	// Append a (fake) KB-JWT so the credential no longer ends in `~`.
	withKb := SdJwtVcdmKb(string(credential) + "fake.kb.jwt")

	_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(withKb)
	require.Error(t, err)
	require.Contains(t, err.Error(), "holder should not receive one")
}

func TestHolder_ExpiredValidUntil_Rejected(t *testing.T) {
	credential := signCredential(t, MediaTypeVcSdJwt, vcdmClaims(t, "2000-01-01T00:00:00Z", "2001-01-01T00:00:00Z"))
	_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired")
}

func TestHolder_UntrustedIssuerCert_Rejected(t *testing.T) {
	credential := signCredential(t, MediaTypeVcSdJwt, vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"))
	// Trust a different chain than the one that signed the credential.
	untrusted := CreateDefaultVerificationContext(testdata.IssuerCertChain_irma_app_Bytes)

	_, err := NewHolderVerificationProcessor(untrusted).ParseAndVerifySdJwtVcdm(credential)
	require.Error(t, err)
	require.Contains(t, err.Error(), "certificate")
}

// VC-JOSE-COSE §3.2.1: a JWT `iss` that disagrees with the VCDM `issuer` is
// rejected; agreement is accepted.
func TestHolder_JwtIssMustMatchVcdmIssuer(t *testing.T) {
	claims := vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z")

	matching := signCredential(t, MediaTypeVcSdJwt, append(claims, sdjwt.Claim("iss", TestIssuerURL)))
	_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(matching)
	require.NoError(t, err)

	claims2 := vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z")
	mismatch := signCredential(t, MediaTypeVcSdJwt, append(claims2, sdjwt.Claim("iss", "https://someone.else.example")))
	_, err = NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(mismatch)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match VCDM issuer")
}
