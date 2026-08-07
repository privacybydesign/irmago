package vcdmsdjwt

import (
	"crypto/ecdsa"
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// The test issuer key + x5c chain are the same fixtures the sdjwtvc tests use,
// so the issuer signature verifies against the trusted chain.
func testIssuerKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := encryption.DecodeEcdsaPrivateKey(testdata.IssuerPrivKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, key)
	return key
}

func testX5c(t *testing.T) []string {
	t.Helper()
	chain, err := utils.ParsePemCertificateChainToX5cFormat(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	require.NoError(t, err)
	return chain
}

func trustedContext() VerificationContext {
	return CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
}

const testIssuerURL = "https://openid4vc.staging.yivi.app"

// vcdmClaims builds a VCDM 2.0 claim tree with two selectively-disclosable
// credentialSubject leaves and a holder cnf key.
func vcdmClaims(t *testing.T, validFrom, validUntil string) []*sdjwt.ClaimElement {
	t.Helper()
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)
	return []*sdjwt.ClaimElement{
		sdjwt.Array(vcdm.ContextKey, sdjwt.Item(vcdm.ContextV2)),
		sdjwt.Array(vcdm.TypeKey, sdjwt.Item(vcdm.TypeVerifiableCredential), sdjwt.Item("ExampleCredential")),
		sdjwt.Claim(vcdm.IssuerKey, testIssuerURL),
		sdjwt.Claim(vcdm.ValidFromKey, validFrom),
		sdjwt.Claim(vcdm.ValidUntilKey, validUntil),
		sdjwt.Object(vcdm.CredentialSubjectKey,
			sdjwt.Claim("id", "did:example:holder"),
			sdjwt.SdClaim("given_name", "Alice"),
			sdjwt.SdClaim("family_name", "Smith"),
		),
		cnf,
	}
}

func signCredential(t *testing.T, typ string, claims []*sdjwt.ClaimElement) SdJwtVcdmKb {
	t.Helper()
	built, err := sdjwt.NewBuilder().
		WithPayload(claims...).
		WithIssuerCertificateChain(testX5c(t)).
		WithTyp(typ).
		Build(sdjwt.NewJwtCreator(testIssuerKey(t)))
	require.NoError(t, err)
	return SdJwtVcdmKb(built)
}

func TestHolder_ValidVcSdJwt_Succeeds(t *testing.T) {
	credential := signCredential(t, MediaTypeVcSdJwt, vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"))

	verified, err := NewHolderVerificationProcessor(trustedContext()).ParseAndVerifySdJwtVcdm(credential)
	require.NoError(t, err)

	// The disclosed document is a conforming VCDM credential.
	require.NoError(t, verified.Document.Validate())
	require.True(t, vcdm.IsVCDM(verified.Document))

	iss, err := verified.Document.IssuerID()
	require.NoError(t, err)
	require.Equal(t, testIssuerURL, iss)

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
	_, err := NewHolderVerificationProcessor(trustedContext()).ParseAndVerifySdJwtVcdm(credential)
	require.NoError(t, err)
}

// dc+sd-jwt carrying an IETF SD-JWT VC (a `vct` payload) verifies its signature
// but is not VCDM: the cornerstone dispatch must reject it here.
func TestHolder_DcSdJwtCarryingSdJwtVc_Rejected(t *testing.T) {
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)
	credential := signCredential(t, MediaTypeDcSdJwt, []*sdjwt.ClaimElement{
		sdjwt.Claim("vct", "https://example.com/credentials/identity"),
		sdjwt.Claim("iss", testIssuerURL),
		sdjwt.SdClaim("given_name", "Alice"),
		cnf,
	})

	_, err = NewHolderVerificationProcessor(trustedContext()).ParseAndVerifySdJwtVcdm(credential)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an SD-JWT-secured VCDM")
	require.Contains(t, err.Error(), vcdm.DataModelSdJwtVc.String())
}

func TestHolder_UnsupportedTypHeader_Rejected(t *testing.T) {
	credential := signCredential(t, "application/nonsense", vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"))
	_, err := NewHolderVerificationProcessor(trustedContext()).ParseAndVerifySdJwtVcdm(credential)
	require.Error(t, err)
}

func TestHolder_KeyBindingJwtPresent_Rejected(t *testing.T) {
	credential := signCredential(t, MediaTypeVcSdJwt, vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"))
	// Append a (fake) KB-JWT so the credential no longer ends in `~`.
	withKb := SdJwtVcdmKb(string(credential) + "fake.kb.jwt")

	_, err := NewHolderVerificationProcessor(trustedContext()).ParseAndVerifySdJwtVcdm(withKb)
	require.Error(t, err)
	require.Contains(t, err.Error(), "holder should not receive one")
}

func TestHolder_ExpiredValidUntil_Rejected(t *testing.T) {
	credential := signCredential(t, MediaTypeVcSdJwt, vcdmClaims(t, "2000-01-01T00:00:00Z", "2001-01-01T00:00:00Z"))
	_, err := NewHolderVerificationProcessor(trustedContext()).ParseAndVerifySdJwtVcdm(credential)
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

	matching := signCredential(t, MediaTypeVcSdJwt, append(claims, sdjwt.Claim("iss", testIssuerURL)))
	_, err := NewHolderVerificationProcessor(trustedContext()).ParseAndVerifySdJwtVcdm(matching)
	require.NoError(t, err)

	claims2 := vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z")
	mismatch := signCredential(t, MediaTypeVcSdJwt, append(claims2, sdjwt.Claim("iss", "https://someone.else.example")))
	_, err = NewHolderVerificationProcessor(trustedContext()).ParseAndVerifySdJwtVcdm(mismatch)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match VCDM issuer")
}
