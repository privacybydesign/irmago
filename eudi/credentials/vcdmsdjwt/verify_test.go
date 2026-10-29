package vcdmsdjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/privacybydesign/irmago/eudi/didjwk"

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

// dc+sd-jwt is IETF SD-JWT VC: a VCDM payload under it fits neither spec.
func TestHolder_DcSdJwtCarryingVcdm_Rejected(t *testing.T) {
	credential := signCredential(t, "dc+sd-jwt", vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"))
	_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
	require.Error(t, err)
}

// A `vct` payload signed as vc+sd-jwt verifies its signature but is not VCDM,
// so the payload gate rejects it.
func TestHolder_VcSdJwtCarryingSdJwtVc_Rejected(t *testing.T) {
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)
	credential := signCredential(t, MediaTypeVcSdJwt, []*sdjwt.ClaimElement{
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

// validFrom/validUntil are the validity of the data, which a verifier judges;
// the wallet accepts the credential whatever they say.
func TestHolder_DocumentValidityIsLeftToTheVerifier(t *testing.T) {
	for name, window := range map[string][2]string{
		"validUntil in the past":  {"2000-01-01T00:00:00Z", "2001-01-01T00:00:00Z"},
		"validFrom in the future": {"2099-01-01T00:00:00Z", "2100-01-01T00:00:00Z"},
	} {
		t.Run(name, func(t *testing.T) {
			credential := signCredential(t, MediaTypeVcSdJwt, vcdmClaims(t, window[0], window[1]))
			_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
			require.NoError(t, err)
		})
	}
}

// exp is when the signature stops being valid: past it, the credential itself
// is no longer valid, so the wallet refuses it.
func TestHolder_ExpiredJwt_Rejected(t *testing.T) {
	claims := append(vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"), sdjwt.Claim("exp", int64(978307200))) // 2001-01-01
	credential := signCredential(t, MediaTypeVcSdJwt, claims)
	_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
	require.ErrorContains(t, err, "expired")
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

// A credential signed under a trusted x5c chain cannot claim another issuer's
// identity: the VCDM `issuer` must name the leaf certificate, with or without a
// matching JWT `iss`.
func TestHolder_VcdmIssuerMustNameTheX5cCertificate(t *testing.T) {
	const otherIssuer = "https://someone.else.example"
	for name, extra := range map[string][]*sdjwt.ClaimElement{
		"without iss":         nil,
		"with a matching iss": {sdjwt.Claim("iss", otherIssuer)},
	} {
		t.Run(name, func(t *testing.T) {
			claims := vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z")
			claims[2] = sdjwt.Claim(vcdm.IssuerKey, otherIssuer)
			credential := signCredential(t, MediaTypeVcSdJwt, append(claims, extra...))

			_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
			require.ErrorContains(t, err, `VCDM issuer "https://someone.else.example" is not a SAN of the issuer certificate`)
		})
	}
}

// The properties a verifier needs to validate a credential must not be
// selectively disclosable: VC-JOSE-COSE §3.2.1 says they SHOULD NOT be, and
// OpenID4VP §6.4 does not let the wallet disclose them when the verifier did
// not ask, so a presentation would lack them.
func TestHolder_SelectivelyDisclosableValidationProperty_Rejected(t *testing.T) {
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)
	subject := sdjwt.Object(vcdm.CredentialSubjectKey, sdjwt.SdClaim("given_name", "Alice"))
	contextClaim := sdjwt.Array(vcdm.ContextKey, sdjwt.Item(vcdm.ContextV2))
	typeClaim := sdjwt.Array(vcdm.TypeKey, sdjwt.Item(vcdm.TypeVerifiableCredential), sdjwt.Item("ExampleCredential"))
	issuer := sdjwt.Claim(vcdm.IssuerKey, TestIssuerURL)

	cases := map[string]struct {
		property string
		claims   []*sdjwt.ClaimElement
	}{
		"type as a whole": {"type", []*sdjwt.ClaimElement{
			contextClaim, sdjwt.SdArray(vcdm.TypeKey, sdjwt.Item(vcdm.TypeVerifiableCredential), sdjwt.Item("ExampleCredential")), issuer, subject, cnf,
		}},
		"one type value": {"type", []*sdjwt.ClaimElement{
			contextClaim, sdjwt.Array(vcdm.TypeKey, sdjwt.Item(vcdm.TypeVerifiableCredential), sdjwt.SdItem("ExampleCredential")), issuer, subject, cnf,
		}},
		"a field of credentialStatus": {"credentialStatus", []*sdjwt.ClaimElement{
			contextClaim, typeClaim, issuer, subject, cnf,
			sdjwt.Object(vcdm.CredentialStatusKey,
				sdjwt.Claim("type", "BitstringStatusListEntry"),
				sdjwt.Claim("statusPurpose", "revocation"),
				sdjwt.SdClaim("statusListIndex", "7"),
				sdjwt.Claim("statusListCredential", "https://issuer.example/lists/1"),
			),
		}},
		"validUntil": {"validUntil", []*sdjwt.ClaimElement{
			contextClaim, typeClaim, issuer, subject, cnf, sdjwt.SdClaim(vcdm.ValidUntilKey, "2035-01-01T00:00:00Z"),
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			credential := signCredential(t, MediaTypeVcSdJwt, c.claims)
			_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
			require.ErrorContains(t, err, fmt.Sprintf("%q is selectively disclosable", c.property))
		})
	}
}

// Other envelope properties may be selectively disclosable: a verifier does not
// need the credential id to validate it.
func TestHolder_SelectivelyDisclosableId_Accepted(t *testing.T) {
	claims := append(vcdmClaims(t, "2020-01-01T00:00:00Z", "2035-01-01T00:00:00Z"), sdjwt.SdClaim(vcdm.IDKey, "urn:uuid:5d2c3c9e-6c9f-4bb0-8a7e-1c1e2c3d4e5f"))
	credential := signCredential(t, MediaTypeVcSdJwt, claims)
	_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(credential)
	require.NoError(t, err)
}

// withKid is a JwtCreator that names the signing key with a kid header.
type withKid struct {
	sdjwt.JwtCreator
	kid string
}

func (c withKid) CreateSignedJwt(header map[string]any, payload string) (string, error) {
	delete(header, "x5c") // the builder sets it, empty, when there is no chain
	header["kid"] = c.kid
	return c.JwtCreator.CreateSignedJwt(header, payload)
}

// signWithDidJwk signs a credential with a fresh did:jwk key, named by an
// absolute kid and no iss, and with the given VCDM issuer; issuer "" means the
// did:jwk itself.
func signWithDidJwk(t *testing.T, issuer string) SdJwtVcdmKb {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicJwk, err := jwk.Import[jwk.Key](key.Public())
	require.NoError(t, err)
	doc, err := (&didjwk.DocumentBuilder{}).FromJwk(publicJwk)
	require.NoError(t, err)
	if issuer == "" {
		issuer = doc.ID
	}
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)

	built, err := sdjwt.NewBuilder().
		WithPayload(
			sdjwt.Array(vcdm.ContextKey, sdjwt.Item(vcdm.ContextV2)),
			sdjwt.Array(vcdm.TypeKey, sdjwt.Item(vcdm.TypeVerifiableCredential), sdjwt.Item("ExampleCredential")),
			sdjwt.Claim(vcdm.IssuerKey, issuer),
			sdjwt.Object(vcdm.CredentialSubjectKey, sdjwt.SdClaim("given_name", "Alice")),
			cnf,
		).
		WithTyp(MediaTypeVcSdJwt).
		Build(withKid{sdjwt.NewJwtCreator(key), doc.VerificationMethod[0].ID})
	require.NoError(t, err)
	return SdJwtVcdmKb(built)
}

// VC-JOSE-COSE §4.2: without iss, the kid is an absolute URL to the issuer's
// verification method. The key is then its DID's, which must be the issuer.
func TestHolder_DidKidWithoutIss(t *testing.T) {
	t.Run("the issuer's own key is accepted", func(t *testing.T) {
		_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(signWithDidJwk(t, ""))
		require.NoError(t, err)
	})
	t.Run("another DID's key is refused", func(t *testing.T) {
		_, err := NewHolderVerificationProcessor(CreateTestVerificationContext()).ParseAndVerifySdJwtVcdm(signWithDidJwk(t, "did:web:issuer.example"))
		require.ErrorContains(t, err, `not of the VCDM issuer "did:web:issuer.example"`)
	})
}
