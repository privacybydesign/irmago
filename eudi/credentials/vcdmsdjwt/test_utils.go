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

// This file is the in-repo issuer-side acceptance harness for SD-JWT-secured
// VCDM (map ticket #680): a reusable generator that mints SD-JWT-secured VCDM
// credentials in Go — the counterpart to how eudi/credentials/sdjwtvc mints
// SD-JWT VCs in-test — plus canonical W3C VCDM 2.0 fixtures. Because the shared
// mock OpenID4VCI issuer signs via an external agent (eduwallet/veramo-agent)
// that this repo can't drive for VCDM yet, and because the wallet receive path
// isn't wired for VCDM until the OpenID4VCI-integration ticket lands, M1
// acceptance is exercised here in Go rather than over HTTP. The exported
// helpers are reusable by the integration tests that ticket will add.
//
// It reuses the same test issuer key + x5c chain as the sdjwtvc tests, so an
// issued credential verifies against the trusted chain in CreateTestVerificationContext.

// TestIssuerURL is the issuer identifier used by the fixtures; it matches the
// subject of the test issuer certificate chain.
const TestIssuerURL = "https://openid4vc.staging.yivi.app"

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

// CreateTestVerificationContext returns a holder verification context trusting
// the test issuer certificate chain. Exported for reuse by the OpenID4VCI
// integration tests.
func CreateTestVerificationContext() VerificationContext {
	return CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
}

// IssueTestSdJwtVcdm mints an SD-JWT-secured VCDM credential from a VCDM claim
// tree, signed with the test issuer key + x5c chain (via SdJwtVcdmBuilder, so
// `typ` = vc+sd-jwt). This is the reusable issuer-side generator: hand it a
// fixture claim tree (e.g. AcademicBaseCredentialClaims) and feed the result to
// a HolderVerificationProcessor. Returns the credential without a KB-JWT (as the
// holder receives it at issuance).
func IssueTestSdJwtVcdm(t *testing.T, claims []*sdjwt.ClaimElement) SdJwtVcdm {
	t.Helper()
	built, err := NewSdJwtVcdmBuilder().
		WithPayload(claims...).
		WithIssuerCertificateChain(testX5c(t)).
		Build(sdjwt.NewJwtCreator(testIssuerKey(t)))
	require.NoError(t, err)
	return built
}

// signCredential is the low-level helper for tests that need a non-default `typ`
// (or a deliberately non-VCDM payload), bypassing SdJwtVcdmBuilder's checks.
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

// ============================ W3C VCDM fixtures ============================

// vcdmClaims builds a minimal VCDM 2.0 claim tree with two selectively-
// disclosable credentialSubject leaves and a holder cnf key, parameterised by
// validity window (used by the verification tests).
func vcdmClaims(t *testing.T, validFrom, validUntil string) []*sdjwt.ClaimElement {
	t.Helper()
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)
	return []*sdjwt.ClaimElement{
		sdjwt.Array(vcdm.ContextKey, sdjwt.Item(vcdm.ContextV2)),
		sdjwt.Array(vcdm.TypeKey, sdjwt.Item(vcdm.TypeVerifiableCredential), sdjwt.Item("ExampleCredential")),
		sdjwt.Claim(vcdm.IssuerKey, TestIssuerURL),
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

// AcademicBaseCredentialClaims is an eduwallet-shaped VCDM 2.0 fixture: an
// AcademicBaseCredential carrying eduPerson-style claims (a representative
// subset), all selectively disclosable. The second `@context` entry is an
// illustrative domain context — the §6.3 lightweight path never dereferences it.
func AcademicBaseCredentialClaims(t *testing.T) []*sdjwt.ClaimElement {
	t.Helper()
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)
	return []*sdjwt.ClaimElement{
		sdjwt.Array(vcdm.ContextKey,
			sdjwt.Item(vcdm.ContextV2),
			sdjwt.Item("https://eduwallet.nl/context/academic/v1"),
		),
		sdjwt.Array(vcdm.TypeKey,
			sdjwt.Item(vcdm.TypeVerifiableCredential),
			sdjwt.Item("AcademicBaseCredential"),
		),
		sdjwt.Claim(vcdm.IssuerKey, TestIssuerURL),
		sdjwt.Claim(vcdm.ValidFromKey, "2024-01-01T00:00:00Z"),
		sdjwt.Claim(vcdm.ValidUntilKey, "2034-01-01T00:00:00Z"),
		sdjwt.Object(vcdm.CredentialSubjectKey,
			sdjwt.Claim("id", "did:example:holder"),
			sdjwt.SdClaim("eduperson_unique_id", "b2c3d4e5@university.example"),
			sdjwt.SdClaim("schac_home_organization", "university.example"),
			sdjwt.SdClaim("eduperson_affiliation", "student"),
			sdjwt.SdClaim("given_name", "Alice"),
			sdjwt.SdClaim("family_name", "Smith"),
		),
		cnf,
	}
}

// W3CExampleCredentialClaims is the canonical W3C VCDM 2.0 example credential
// (adapted from the spec's ExampleAlumniCredential), with a selectively-
// disclosable subject claim.
func W3CExampleCredentialClaims(t *testing.T) []*sdjwt.ClaimElement {
	t.Helper()
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)
	return []*sdjwt.ClaimElement{
		sdjwt.Array(vcdm.ContextKey,
			sdjwt.Item(vcdm.ContextV2),
			sdjwt.Item("https://www.w3.org/ns/credentials/examples/v2"),
		),
		sdjwt.Array(vcdm.TypeKey,
			sdjwt.Item(vcdm.TypeVerifiableCredential),
			sdjwt.Item("ExampleAlumniCredential"),
		),
		sdjwt.Claim(vcdm.IDKey, "http://university.example/credentials/1872"),
		sdjwt.Claim(vcdm.IssuerKey, TestIssuerURL),
		sdjwt.Claim(vcdm.ValidFromKey, "2010-01-01T19:23:24Z"),
		sdjwt.Object(vcdm.CredentialSubjectKey,
			sdjwt.Claim("id", "did:example:ebfeb1f712ebc6f1c276e12ec21"),
			sdjwt.SdClaim("alumniOf", "Example University"),
		),
		cnf,
	}
}

// AcademicBaseCredentialJSON and W3CExampleCredentialJSON are the same fixtures
// as fully-disclosed VCDM 2.0 documents (JSON), for structural-validation checks
// (vcdm.Document.Validate) and for reuse by the OpenID4VCI integration tests.
const AcademicBaseCredentialJSON = `{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://eduwallet.nl/context/academic/v1"],
  "type": ["VerifiableCredential", "AcademicBaseCredential"],
  "issuer": "https://openid4vc.staging.yivi.app",
  "validFrom": "2024-01-01T00:00:00Z",
  "validUntil": "2034-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:holder",
    "eduperson_unique_id": "b2c3d4e5@university.example",
    "schac_home_organization": "university.example",
    "eduperson_affiliation": "student",
    "given_name": "Alice",
    "family_name": "Smith"
  }
}`

const W3CExampleCredentialJSON = `{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
  "id": "http://university.example/credentials/1872",
  "type": ["VerifiableCredential", "ExampleAlumniCredential"],
  "issuer": "https://openid4vc.staging.yivi.app",
  "validFrom": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "alumniOf": "Example University"
  }
}`
