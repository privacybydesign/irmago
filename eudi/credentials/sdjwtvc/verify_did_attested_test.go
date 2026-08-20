package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// serveDidWebWithAttestingCert publishes a did:web document whose single
// verification method carries signingKey's public part with x5cLeaf embedded in
// its x5c, and returns the DID. The document is served over plain HTTP, which
// the insecure resolver falls back to; x5cLeaf need not certify signingKey (the
// mismatch case pins a foreign leaf on purpose).
func serveDidWebWithAttestingCert(t *testing.T, signingKey *ecdsa.PrivateKey, x5cLeaf *x509.Certificate) string {
	t.Helper()
	pub, err := jwk.Import(signingKey.Public())
	require.NoError(t, err)
	chain := &cert.Chain{}
	require.NoError(t, chain.AddString(base64.StdEncoding.EncodeToString(x5cLeaf.Raw)))
	require.NoError(t, pub.Set(jwk.X509CertChainKey, chain))

	var did string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"@context": []string{"https://www.w3.org/ns/did/v1"},
			"id":       did,
			"verificationMethod": []any{map[string]any{
				"id":           did + "#key-1",
				"type":         "JsonWebKey2020",
				"controller":   did,
				"publicKeyJwk": pub,
			}},
		}))
	}))
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	// Assign the captured variable the handler serves as the document id, not
	// only the returned value — the handler reads did at request time.
	did = "did:web:" + strings.ReplaceAll(serverURL.Host, ":", "%3A")
	return did
}

// didIssuedSdJwtVc builds a credential signed with issuerKey and identified by
// did via kid (no x5c header — that is the x5c-header path, not this one), valid
// around the given clock.
func didIssuedSdJwtVc(t *testing.T, issuerKey *ecdsa.PrivateKey, did string, now int64) SdJwtVc {
	t.Helper()
	disclosures, err := sdjwt.MultipleNewDisclosureContents(map[string]string{"email": "test@gmail.com"})
	require.NoError(t, err)
	iat, exp, nbf := now-100, now+100000, now-100
	return createTestSdJwtVc(t, newEmptyTestConfig().
		withIssuerPrivateKey(issuerKey).
		withVct("test.test.email").
		withIssuerUrl(did, true).
		withKidHeader("#key-1").
		withIssuedAt(&iat).
		withExpiryTime(&exp).
		withNotBefore(&nbf).
		withSdClaims(disclosures, iana.SHA256).
		withDisclosures(disclosures).
		withTypHeader(SdJwtVcTyp))
}

// Test_HolderVerification_DidWebIssuer_WithAttestingCertificate_SurfacesTheCertificate
// is § 5 end to end on the issuer path: a did:web issuer whose verification
// method carries an x5c over its signing key verifies, and the certificate it
// carries is surfaced for the trust ladder to classify — the DID authenticated
// the issuer, the certificate vouches for its key.
func Test_HolderVerification_DidWebIssuer_WithAttestingCertificate_SurfacesTheCertificate(t *testing.T) {
	// A leaf over the issuer's own key, chaining to an anchored CA.
	crlDistPoint := "https://yivi.app/crl.crl"
	_, rootCert, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(
		t, testdata.CreateDistinguishedName("DID ISSUER ROOT"), 1, testdata.PkiOption_None, &crlDistPoint)
	issuerKey, leaf, _ := testdata.CreateEndEntityCertificate(
		t, testdata.CreateDistinguishedName("DID Issuer"), "issuer.example",
		caCerts[0], caKeys[0], testdata.VerifierCertSchemeData, testdata.PkiOption_None)

	did := serveDidWebWithAttestingCert(t, issuerKey, leaf)
	now := time.Now().Unix()
	sdJwtVc := didIssuedSdJwtVc(t, issuerKey, did, now)

	// A trust model anchoring the leaf, so the certificate is well-formed and
	// in date. The OpenID4VCI context leaves the VCT-authorization flag off, so
	// ranking is left to the ladder — this path only has to surface the cert.
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(caCerts[0])
	ctx := SdJwtVcVerificationContext{
		X509VerificationContext: eudi.NewTestTrustModel(t.TempDir(), rootPool, intermediatePool, nil),
		Clock:                   &testClock{time: now},
		JwtVerifier:             sdjwt.NewJwxJwtVerifier(),
	}

	processor := NewHolderVerificationProcessor(ctx)
	processor.SetAllowInsecureDidWeb(true)

	verified, err := processor.ParseAndVerifySdJwtVc(SdJwtVcKb(sdJwtVc))
	require.NoError(t, err)
	require.NotNil(t, verified.IssuerCertificate,
		"a did:web issuer's attesting certificate is surfaced for the trust ladder")
	require.Equal(t, leaf.SerialNumber, verified.IssuerCertificate.SerialNumber)
}

// Test_HolderVerification_DidWebIssuer_KeyMismatchedCertificate_Fails is the §2
// refusal on the issuer path: a certificate that does not certify the signing
// key is a malformed document and refuses, before the credential is trusted.
func Test_HolderVerification_DidWebIssuer_KeyMismatchedCertificate_Fails(t *testing.T) {
	_, _, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(
		t, testdata.CreateDistinguishedName("DID ISSUER ROOT"), 1, testdata.PkiOption_None, nil)
	issuerKey, _, _ := testdata.CreateEndEntityCertificate(
		t, testdata.CreateDistinguishedName("DID Issuer"), "issuer.example",
		caCerts[0], caKeys[0], testdata.VerifierCertSchemeData, testdata.PkiOption_None)
	// A leaf over a *different* key, pasted into the document.
	_, foreignLeaf, _ := testdata.CreateEndEntityCertificate(
		t, testdata.CreateDistinguishedName("Someone Else"), "issuer.example",
		caCerts[0], caKeys[0], testdata.VerifierCertSchemeData, testdata.PkiOption_None)

	did := serveDidWebWithAttestingCert(t, issuerKey, foreignLeaf)
	now := time.Now().Unix()
	sdJwtVc := didIssuedSdJwtVc(t, issuerKey, did, now)

	ctx := SdJwtVcVerificationContext{
		X509VerificationContext: eudi.NewTestTrustModel(t.TempDir(), x509.NewCertPool(), x509.NewCertPool(), nil),
		Clock:                   &testClock{time: now},
		JwtVerifier:             sdjwt.NewJwxJwtVerifier(),
	}
	processor := NewHolderVerificationProcessor(ctx)
	processor.SetAllowInsecureDidWeb(true)

	_, err := processor.ParseAndVerifySdJwtVc(SdJwtVcKb(sdJwtVc))
	require.Error(t, err, "an x5c that does not certify the signing key refuses the credential")
	require.Contains(t, err.Error(), "invalid attesting certificate")
}
