package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// An issuer certificate no anchor stands behind is a legitimate-looking
// stranger and passes, ranked low by the trust ladder. A *revoked* one does not:
// its CA went out of its way to withdraw it, which is how a compromised issuer
// is cut off, so it is refused on every issuance path — including the OpenID4VCI
// one, which deliberately skips chain building because nothing there reads the
// answer.

func TestHolderVerification_RevokedIssuerCertificate_IsRefused(t *testing.T) {
	// Both verification contexts the wallet builds: OpenID4VCI leaves the
	// requestor-info check off (client.go), IRMA issuance turns it on.
	for _, verifyRequestorInfo := range []bool{false, true} {
		name := "without the requestor info check"
		if verifyRequestorInfo {
			name = "with the requestor info check"
		}
		t.Run(name, func(t *testing.T) {
			sdJwtVc, context := revokedIssuerFixture(t, true, verifyRequestorInfo)

			_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdJwtVc))

			require.ErrorIs(t, err, eudi_jwt.ErrCertificateRevoked)
			require.ErrorContains(t, err, "issuer certificate is refused")
		})
	}
}

func TestHolderVerification_UnrevokedIssuerCertificate_OnOpenID4VciPath_Verifies(t *testing.T) {
	// The control for the case above: the same credential, the same anchors, no
	// CRL naming its issuer. It has to verify, or the test above would pass on
	// any fixture breakage rather than on the revocation.
	sdJwtVc, context := revokedIssuerFixture(t, false, false)

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdJwtVc))

	require.NoError(t, err)
}

// revokedIssuerFixture mints a CA, an issuer certificate under it and an SD-JWT
// VC signed with that certificate, plus the verification context anchoring the
// CA. When revoked is set, the context also carries the CA's CRL naming the
// issuer certificate.
func revokedIssuerFixture(t *testing.T, revoked, verifyRequestorInfo bool) (SdJwtVc, SdJwtVcVerificationContext) {
	t.Helper()

	const hostname = "issuer.example.com"

	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Revocation Root"), testdata.PkiOption_None)
	caKey, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Revocation CA"), rootCert, rootKey, testdata.PkiOption_None, nil)
	issuerKey, issuerCert, _ := testdata.CreateEndEntityCertificate(
		t, testdata.CreateDistinguishedName(hostname), hostname, caCert, caKey, "", testdata.PkiOption_None,
	)

	x5c, err := utils.ConvertPemCertificateChainToX5cFormat([]*x509.Certificate{issuerCert, caCert})
	require.NoError(t, err)

	sdJwtVc, err := NewSdJwtVcBuilder().
		WithPayload(
			sdjwt.Claim(jwt.IssuerKey, "https://"+hostname),
			sdjwt.Claim(jwt.ExpirationKey, time.Now().Add(time.Hour).Unix()),
			sdjwt.Claim(sdjwt.SdAlgKey, iana.SHA256),
			sdjwt.Claim(VerifiableCredentialTypeKey, "test.test.email"),
			sdjwt.SdClaim("email", "test@gmail.com"),
		).
		WithIssuerCertificateChain(x5c).
		Build(sdjwt.NewJwtCreator(issuerKey))
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(caCert)

	var revocationLists []*x509.RevocationList
	if revoked {
		revocationLists = append(revocationLists, revocationListRevoking(t, issuerCert, caCert, caKey))
	}

	return sdJwtVc, SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			},
			RevocationLists: revocationLists,
		},
		Clock:       eudi_jwt.NewSystemClock(),
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
		VerifyVerifiableCredentialTypeInRequestorInfo: verifyRequestorInfo,
	}
}

// revocationListRevoking builds the CA's CRL naming cert as revoked.
func revocationListRevoking(t *testing.T, cert, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.RevocationList {
	t.Helper()

	template := testdata.GetDefaultCrlTemplate(caCert)
	template.RevokedCertificateEntries = []x509.RevocationListEntry{{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now().Add(-time.Hour),
	}}
	der, err := x509.CreateRevocationList(rand.Reader, template, caCert, caKey)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	return crl
}
