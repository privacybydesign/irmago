package services

import (
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

func newTestMdocCredentialResponseString(t *testing.T) (raw string, iacaCert *x509.Certificate) {
	t.Helper()

	issuer, err := mdoc.NewIssuer()
	require.NoError(t, err)
	holder, err := mdoc.NewHolder()
	require.NoError(t, err)

	issued, err := issuer.Issue(
		"eu.europa.ec.av.1",
		"eu.europa.ec.av.1",
		map[string]any{"age_over_18": true},
		holder.PublicKey(),
	)
	require.NoError(t, err)

	encoded, err := cbor.Marshal(issued)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(encoded), issuer.IACACert()
}

func TestMdocCredentialFormatParser_ParseAndVerify(t *testing.T) {
	raw, iacaCert := newTestMdocCredentialResponseString(t)
	verifier := mdoc.NewVerifier([]*x509.Certificate{iacaCert})
	parser := NewMdocCredentialFormatParser(verifier)

	parsed, err := parser.ParseAndVerify(raw, "https://test-issuer.example.com", true)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	require.Equal(t, models.CredentialFormatMsoMdoc, parsed.Format)
	require.Equal(t, "eu.europa.ec.av.1", parsed.VerifiableCredentialType)
	require.Equal(t, "https://test-issuer.example.com", parsed.IssuerURL)
	require.NotEmpty(t, parsed.ResolvedClaims)
	require.NotEmpty(t, parsed.RawCredentialBytes)
	require.NotNil(t, parsed.IssuedAt)
	require.NotNil(t, parsed.ExpiresAt)
	require.NotNil(t, parsed.NotBefore)
	require.NotNil(t, parsed.HolderBindingKeyThumbprint)
	require.Nil(t, parsed.SdJwtVc)
}

func TestMdocCredentialFormatParser_ParseAndVerify_UntrustedRootRejected(t *testing.T) {
	raw, _ := newTestMdocCredentialResponseString(t)
	otherIssuer, err := mdoc.NewIssuer()
	require.NoError(t, err)
	verifier := mdoc.NewVerifier([]*x509.Certificate{otherIssuer.IACACert()})
	parser := NewMdocCredentialFormatParser(verifier)

	_, err = parser.ParseAndVerify(raw, "https://test-issuer.example.com", false)
	require.Error(t, err)
}

func TestMdocCredentialFormatParser_ParseAndVerify_InvalidBase64(t *testing.T) {
	verifier := mdoc.NewVerifier(nil)
	parser := NewMdocCredentialFormatParser(verifier)

	_, err := parser.ParseAndVerify("not-valid-base64url!!!", "https://test-issuer.example.com", false)
	require.Error(t, err)
}

func TestMdocCredentialFormatParser_CheckBatchUniqueness(t *testing.T) {
	parser := NewMdocCredentialFormatParser(nil)

	thumbprint := "same-thumbprint"
	err := parser.CheckBatchUniqueness([]*ParsedCredential{
		{HolderBindingKeyThumbprint: &thumbprint},
		{HolderBindingKeyThumbprint: &thumbprint},
	})
	require.Error(t, err)

	other := "different-thumbprint"
	err = parser.CheckBatchUniqueness([]*ParsedCredential{
		{HolderBindingKeyThumbprint: &thumbprint},
		{HolderBindingKeyThumbprint: &other},
	})
	require.NoError(t, err)
}
