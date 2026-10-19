package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/stretchr/testify/require"
)

// newCert makes a self-signed certificate issued by issuerOrg; withScheme
// adds Yivi's relying-party scheme extension, as on a Yivi-issued certificate.
func newCert(t *testing.T, issuerOrg string, withScheme bool, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	name := pkix.Name{CommonName: "webshopnoord.nl"}
	if issuerOrg != "" {
		name.Organization = []string{issuerOrg}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      name,
		Issuer:       name,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	if withScheme {
		value, err := asn1.Marshal(`{"relying_party":{}}`)
		require.NoError(t, err)
		oid, err := parseOid(scheme.X509SchemeExtensionOID)
		require.NoError(t, err)
		template.ExtraExtensions = []pkix.Extension{{Id: oid, Value: value}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func parseOid(s string) (asn1.ObjectIdentifier, error) {
	oid, err := x509.ParseOID(s)
	if err != nil {
		return nil, err
	}
	der, err := oid.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var id asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(append([]byte{0x06, byte(len(der))}, der...), &id)
	return id, err
}

func TestTrustSourceOf_YiviIssuedCertificate(t *testing.T) {
	cert := newCert(t, "Yivi", true, time.Now().Add(time.Hour))
	source, anchor := trustSourceOf(cert)
	require.Equal(t, clientmodels.TrustSource_YiviTrustList, source)
	require.Empty(t, anchor)
}

func TestTrustSourceOf_OtherCaNamesItsOrganization(t *testing.T) {
	cert := newCert(t, "Example Trust Services", false, time.Now().Add(time.Hour))
	source, anchor := trustSourceOf(cert)
	require.Equal(t, clientmodels.TrustSource_Other, source)
	require.Equal(t, "Example Trust Services", anchor)
}

func TestTrustSourceOf_OtherCaWithoutOrganizationFallsBackToCommonName(t *testing.T) {
	cert := newCert(t, "", false, time.Now().Add(time.Hour))
	_, anchor := trustSourceOf(cert)
	require.Equal(t, "webshopnoord.nl", anchor)
}

func TestTrustCertificateOf(t *testing.T) {
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := newCert(t, "Example Trust Services", false, notAfter)
	got := trustCertificateOf(cert)
	require.Equal(t, "CN=webshopnoord.nl,O=Example Trust Services", got.Subject)
	require.Equal(t, got.Subject, got.Issuer)
	require.Equal(t, notAfter.Unix(), got.NotAfter)
}
