package eudi_jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/stretchr/testify/require"
)

// attestedKey returns a public JWK for key, carrying certForX5c in its x5c when
// non-nil. The x5c leaf is certForX5c; the key material is key's public part —
// the two match only when the caller passes the certificate that certifies key.
func attestedKey(t *testing.T, key *ecdsa.PublicKey, certForX5c *x509.Certificate) jwk.Key {
	t.Helper()
	pub, err := jwk.Import(key)
	require.NoError(t, err)
	if certForX5c != nil {
		chain := &cert.Chain{}
		require.NoError(t, chain.AddString(base64.StdEncoding.EncodeToString(certForX5c.Raw)))
		require.NoError(t, pub.Set(jwk.X509CertChainKey, chain))
	}
	return pub
}

// selfSignedFor mints a self-signed certificate over key. The chain does not
// matter for AttestingCertificate, which never builds one — only the leaf's
// public key does.
func selfSignedFor(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Attesting BV"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	crt, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return crt
}

func TestAttestingCertificate_AbsentX5c_IsNoAttestation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leaf, err := AttestingCertificate(attestedKey(t, &key.PublicKey, nil))
	require.NoError(t, err, "an absent x5c is not an error")
	require.Nil(t, leaf, "an absent x5c yields no certificate")
}

func TestAttestingCertificate_MatchingX5c_ReturnsLeaf(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	crt := selfSignedFor(t, key)

	leaf, err := AttestingCertificate(attestedKey(t, &key.PublicKey, crt))
	require.NoError(t, err)
	require.NotNil(t, leaf)
	require.Equal(t, crt.SerialNumber, leaf.SerialNumber)
	require.Equal(t, "Attesting BV", leaf.Subject.CommonName)
}

func TestAttestingCertificate_KeyMismatch_IsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// A certificate over a *different* key, pasted onto our key's JWK — the
	// forgery RFC 7517 §4.7 forbids.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	foreignCert := selfSignedFor(t, otherKey)

	leaf, err := AttestingCertificate(attestedKey(t, &key.PublicKey, foreignCert))
	require.ErrorIs(t, err, ErrAttestationKeyMismatch)
	require.Nil(t, leaf)
}

// TestAttestingCertificate_DidJwkAndDidWebShareThePath proves the method-agnostic
// claim: a did:jwk identifier carrying an x5c resolves to the same jwk.Key shape
// the did:web verification method produces, so one helper serves both.
func TestAttestingCertificate_DidJwkAndDidWebShareThePath(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	crt := selfSignedFor(t, key)

	// A did:jwk whose embedded JWK carries the x5c, resolved through the real
	// did:jwk resolver.
	attested := attestedKey(t, &key.PublicKey, crt)
	jwkJSON, err := attested.(interface{ MarshalJSON() ([]byte, error) }).MarshalJSON()
	require.NoError(t, err)
	didJwk := didjwk.Prefix + base64.RawURLEncoding.EncodeToString(jwkJSON)

	resolved, err := didjwk.Resolve(didJwk)
	require.NoError(t, err)

	leaf, err := AttestingCertificate(resolved)
	require.NoError(t, err)
	require.NotNil(t, leaf, "an x5c on a did:jwk survives resolution and is read by the same helper")
	require.Equal(t, crt.SerialNumber, leaf.SerialNumber)
}
