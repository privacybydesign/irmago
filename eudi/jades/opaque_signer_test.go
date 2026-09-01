package jades_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/privacybydesign/irmago/eudi/jades"
	"github.com/stretchr/testify/require"
)

// opaqueSigner is a key that never hands out its private half: what an HSM, a
// PKCS#11 token or a cloud KMS looks like to the signer.
type opaqueSigner struct{ key *ecdsa.PrivateKey }

func (o opaqueSigner) Public() crypto.PublicKey { return o.key.Public() }
func (o opaqueSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.key.Sign(random, digest, opts)
}

// Moving the list signer to hardware is meant to be a constructor swap. That is
// only true if an opaque crypto.Signer signs the same as an in-memory key.
func TestSignBaselineB_SignsWithAnOpaqueSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := opaqueSigner{key: key}

	alg, err := jades.SignatureAlgorithmFor(signer)
	require.NoError(t, err)
	require.Equal(t, jwa.ES256(), alg, "the algorithm follows the public key, which an opaque signer does hand out")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "opaque signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	signed, err := jades.SignBaselineB([]byte(`{"LoTE":{}}`), jades.SignOptions{
		Typ:      "tl+jwt",
		Chain:    []*x509.Certificate{cert},
		Key:      signer,
		SignedAt: time.Now(),
	})
	require.NoError(t, err)

	verified, err := jades.VerifyBaselineB(signed, jades.VerifyOptions{AllowedTyps: []string{"tl+jwt"}})
	require.NoError(t, err)
	require.Equal(t, cert.Raw, verified.Signer.Raw)
}
