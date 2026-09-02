package walletconfig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

func TestSign_ProducesTheHeadersVerifyExpects(t *testing.T) {
	signer := NewTestSigner(t)
	raw := signer.Sign(t, NewTestConfig("test", 1, time.Now()))

	message, err := jws.Parse(raw)
	require.NoError(t, err)
	require.Len(t, message.Signatures(), 1)
	protected := message.Signatures()[0].ProtectedHeaders()

	typ, _ := protected.Type()
	require.Equal(t, Typ, typ)
	alg, _ := protected.Algorithm()
	require.Equal(t, jwa.ES256(), alg)
	x5c, ok := protected.X509CertChain()
	require.True(t, ok)
	require.Equal(t, 2, x5c.Len(), "leaf and intermediate; the root is what the wallet pins")
}

func TestSign_RefusesAnInvalidConfig(t *testing.T) {
	signer := NewTestSigner(t)
	config := NewTestConfig("test", 0, time.Now())
	_, err := Sign(config, signer.Key, signer.Chain())
	require.ErrorContains(t, err, "refusing to sign an invalid config")
	require.ErrorContains(t, err, "version must be at least 1")

	_, err = Sign(nil, signer.Key, signer.Chain())
	require.ErrorContains(t, err, "no config")
}

func TestSign_RefusesAKeyThatDoesNotMatchTheLeaf(t *testing.T) {
	signer := NewTestSigner(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = Sign(NewTestConfig("test", 1, time.Now()), otherKey, signer.Chain())
	require.ErrorContains(t, err, "does not match the leaf certificate")
}

func TestSign_RefusesANonP256Key(t *testing.T) {
	signer := NewTestSigner(t)
	key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	_, err = Sign(NewTestConfig("test", 1, time.Now()), key384, signer.Chain())
	require.ErrorContains(t, err, "P-256")
}

func TestSign_RefusesAMissingKeyOrChain(t *testing.T) {
	signer := NewTestSigner(t)
	_, err := Sign(NewTestConfig("test", 1, time.Now()), nil, signer.Chain())
	require.ErrorContains(t, err, "no signing key")
	_, err = Sign(NewTestConfig("test", 1, time.Now()), signer.Key, nil)
	require.ErrorContains(t, err, "no signing certificate")
}

// opaqueSigner hides its private key, as a key in an HSM or a cloud KMS does.
// Moving the publisher's key to hardware must be a constructor swap.
type opaqueSigner struct {
	key *ecdsa.PrivateKey
}

func (s opaqueSigner) Public() crypto.PublicKey { return s.key.Public() }
func (s opaqueSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(random, digest, opts)
}

func TestSign_AcceptsAnOpaqueSigner(t *testing.T) {
	signer := NewTestSigner(t)
	raw, err := Sign(NewTestConfig("test", 1, time.Now()), opaqueSigner{signer.Key}, signer.Chain())
	require.NoError(t, err)

	verified, err := Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.NoError(t, err)
	require.Equal(t, uint64(1), verified.Config.Version)
}

func TestSign_ThenVerifyRoundTripsEveryField(t *testing.T) {
	signer := NewTestSigner(t)
	config := fullyFeaturedConfig(t)

	raw, err := Sign(config, signer.Key, signer.Chain())
	require.NoError(t, err)
	verified, err := Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.NoError(t, err)
	require.JSONEq(t, string(mustJSON(t, config)), string(mustJSON(t, verified.Config)))

	var _ *x509.Certificate = verified.Config.TrustedEntities[0].Handles[0].RootCertificate.Certificate
}
