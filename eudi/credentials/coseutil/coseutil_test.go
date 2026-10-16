package coseutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func Test_X5Chain_ProtectedOnly(t *testing.T) {
	der := testCertDER(t, "protected")
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelX5Chain] = [][]byte{der}

	certs, err := X5Chain(roundTrip(t, msg))
	require.NoError(t, err)
	require.Equal(t, "protected", certs[0].Subject.CommonName)
}

func Test_X5Chain_UnprotectedOnly(t *testing.T) {
	der := testCertDER(t, "unprotected")
	msg := cose.NewSign1Message()
	msg.Headers.Unprotected[cose.HeaderLabelX5Chain] = der

	certs, err := X5Chain(roundTrip(t, msg))
	require.NoError(t, err)
	require.Equal(t, "unprotected", certs[0].Subject.CommonName)
}

func Test_X5Chain_BothHeaders_ProtectedWins(t *testing.T) {
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelX5Chain] = [][]byte{testCertDER(t, "protected")}
	msg.Headers.Unprotected[cose.HeaderLabelX5Chain] = [][]byte{testCertDER(t, "unprotected")}

	certs, err := X5Chain(roundTrip(t, msg))
	require.NoError(t, err)
	require.Equal(t, "protected", certs[0].Subject.CommonName)
}

func Test_X5Chain_Missing(t *testing.T) {
	_, err := X5Chain(roundTrip(t, cose.NewSign1Message()))
	require.Error(t, err)
}

func Test_UnprotectedX5Chain_IgnoresProtectedHeader(t *testing.T) {
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelX5Chain] = [][]byte{testCertDER(t, "protected")}

	_, err := UnprotectedX5Chain(roundTrip(t, msg))
	require.Error(t, err)
}

// roundTrip encodes and decodes msg, so its headers hold the decoded CBOR
// types a received message has rather than the Go types set in the test.
func roundTrip(t *testing.T, msg *cose.Sign1Message) *cose.Sign1Message {
	t.Helper()
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Signature = []byte{0}
	raw, err := msg.MarshalCBOR()
	require.NoError(t, err)
	decoded, err := DecodeSign1(raw)
	require.NoError(t, err)
	return decoded
}

func testCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}
