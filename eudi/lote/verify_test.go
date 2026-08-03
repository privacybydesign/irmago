package lote

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/stretchr/testify/require"
)

func testList() List {
	return NewTestList(TestListOpts{
		Id:        "yivi-test",
		Providers: []TrustServiceProvider{GrantedVerifier("Listed Verifier", DidIdentity("did:web:verifier.example.com"))},
	})
}

func TestVerifyList_SignedListVerifies(t *testing.T) {
	signer := NewTestListSigner(t)

	list, err := verifyList(signer.Sign(t, testList()), signer.Anchors())

	require.NoError(t, err)
	require.Equal(t, "yivi-test", list.SchemeInformation.ListIdentifier)
	require.Len(t, list.Providers, 1)
	require.Equal(t, StatusGranted, list.Providers[0].Services[0].Status)
}

func TestVerifyList_TamperedPayloadIsRejected(t *testing.T) {
	signer := NewTestListSigner(t)
	signed := signer.Sign(t, testList())

	// Flip a byte of the payload segment, leaving the signature in place.
	tampered := append([]byte(nil), signed...)
	payloadStart := 0
	for i, b := range tampered {
		if b == '.' {
			payloadStart = i + 1
			break
		}
	}
	tampered[payloadStart] ^= 0x01

	_, err := verifyList(tampered, signer.Anchors())
	require.Error(t, err)
}

func TestVerifyList_SignerOutsideTheAnchorsIsRejected(t *testing.T) {
	signer := NewTestListSigner(t)
	stranger := NewTestListSigner(t)

	// A perfectly well-formed list, signed by a chain the anchors do not cover.
	_, err := verifyList(stranger.Sign(t, testList()), signer.Anchors())
	require.ErrorContains(t, err, "not trusted")
}

func TestVerifyList_WrongTypIsRejected(t *testing.T) {
	signer := NewTestListSigner(t)

	_, err := verifyList(signer.SignWithTyp(t, testList(), "statuslist+jwt"), signer.Anchors())
	require.ErrorContains(t, err, "'typ'")
}

func TestVerifyList_UnsignedListIsRejected(t *testing.T) {
	signer := NewTestListSigner(t)
	payload, err := json.Marshal(testList())
	require.NoError(t, err)

	_, err = verifyList(payload, signer.Anchors())
	require.Error(t, err, "a bare JSON list is not a signed list")
}

func TestVerifyList_MissingX5cIsRejected(t *testing.T) {
	// A list signed with a key the wallet is asked to resolve rather than to
	// pin: no certificate, no chain, no anchor.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	payload, err := json.Marshal(testList())
	require.NoError(t, err)

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, Typ))
	require.NoError(t, headers.Set(jws.KeyIDKey, "did:web:signer.example.com#key-1"))
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	_, err = verifyList(signed, NewTestListSigner(t).Anchors())
	require.ErrorContains(t, err, "'x5c'")
}

func TestVerifyList_WithoutAnchorsIsRejected(t *testing.T) {
	signer := NewTestListSigner(t)

	_, err := verifyList(signer.Sign(t, testList()), nil)
	require.ErrorContains(t, err, "no trust anchors")
}

func TestVerifyList_ListWithoutIdentifierOrNextUpdateIsRejected(t *testing.T) {
	signer := NewTestListSigner(t)

	t.Run("no identifier", func(t *testing.T) {
		list := testList()
		list.SchemeInformation.ListIdentifier = ""
		_, err := verifyList(signer.Sign(t, list), signer.Anchors())
		require.ErrorContains(t, err, "listIdentifier")
	})

	t.Run("no next update", func(t *testing.T) {
		list := testList()
		list.SchemeInformation.NextUpdate = time.Time{}
		_, err := verifyList(signer.Sign(t, list), signer.Anchors())
		require.ErrorContains(t, err, "nextUpdate")
	})
}

func TestVerifyList_MacAlgorithmIsRejected(t *testing.T) {
	// The header names the algorithm and the certificate carries the key, so a
	// list must not be able to ask to be verified with a symmetric one.
	signer := NewTestListSigner(t)
	payload, err := json.Marshal(testList())
	require.NoError(t, err)

	chain := &cert.Chain{}
	require.NoError(t, chain.Add([]byte(base64.StdEncoding.EncodeToString(signer.SignerCert.Raw))))
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, Typ))
	require.NoError(t, headers.Set(jws.X509CertChainKey, chain))

	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), []byte("shared secret"), jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	_, err = verifyList(signed, signer.Anchors())
	require.ErrorContains(t, err, "'alg'")
}

func TestTestListSigner_AnchorsAcceptTheSignerCertificate(t *testing.T) {
	// Guards the fixture itself: the tests above only mean something if the
	// signer's chain is a real chain the anchors accept.
	signer := NewTestListSigner(t)

	require.NoError(t, eudi_jwt.VerifyCertificate(signer.Anchors(), signer.SignerCert, nil))
	require.False(t, signer.SignerCert.Equal(signer.RootCert), "the signer must not be its own anchor")
	require.Equal(t, signer.CaCert.Subject.String(), signer.SignerCert.Issuer.String())
	require.NotEmpty(t, signer.SignerCert.Raw)
	require.IsType(t, &ecdsa.PublicKey{}, signer.SignerCert.PublicKey)
}
