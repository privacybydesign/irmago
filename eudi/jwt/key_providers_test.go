package eudi_jwt

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/stretchr/testify/require"
)

// testKeySink captures the algorithm and key passed by a key provider.
type testKeySink struct {
	alg jwa.SignatureAlgorithm
	key any
}

func (s *testKeySink) Key(alg jwa.SignatureAlgorithm, key any) {
	s.alg = alg
	s.key = key
}

// testRedirectTransport redirects all requests to the given HTTP address.
type testRedirectTransport struct {
	targetAddr string
}

func (t *testRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = t.targetAddr
	return http.DefaultTransport.RoundTrip(clone)
}

// newTestECDSACert creates a self-signed ECDSA P256 certificate.
func newTestECDSACert(t *testing.T) (derBytes []byte, privKey *ecdsa.PrivateKey, parsed *x509.Certificate) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, err = x509.CreateCertificate(rand.Reader, template, template, privKey.Public(), privKey)
	require.NoError(t, err)
	parsed, err = x509.ParseCertificate(derBytes)
	require.NoError(t, err)
	return
}

// newTestCertChain builds a cert.Chain containing a single base64-encoded DER certificate.
func newTestCertChain(t *testing.T, derBytes []byte) *cert.Chain {
	t.Helper()
	chain := &cert.Chain{}
	err := chain.Add([]byte(base64.StdEncoding.EncodeToString(derBytes)))
	require.NoError(t, err)
	return chain
}

// newTestJWSMessage creates a compact JWS message containing a JWT with the given issuer.
func newTestJWSMessage(t *testing.T, issuer string) *jws.Message {
	t.Helper()
	builder := jwt.NewBuilder()
	if issuer != "" {
		builder = builder.Issuer(issuer)
	}
	tok, err := builder.Build()
	require.NoError(t, err)
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tokenBytes, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), signingKey))
	require.NoError(t, err)
	msg, err := jws.Parse(tokenBytes)
	require.NoError(t, err)
	return msg
}

// newTestDIDDocument serialises a DID document containing a single verification method.
func newTestDIDDocument(t *testing.T, didID, keyID string, pubKey jwk.Key) []byte {
	t.Helper()
	doc := did.Document{
		ID: didID,
		VerificationMethod: []did.VerificationMethod{
			{
				ID:           keyID,
				Type:         "JsonWebKey2020",
				Controller:   didID,
				PublicKeyJwk: &pubKey,
			},
		},
	}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	return data
}

// ─── X509KeyProvider ─────────────────────────────────────────────────────────

func Test_X509KeyProvider_GetCert_InitiallyNil(t *testing.T) {
	p := NewX509KeyProvider(&cert.Chain{})
	require.Nil(t, p.GetCert())
}

func Test_X509KeyProvider_FetchKeys_NilChain_ReturnsError(t *testing.T) {
	p := NewX509KeyProvider(nil)
	err := p.FetchKeys(context.Background(), &testKeySink{}, nil, nil)
	require.ErrorContains(t, err, "expected x5c header, but is empty")
}

func Test_X509KeyProvider_FetchKeys_EmptyChain_ReturnsError(t *testing.T) {
	p := NewX509KeyProvider(&cert.Chain{})
	err := p.FetchKeys(context.Background(), &testKeySink{}, nil, nil)
	require.ErrorContains(t, err, "expected x5c header, but is empty")
}

func Test_X509KeyProvider_FetchKeys_InvalidBase64InChain_ReturnsError(t *testing.T) {
	chain := &cert.Chain{}
	_ = chain.Add([]byte("not-valid-base64===!!!"))
	p := NewX509KeyProvider(chain)
	err := p.FetchKeys(context.Background(), &testKeySink{}, nil, nil)
	require.ErrorContains(t, err, "failed to decode end-entity base64 encoded der")
}

func Test_X509KeyProvider_FetchKeys_InvalidDERInChain_ReturnsError(t *testing.T) {
	chain := &cert.Chain{}
	_ = chain.Add([]byte(base64.StdEncoding.EncodeToString([]byte("not valid DER"))))
	p := NewX509KeyProvider(chain)
	err := p.FetchKeys(context.Background(), &testKeySink{}, nil, nil)
	require.ErrorContains(t, err, "failed to parse end-entity certificate")
}

func Test_X509KeyProvider_FetchKeys_NilSignature_ReturnsError(t *testing.T) {
	derBytes, _, _ := newTestECDSACert(t)
	p := NewX509KeyProvider(newTestCertChain(t, derBytes))
	err := p.FetchKeys(context.Background(), &testKeySink{}, nil, nil)
	require.ErrorContains(t, err, "missing JWS signature")
}

func Test_X509KeyProvider_FetchKeys_MissingAlgHeader_ReturnsError(t *testing.T) {
	derBytes, _, _ := newTestECDSACert(t)
	p := NewX509KeyProvider(newTestCertChain(t, derBytes))
	sig := jws.NewSignature()
	sig.SetProtectedHeaders(jws.NewHeaders()) // headers present but no alg field
	err := p.FetchKeys(context.Background(), &testKeySink{}, sig, nil)
	require.ErrorContains(t, err, "missing alg header in JWS signature")
}

func Test_X509KeyProvider_FetchKeys_UsesJWSAlgHeaderWhenPresent(t *testing.T) {
	derBytes, privKey, _ := newTestECDSACert(t)
	chain := newTestCertChain(t, derBytes)
	p := NewX509KeyProvider(chain)
	sink := &testKeySink{}

	// Sign a JWT with the cert's private key using ES256; the JWS alg header will be ES256.
	tok, err := jwt.NewBuilder().Issuer("test").Build()
	require.NoError(t, err)
	tokenBytes, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privKey))
	require.NoError(t, err)
	msg, err := jws.Parse(tokenBytes)
	require.NoError(t, err)
	sig := msg.Signatures()[0]

	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Equal(t, jwa.ES256(), sink.alg)
	require.NotNil(t, sink.key)
}

func Test_X509KeyProvider_FetchKeys_ECDSACert_GetCertMatchesParsedCert(t *testing.T) {
	derBytes, privKey, parsed := newTestECDSACert(t)
	p := NewX509KeyProvider(newTestCertChain(t, derBytes))

	tok, err := jwt.NewBuilder().Issuer("test").Build()
	require.NoError(t, err)
	tokenBytes, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privKey))
	require.NoError(t, err)
	msg, err := jws.Parse(tokenBytes)
	require.NoError(t, err)

	err = p.FetchKeys(context.Background(), &testKeySink{}, msg.Signatures()[0], msg)
	require.NoError(t, err)

	require.Equal(t, parsed.SerialNumber, p.GetCert().SerialNumber)
	require.Equal(t, parsed.Subject, p.GetCert().Subject)
}

// ─── algorithmFromJWK ────────────────────────────────────────────────────────

func Test_algorithmFromJWK_ECKey_P256_ReturnsES256(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k, err := jwk.Import(privKey.Public())
	require.NoError(t, err)

	alg, err := algorithmFromJWK(k)
	require.NoError(t, err)
	require.Equal(t, jwa.ES256(), alg)
}

func Test_algorithmFromJWK_ECKey_P384_ReturnsES384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	k, err := jwk.Import(privKey.Public())
	require.NoError(t, err)

	alg, err := algorithmFromJWK(k)
	require.NoError(t, err)
	require.Equal(t, jwa.ES384(), alg)
}

func Test_algorithmFromJWK_ECKey_P521_ReturnsES512(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	k, err := jwk.Import(privKey.Public())
	require.NoError(t, err)

	alg, err := algorithmFromJWK(k)
	require.NoError(t, err)
	require.Equal(t, jwa.ES512(), alg)
}

func Test_algorithmFromJWK_ECKey_WithExplicitAlg_UsesExplicitAlg(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k, err := jwk.Import(privKey.Public())
	require.NoError(t, err)
	require.NoError(t, k.Set("alg", jwa.ES384()))

	alg, err := algorithmFromJWK(k)
	require.NoError(t, err)
	require.Equal(t, jwa.ES384(), alg)
}

func Test_algorithmFromJWK_OKPKey_Ed25519_ReturnsEdDSA(t *testing.T) {
	_, edPub, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k, err := jwk.Import(edPub)
	require.NoError(t, err)

	alg, err := algorithmFromJWK(k)
	require.NoError(t, err)
	require.Equal(t, jwa.EdDSA(), alg)
}

func Test_algorithmFromJWK_OKPKey_X25519_UnsupportedCurve_ReturnsError(t *testing.T) {
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	k, err := jwk.Import(x25519Key.Public())
	require.NoError(t, err)

	_, err = algorithmFromJWK(k)
	require.ErrorContains(t, err, "unsupported OKP curve")
}

func Test_algorithmFromJWK_RSAKey_ReturnsRS256(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	k, err := jwk.Import(rsaKey.Public())
	require.NoError(t, err)

	alg, err := algorithmFromJWK(k)
	require.NoError(t, err)
	require.Equal(t, jwa.RS256(), alg)
}

func Test_algorithmFromJWK_SymmetricKey_UnsupportedType_ReturnsError(t *testing.T) {
	k, err := jwk.ParseKey([]byte(`{"kty":"oct","k":"c2VjcmV0LWtleQ"}`))
	require.NoError(t, err)

	_, err = algorithmFromJWK(k)
	require.ErrorContains(t, err, "unsupported key type")
}

// ─── KidKeyProvider ──────────────────────────────────────────────────────────

func Test_KidKeyProvider_FetchKeys_JWTWithoutIssuerClaim_ReturnsError(t *testing.T) {
	msg := newTestJWSMessage(t, "")
	p := NewKidKeyProvider("#key-1", false)
	err := p.FetchKeys(context.Background(), &testKeySink{}, nil, msg)
	require.ErrorContains(t, err, "failed to obtain 'iss' claim")
}

func Test_KidKeyProvider_FetchKeys_DIDResolutionFails_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, "did:web:example.com")
	p := &KidKeyProvider{
		kidHeader:     "#key-1",
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	err := p.FetchKeys(context.Background(), &testKeySink{}, nil, msg)
	require.ErrorContains(t, err, "failed to resolve did document")
}

func Test_KidKeyProvider_FetchKeys_NoMatchingVerificationMethod_ReturnsError(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import(privKey.Public())
	require.NoError(t, err)

	// DID document has a key with a different ID
	docBytes := newTestDIDDocument(t, issuerDID, issuerDID+"#other-key", pubJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	p := &KidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	err = p.FetchKeys(context.Background(), &testKeySink{}, nil, msg)
	require.ErrorContains(t, err, "failed to find matching verification method")
}

func Test_KidKeyProvider_FetchKeys_PrivateKeyInVerificationMethod_ReturnsError(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"
	fullKID := issuerDID + kidHeader

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privJWK, err := jwk.Import(privKey) // private key – not allowed in DID document
	require.NoError(t, err)

	docBytes := newTestDIDDocument(t, issuerDID, fullKID, privJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	p := &KidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	err = p.FetchKeys(context.Background(), &testKeySink{}, nil, msg)
	require.ErrorContains(t, err, "cannot use a JWK containing private key material")
}

func Test_KidKeyProvider_FetchKeys_ValidPublicKey_FeedsKeyAndAlgorithmToSink(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"
	fullKID := issuerDID + kidHeader

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import(privKey.Public())
	require.NoError(t, err)

	docBytes := newTestDIDDocument(t, issuerDID, fullKID, pubJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	p := &KidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, nil, msg)

	require.NoError(t, err)
	require.Equal(t, jwa.ES256(), sink.alg)
	require.NotNil(t, sink.key)
}
