package eudi_jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"github.com/privacybydesign/irmago/eudi/didjwk"
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

// newTestJWSMessageSigned creates a JWS message signed with the given private key and algorithm.
func newTestJWSMessageSigned(t *testing.T, issuer string, privKey any, alg jwa.SignatureAlgorithm) *jws.Message {
	t.Helper()
	builder := jwt.NewBuilder()
	if issuer != "" {
		builder = builder.Issuer(issuer)
	}
	tok, err := builder.Build()
	require.NoError(t, err)
	tokenBytes, err := jwt.Sign(tok, jwt.WithKey(alg, privKey))
	require.NoError(t, err)
	msg, err := jws.Parse(tokenBytes)
	require.NoError(t, err)
	return msg
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

func Test_X509KeyProvider_FetchKeys_AlgFromJWSHeaderNotKeyType(t *testing.T) {
	// Regression: alg must come from the JWS protected header, not be inferred from the cert's key type.
	// A P384 key signed under ES384 must yield ES384 in the sink (not a default like ES256).
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, privKey.Public(), privKey)
	require.NoError(t, err)

	p := NewX509KeyProvider(newTestCertChain(t, derBytes))
	sink := &testKeySink{}

	msg := newTestJWSMessageSigned(t, "test", privKey, jwa.ES384())
	sig := msg.Signatures()[0]

	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Equal(t, jwa.ES384(), sink.alg)
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
	sig := msg.Signatures()[0]
	p := &KidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Equal(t, jwa.ES256(), sink.alg)
	require.NotNil(t, sink.key)
}

// Test that when kidHeader does NOT start with '#', it is used as-is (no concatenation with iss).
func Test_KidKeyProvider_FetchKeys_FullKidHeader_UsedAsIs(t *testing.T) {
	const issuerDID = "did:web:example.com"
	// Full absolute DID URL — should be used as-is, not prepended with issuerDID.
	const kidHeader = "did:web:example.com#key-1"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import(privKey.Public())
	require.NoError(t, err)

	// DID document uses the full KID, not issuerDID + "#key-1"
	docBytes := newTestDIDDocument(t, issuerDID, kidHeader, pubJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	sig := msg.Signatures()[0]
	p := &KidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Equal(t, jwa.ES256(), sink.alg)
	require.NotNil(t, sink.key)
}

// Test that when kidHeader does NOT start with '#' but the DID document only has the fragment-prefixed
// key, resolution fails — confirming no concatenation happened.
func Test_KidKeyProvider_FetchKeys_FullKidHeader_DoesNotConcatenateWithIss(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "did:web:example.com#key-1"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import(privKey.Public())
	require.NoError(t, err)

	// DID document only has the concatenated form — should NOT match when kidHeader is already absolute.
	docBytes := newTestDIDDocument(t, issuerDID, issuerDID+issuerDID+"#key-1", pubJWK)

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

func Test_KidKeyProvider_FetchKeys_NilSignature_ReturnsError(t *testing.T) {
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

	err = p.FetchKeys(context.Background(), &testKeySink{}, nil, msg)
	require.ErrorContains(t, err, "missing JWS signature")
}

func Test_KidKeyProvider_FetchKeys_MissingAlgHeader_ReturnsError(t *testing.T) {
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
	sig := jws.NewSignature()
	sig.SetProtectedHeaders(jws.NewHeaders()) // headers present but no alg field
	p := &KidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	err = p.FetchKeys(context.Background(), &testKeySink{}, sig, msg)
	require.ErrorContains(t, err, "missing alg header in JWS signature")
}

func Test_KidKeyProvider_FetchKeys_AlgFromJWSHeaderNotJWK(t *testing.T) {
	// Regression: alg must come from the JWS protected header, not from the "alg" field in the DID
	// document's JWK. Before the fix, algorithmFromJWK read the JWK's alg field (ES384 here) and
	// passed it to the sink instead of the header's alg (ES256).
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"
	fullKID := issuerDID + kidHeader

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import(privKey.Public())
	require.NoError(t, err)
	// Deliberately set a different alg on the JWK than what the JWT is actually signed with.
	require.NoError(t, pubJWK.Set("alg", jwa.ES384()))

	docBytes := newTestDIDDocument(t, issuerDID, fullKID, pubJWK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	// JWT is signed with ES256; the JWS header carries alg=ES256.
	msg := newTestJWSMessageSigned(t, issuerDID, privKey, jwa.ES256())
	sig := msg.Signatures()[0]
	p := &KidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	// Sink must receive the alg from the JWS header (ES256), not from the JWK field (ES384).
	require.Equal(t, jwa.ES256(), sink.alg)
	require.NotNil(t, sink.key)
}

// ─── KidKeyProvider: did:jwk ─────────────────────────────────────────────────

// newTestDidJwk derives a did:jwk DID from the public part of the given key.
func newTestDidJwk(t *testing.T, privKey *ecdsa.PrivateKey) string {
	t.Helper()
	pubJWK, err := jwk.Import(privKey.Public())
	require.NoError(t, err)
	doc, err := (&didjwk.DocumentBuilder{}).FromJwk(pubJWK)
	require.NoError(t, err)
	return doc.ID
}

func Test_KidKeyProvider_FetchKeys_DidJwk_ValidPublicKey_FeedsKeyAndAlgorithmToSink(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didJwk := newTestDidJwk(t, privKey)
	msg := newTestJWSMessageSigned(t, didJwk, privKey, jwa.ES256())
	sig := msg.Signatures()[0]

	p := NewKidKeyProvider("#0", false)
	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Equal(t, jwa.ES256(), sink.alg)
	require.NotNil(t, sink.key)
}

func Test_KidKeyProvider_FetchKeys_DidJwk_FullKidHeader_UsedAsIs(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didJwk := newTestDidJwk(t, privKey)
	msg := newTestJWSMessageSigned(t, didJwk, privKey, jwa.ES256())
	sig := msg.Signatures()[0]

	p := NewKidKeyProvider(didJwk+"#0", false)
	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Equal(t, jwa.ES256(), sink.alg)
	require.NotNil(t, sink.key)
}

func Test_KidKeyProvider_FetchKeys_DidJwk_NoMatchingVerificationMethod_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didJwk := newTestDidJwk(t, privKey)
	msg := newTestJWSMessageSigned(t, didJwk, privKey, jwa.ES256())

	// did:jwk DID documents only contain a verification method with id "#0".
	p := NewKidKeyProvider("#1", false)
	err = p.FetchKeys(context.Background(), &testKeySink{}, msg.Signatures()[0], msg)
	require.ErrorContains(t, err, "failed to find matching verification method")
}

func Test_KidKeyProvider_FetchKeys_DidJwk_MalformedEncoding_ReturnsError(t *testing.T) {
	msg := newTestJWSMessage(t, "did:jwk:not-valid-base64!!!")
	p := NewKidKeyProvider("#0", false)

	err := p.FetchKeys(context.Background(), &testKeySink{}, msg.Signatures()[0], msg)
	require.ErrorContains(t, err, "failed to resolve did document for kid")
}

func Test_KidKeyProvider_FetchKeys_UnsupportedDidMethod_ReturnsError(t *testing.T) {
	msg := newTestJWSMessage(t, "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
	p := NewKidKeyProvider("#0", false)

	err := p.FetchKeys(context.Background(), &testKeySink{}, msg.Signatures()[0], msg)
	require.ErrorContains(t, err, "unsupported DID method")
}
