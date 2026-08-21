package eudi_jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/stretchr/testify/require"
)

// testKeySink captures the algorithm and key passed by a key provider.
type testKey struct {
	alg jwa.SignatureAlgorithm
	key any
}

type testKeySink struct {
	keys []testKey
}

func (s *testKeySink) Key(alg jwa.SignatureAlgorithm, key any) {
	s.keys = append(s.keys, testKey{alg: alg, key: key})
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
				PublicKeyJwk: pubKey,
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
	// cert.Chain.Add now validates; invalid base64 is rejected during Add.
	require.Error(t, chain.Add([]byte("not-valid-base64===!!!")))
	p := NewX509KeyProvider(chain)
	err := p.FetchKeys(context.Background(), &testKeySink{}, nil, nil)
	require.ErrorContains(t, err, "expected x5c header, but is empty")
}

func Test_X509KeyProvider_FetchKeys_InvalidDERInChain_ReturnsError(t *testing.T) {
	chain := &cert.Chain{}
	// cert.Chain.Add now validates; invalid DER is rejected during Add.
	require.Error(t, chain.Add([]byte(base64.StdEncoding.EncodeToString([]byte("not valid DER")))))
	p := NewX509KeyProvider(chain)
	err := p.FetchKeys(context.Background(), &testKeySink{}, nil, nil)
	require.ErrorContains(t, err, "expected x5c header, but is empty")
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
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)
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
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES384(), sink.keys[0].alg)
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

// ─── DidKeyProvider ──────────────────────────────────────────────────────────
func Test_DidKeyProvider_FetchKeys_NoJwtSignature_ReturnsNoKeysNoError(t *testing.T) {
	sink := &testKeySink{}
	msg := newTestJWSMessage(t, "")
	p := NewDidKeyProvider("#key-1", false)
	err := p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
}

func Test_DidKeyProvider_FetchKeys_JWTWithoutIssuerClaim_ReturnsNoKeysNoError(t *testing.T) {
	msg := newTestJWSMessage(t, "")
	p := NewDidKeyProvider("#key-1", false)
	err := p.FetchKeys(context.Background(), &testKeySink{}, msg.Signatures()[0], msg)
	require.NoError(t, err)
}

func Test_DidKeyProvider_FetchKeys_DIDResolutionFails_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, "did:web:example.com")
	p := &DidKeyProvider{
		kidHeader:     "#key-1",
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	err := p.FetchKeys(context.Background(), &testKeySink{}, msg.Signatures()[0], msg)
	require.ErrorContains(t, err, "failed to resolve did document")
}

func Test_DidKeyProvider_FetchKeys_NoMatchingVerificationMethod_ReturnsNoKeysNoError(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](privKey.Public())
	require.NoError(t, err)

	// DID document has a key with a different ID
	docBytes := newTestDIDDocument(t, issuerDID, issuerDID+"#other-key", pubJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	p := &DidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
}

func Test_DidKeyProvider_FetchKeys_PrivateKeyInVerificationMethod_NotReturned_NoError(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"
	fullKID := issuerDID + kidHeader

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privJWK, err := jwk.Import[jwk.Key](privKey) // private key – not allowed in DID document
	require.NoError(t, err)

	docBytes := newTestDIDDocument(t, issuerDID, fullKID, privJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	p := &DidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
}

func Test_DidKeyProvider_FetchKeys_ValidPublicKey_EncryptionUsage_ReturnsNoKeysNoError(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"
	fullKID := issuerDID + kidHeader

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](privKey.Public())
	require.NoError(t, err)

	pubJWK.Set("use", "enc") // key usage is "enc" (encryption) – not allowed for signature verification

	docBytes := newTestDIDDocument(t, issuerDID, fullKID, pubJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	sig := msg.Signatures()[0]
	p := &DidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Len(t, sink.keys, 0)
}

func Test_DidKeyProvider_FetchKeys_ValidPublicKey_FeedsKeyAndAlgorithmToSink(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"
	fullKID := issuerDID + kidHeader

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](privKey.Public())
	require.NoError(t, err)

	docBytes := newTestDIDDocument(t, issuerDID, fullKID, pubJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	sig := msg.Signatures()[0]
	p := &DidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)
}

// Test that when kidHeader does NOT start with '#', it is used as-is (no concatenation with iss).
func Test_DidKeyProvider_FetchKeys_FullKidHeader_UsedAsIs(t *testing.T) {
	const issuerDID = "did:web:example.com"
	// Full absolute DID URL — should be used as-is, not prepended with issuerDID.
	const kidHeader = "did:web:example.com#key-1"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](privKey.Public())
	require.NoError(t, err)

	// DID document uses the full KID, not issuerDID + "#key-1"
	docBytes := newTestDIDDocument(t, issuerDID, kidHeader, pubJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	p := &DidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)
}

// Test that when kidHeader does NOT start with '#' but the DID document only has the fragment-prefixed
// key, resolution fails — confirming no concatenation happened.
func Test_DidKeyProvider_FetchKeys_FullKidHeader_DoesNotConcatenateWithIss_ReturnsNoKeysNoError(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "did:web:example.com#key-1"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](privKey.Public())
	require.NoError(t, err)

	// DID document only has the concatenated form — should NOT match when kidHeader is already absolute.
	docBytes := newTestDIDDocument(t, issuerDID, issuerDID+issuerDID+"#key-1", pubJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	p := &DidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, nil, msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
}

func Test_DidKeyProvider_FetchKeys_MissingAlgHeader_ReturnsNoKeysNoError(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"

	msg := newTestJWSMessage(t, issuerDID)
	sig := jws.NewSignature()
	sig.SetProtectedHeaders(jws.NewHeaders()) // headers present but no alg field
	p := &DidKeyProvider{
		kidHeader: kidHeader,
	}

	sink := &testKeySink{}
	err := p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
}

func Test_DidKeyProvider_FetchKeys_AlgFromJWSHeaderNotJWK(t *testing.T) {
	// Regression: alg must come from the JWS protected header, not from the "alg" field in the DID
	// document's JWK. Before the fix, algorithmFromJWK read the JWK's alg field (ES384 here) and
	// passed it to the sink instead of the header's alg (ES256).
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"
	fullKID := issuerDID + kidHeader

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](privKey.Public())
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
	p := &DidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	// Sink must receive the alg from the JWS header (ES256), not from the JWK field (ES384).
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)
}

// ─── KidKeyProvider: did:jwk ─────────────────────────────────────────────────

// newTestDidJwk derives a did:jwk DID from the public part of the given key.
func newTestDidJwk(t *testing.T, privKey *ecdsa.PrivateKey) string {
	t.Helper()
	pubJWK, err := jwk.Import[jwk.Key](privKey.Public())
	require.NoError(t, err)
	doc, err := (&didjwk.DocumentBuilder{}).FromJwk(pubJWK)
	require.NoError(t, err)
	return doc.ID
}

func Test_DidKeyProvider_FetchKeys_DidJwk_ValidPublicKey_FeedsKeyAndAlgorithmToSink(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didJwk := newTestDidJwk(t, privKey)
	msg := newTestJWSMessageSigned(t, didJwk, privKey, jwa.ES256())
	sig := msg.Signatures()[0]

	p := NewDidKeyProvider("#0", false)
	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)
}

func Test_DidKeyProvider_FetchKeys_DidJwk_FullKidHeader_UsedAsIs(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didJwk := newTestDidJwk(t, privKey)
	msg := newTestJWSMessageSigned(t, didJwk, privKey, jwa.ES256())
	sig := msg.Signatures()[0]

	p := NewDidKeyProvider(didJwk+"#0", false)
	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)
}

func Test_DidKeyProvider_FetchKeys_DidJwk_ForeignMemberOrdering_FeedsKeyAndAlgorithmToSink(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](privKey.Public())
	require.NoError(t, err)

	// A did:jwk minted by an implementation that serializes the JWK members in a different
	// order than jwx does. The spec puts no ordering requirement on the encoded JWK, so
	// resolution has to work off the DID as given instead of re-encoding the parsed key.
	var members map[string]any
	pubJson, err := json.Marshal(pubJWK)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(pubJson, &members))
	reordered := fmt.Sprintf(
		`{"kty":%q,"crv":%q,"x":%q,"y":%q}`,
		members["kty"], members["crv"], members["x"], members["y"],
	)
	didJwk := didjwk.Prefix + base64.RawURLEncoding.EncodeToString([]byte(reordered))

	msg := newTestJWSMessageSigned(t, didJwk, privKey, jwa.ES256())
	sig := msg.Signatures()[0]

	p := NewDidKeyProvider("#0", false)
	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)
}

func Test_DidKeyProvider_FetchKeys_DidJwk_NoMatchingVerificationMethod_ReturnsNoKeysNoError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didJwk := newTestDidJwk(t, privKey)
	msg := newTestJWSMessageSigned(t, didJwk, privKey, jwa.ES256())

	// did:jwk DID documents only contain a verification method with id "#0".
	p := NewDidKeyProvider("#1", false)
	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
}

func Test_DidKeyProvider_FetchKeys_VerificationMethodWithoutPublicKeyJwk_ReturnsNoKeysNoError(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"
	fullKID := issuerDID + kidHeader

	// DID document with a matching verification method that has no publicKeyJwk.
	doc := did.Document{
		ID: issuerDID,
		VerificationMethod: []did.VerificationMethod{
			{ID: fullKID, Type: "JsonWebKey2020", Controller: issuerDID},
		},
	}
	docBytes, err := json.Marshal(doc)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	msg := newTestJWSMessage(t, issuerDID)
	p := &DidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: true,
		httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
	}

	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
}

func Test_DidKeyProvider_FetchKeys_DidJwk_MalformedEncoding_ReturnsError(t *testing.T) {
	msg := newTestJWSMessage(t, "did:jwk:not-valid-base64!!!")
	p := NewDidKeyProvider("#0", false)

	err := p.FetchKeys(context.Background(), &testKeySink{}, msg.Signatures()[0], msg)
	require.ErrorContains(t, err, "failed to resolve did document for kid")
}

func Test_DidKeyProvider_FetchKeys_UnsupportedDidMethod_ReturnsNoKeysNoError(t *testing.T) {
	msg := newTestJWSMessage(t, "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
	p := NewDidKeyProvider("#0", false)

	sink := &testKeySink{}
	err := p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
}

// ─── JwtKeyProvider ──────────────────────────────────────────────────────────

// newSignedJWSMessageWithTyp signs a JWT with the given key and writes the
// requested 'typ' value into the JWS protected header.
func newSignedJWSMessageWithTyp(t *testing.T, issuer string, privKey any, alg jwa.SignatureAlgorithm, typ string, headerExtra map[string]any) *jws.Message {
	t.Helper()
	tok, err := jwt.NewBuilder().Issuer(issuer).Build()
	require.NoError(t, err)
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, typ))
	for k, v := range headerExtra {
		require.NoError(t, headers.Set(k, v))
	}
	tokenBytes, err := jwt.Sign(tok, jwt.WithKey(alg, privKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	msg, err := jws.Parse(tokenBytes)
	require.NoError(t, err)
	return msg
}

func Test_JwtKeyProvider_FetchKeys_MissingTypHeader_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Plain message — no typ header set.
	msg := newTestJWSMessageSigned(t, "test", privKey, jwa.ES256())
	sig := msg.Signatures()[0]

	p := NewJwtKeyProvider([]string{"statuslist+jwt"}, false)
	err = p.FetchKeys(context.Background(), &testKeySink{}, sig, msg)
	require.ErrorContains(t, err, "invalid 'typ' header")
}

func Test_JwtKeyProvider_FetchKeys_DisallowedTyp_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	msg := newSignedJWSMessageWithTyp(t, "test", privKey, jwa.ES256(), "dc+sd-jwt", nil)
	sig := msg.Signatures()[0]

	p := NewJwtKeyProvider([]string{"statuslist+jwt"}, false)
	err = p.FetchKeys(context.Background(), &testKeySink{}, sig, msg)
	require.ErrorContains(t, err, "invalid 'typ' header")
}

func Test_JwtKeyProvider_FetchKeys_AllowedTyp_NoKeyReference_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	msg := newSignedJWSMessageWithTyp(t, "test", privKey, jwa.ES256(), "statuslist+jwt", nil)
	sig := msg.Signatures()[0]

	p := NewJwtKeyProvider([]string{"statuslist+jwt"}, false)
	err = p.FetchKeys(context.Background(), &testKeySink{}, sig, msg)
	require.ErrorContains(t, err, "no supported key reference header")
}

func Test_JwtKeyProvider_FetchKeys_AllowedTyp_WithX5c_DispatchesToX509Provider(t *testing.T) {
	derBytes, privKey, _ := newTestECDSACert(t)
	chain := newTestCertChain(t, derBytes)

	msg := newSignedJWSMessageWithTyp(t, "test", privKey, jwa.ES256(), "statuslist+jwt", map[string]any{
		jws.X509CertChainKey: chain,
	})
	sig := msg.Signatures()[0]

	p := NewJwtKeyProvider([]string{"statuslist+jwt"}, false)
	sink := &testKeySink{}
	err := p.FetchKeys(context.Background(), sink, sig, msg)
	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)

	_, isX509 := p.InnerKeyProvider.(*X509KeyProvider)
	require.True(t, isX509, "InnerKeyProvider should be *X509KeyProvider after x5c dispatch")
}

func Test_JwtKeyProvider_FetchKeys_AllowedTyp_WithKid_DispatchesToKidProvider(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	didJwk := newTestDidJwk(t, privKey)

	msg := newSignedJWSMessageWithTyp(t, didJwk, privKey, jwa.ES256(), "statuslist+jwt", map[string]any{
		jws.KeyIDKey: "#0",
	})
	sig := msg.Signatures()[0]

	p := NewJwtKeyProvider([]string{"statuslist+jwt"}, false)
	sink := &testKeySink{}
	err = p.FetchKeys(context.Background(), sink, sig, msg)
	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)

	_, ok := p.InnerKeyProvider.(*DidKeyProvider)
	require.True(t, ok, "InnerKeyProvider should be *DidKeyProvider after kid dispatch")
}

func Test_JwtKeyProvider_FetchKeys_MultipleAllowedTyps_AcceptsAny(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	didJwk := newTestDidJwk(t, privKey)

	for _, typ := range []string{"dc+sd-jwt", "vc+sd-jwt"} {
		msg := newSignedJWSMessageWithTyp(t, didJwk, privKey, jwa.ES256(), typ, map[string]any{
			jws.KeyIDKey: "#0",
		})
		sig := msg.Signatures()[0]
		p := NewJwtKeyProvider([]string{"dc+sd-jwt", "vc+sd-jwt"}, false)
		err = p.FetchKeys(context.Background(), &testKeySink{}, sig, msg)
		require.NoError(t, err, "typ %s should be accepted", typ)
	}
}

// ─── OAuthDiscoveryJwkKeyProvider ────────────────────────────────────────────
// Resolves the signing key by treating the `iss` claim as an OAuth 2.0
// authorization server (RFC 8414): fetch its metadata, follow jwks_uri, match
// the `kid` protected header. The provider distinguishes two failure classes,
// and the split is deliberate:
//
//   - "this signature is not mine to resolve" (no alg, unsupported alg, no kid,
//     no iss, no jwks_uri) → return nil without feeding the sink, so jwx moves
//     on to the next key provider;
//   - "it is mine but I could not complete it" (network/JWKS failures, kid not
//     in the JWKS) → return an error, so a transient outage is not silently
//     downgraded into "unverifiable".

// testOAuthDiscoveryServer serves an authorization server metadata document and
// the JWKS it points at, counting requests per endpoint so a test can assert the
// provider bailed out *before* touching the network.
type testOAuthDiscoveryServer struct {
	server        *httptest.Server
	discoveryHits atomic.Int64
	jwksHits      atomic.Int64

	discoveryStatus int    // response status for the well-known document (0 → 200)
	jwksStatus      int    // response status for the JWKS (0 → 200)
	omitJwksUri     bool   // serve metadata without a jwks_uri member
	inlineJwks      []byte // JWKS document to embed in the metadata's jwks member
	jwksBody        []byte // JWKS document to serve
}

func newTestOAuthDiscoveryServer(t *testing.T, jwksBody []byte) *testOAuthDiscoveryServer {
	t.Helper()
	s := &testOAuthDiscoveryServer{jwksBody: jwksBody}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.server.Close)
	return s
}

func (s *testOAuthDiscoveryServer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration":
		s.discoveryHits.Add(1)
		if s.discoveryStatus != 0 && s.discoveryStatus != http.StatusOK {
			w.WriteHeader(s.discoveryStatus)
			return
		}
		metadata := map[string]any{"issuer": s.URL()}
		if !s.omitJwksUri {
			metadata["jwks_uri"] = s.URL() + "/jwks.json"
		}
		if s.inlineJwks != nil {
			metadata["jwks"] = json.RawMessage(s.inlineJwks)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	case "/jwks.json":
		s.jwksHits.Add(1)
		if s.jwksStatus != 0 && s.jwksStatus != http.StatusOK {
			w.WriteHeader(s.jwksStatus)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(s.jwksBody)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// URL is the issuer identifier tests put in the `iss` claim.
func (s *testOAuthDiscoveryServer) URL() string { return s.server.URL }

// newTestJWKS marshals a single public key into a JWKS under the given kid. A
// non-empty algField is written to the key's own "alg" member, which the sink
// must ignore in favour of the JWS protected header.
func newTestJWKS(t *testing.T, pub any, kid string, algField string) []byte {
	t.Helper()
	key, err := jwk.Import[jwk.Key](pub)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	if algField != "" {
		require.NoError(t, key.Set(jwk.AlgorithmKey, algField))
	}
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))
	body, err := json.Marshal(set)
	require.NoError(t, err)
	return body
}

// newTestJWSMessageWithHeaders signs a JWT carrying the given iss claim, with
// the given extra protected headers (typically kid).
func newTestJWSMessageWithHeaders(t *testing.T, issuer string, privKey any, alg jwa.SignatureAlgorithm, headerExtra map[string]any) *jws.Message {
	t.Helper()
	builder := jwt.NewBuilder()
	if issuer != "" {
		builder = builder.Issuer(issuer)
	}
	tok, err := builder.Build()
	require.NoError(t, err)
	headers := jws.NewHeaders()
	for k, v := range headerExtra {
		require.NoError(t, headers.Set(k, v))
	}
	tokenBytes, err := jwt.Sign(tok, jwt.WithKey(alg, privKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	msg, err := jws.Parse(tokenBytes)
	require.NoError(t, err)
	return msg
}

func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_InvalidTyp_ReturnsNoKeysNoError(t *testing.T) {
	p := NewJwtKeyProvider([]string{"any+jwt"}, false)

	sink := &testKeySink{}
	err := p.FetchKeys(context.Background(), sink, nil, nil)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
}

func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_HappyPath_FeedsKeyAndAlgorithmToSink(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, newTestJWKS(t, privKey.Public(), "key-1", ""))
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)
	require.Equal(t, int64(1), srv.jwksHits.Load())
}

// Regression guard, mirroring the same rule for the x5c and did providers: the
// algorithm handed to the sink comes from the JWS protected header, never from
// the "alg" member of the resolved JWK.
func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_UsesJWSAlgHeaderNotJwkAlg(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, newTestJWKS(t, privKey.Public(), "key-1", "ES384"))
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
}

func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_MissingAlgHeader_ReturnsNoKeysNoErrorWithoutNetwork(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, newTestJWKS(t, privKey.Public(), "key-1", ""))
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sig := jws.NewSignature()
	sig.SetProtectedHeaders(jws.NewHeaders()) // headers present but no alg field

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
	require.Zero(t, srv.discoveryHits.Load(), "no alg header must not cost a network round trip")
}

// The algorithm allow-list is a security control: a MAC algorithm must never
// reach the sink with an asymmetric key resolved from a JWKS, and it must not
// even trigger discovery.
func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_SymmetricAlg_ReturnsNoKeysNoErrorWithoutNetwork(t *testing.T) {
	srv := newTestOAuthDiscoveryServer(t, nil)
	hmacKey := []byte("0123456789abcdef0123456789abcdef")
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), hmacKey, jwa.HS256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err := p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys, "HS256 is not in the allow-list and must never be fed to the sink")
	require.Zero(t, srv.discoveryHits.Load())
}

func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_AlgNone_ReturnsNoKeysNoErrorWithoutNetwork(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, newTestJWKS(t, privKey.Public(), "key-1", ""))
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.AlgorithmKey, jwa.NoSignature()))
	require.NoError(t, headers.Set(jws.KeyIDKey, "key-1"))
	sig := jws.NewSignature()
	sig.SetProtectedHeaders(headers)

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, sig, msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys, `alg "none" must never resolve a key`)
	require.Zero(t, srv.discoveryHits.Load())
}

func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_MissingKidHeader_ReturnsNoKeysNoErrorWithoutNetwork(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, newTestJWKS(t, privKey.Public(), "key-1", ""))
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), nil) // no kid

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
	require.Zero(t, srv.discoveryHits.Load(), "without a kid there is nothing to look up; discovery must be skipped")
}

func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_MissingIssuerClaim_ReturnsNoKeysNoError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := newTestJWSMessageWithHeaders(t, "", privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
}

// A DID issuer belongs to the did key provider, not to this one. It must decline
// rather than error, so the next provider in the chain still gets its turn.
func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_DidIssuer_DeclinesWithoutBlockingOtherProviders(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := newTestJWSMessageWithHeaders(t, "did:web:example.com", privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "#key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.Empty(t, sink.keys)
	require.NoError(t, err, "a did: issuer is not an OAuth issuer; declining must not surface as an error")
}

func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_DiscoveryUnreachable_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// A server that is started and immediately closed yields an address nothing
	// listens on, so discovery fails at the transport level.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	msg := newTestJWSMessageWithHeaders(t, deadURL, privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, "failed to fetch OAuth2/OpenID discovery metadata")
	require.Empty(t, sink.keys)
}

func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_DiscoveryWithoutJwksUri_ReturnsNoKeysNoError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, nil)
	srv.omitJwksUri = true
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Empty(t, sink.keys)
	require.Zero(t, srv.jwksHits.Load())
}

// The jwks member is non-standard in RFC 8414 but appears in practice, so it is
// honoured as a fallback: with no jwks_uri to dereference, the key is resolved
// from the metadata document itself.
func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_InlineJwksWithoutJwksUri_FeedsKeyAndAlgorithmToSink(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, nil)
	srv.omitJwksUri = true
	srv.inlineJwks = newTestJWKS(t, privKey.Public(), "key-1", "")
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, jwa.ES256(), sink.keys[0].alg)
	require.NotNil(t, sink.keys[0].key)
	require.Zero(t, srv.jwksHits.Load(), "an inline jwks member must not cost a JWKS round trip")
}

// The standard member wins: the inline jwks is only consulted when jwks_uri is
// absent, so a JWT whose kid both sets publish is verified against the hosted key.
func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_JwksUriTakesPrecedenceOverInlineJwks(t *testing.T) {
	hostedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	inlineKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, newTestJWKS(t, hostedKey.Public(), "key-1", ""))
	srv.inlineJwks = newTestJWKS(t, inlineKey.Public(), "key-1", "")
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), hostedKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.NoError(t, err)
	require.Len(t, sink.keys, 1)
	require.Equal(t, int64(1), srv.jwksHits.Load(), "jwks_uri must still be dereferenced when an inline jwks is also present")

	// The key that reached the sink is the hosted one, not the key the inline
	// jwks member publishes under the same kid.
	resolved, ok := sink.keys[0].key.(jwk.Key)
	require.True(t, ok, "expected a jwk.Key on the sink, got %T", sink.keys[0].key)
	resolvedPub, err := jwk.Export[*ecdsa.PublicKey](resolved)
	require.NoError(t, err)
	require.True(t, hostedKey.PublicKey.Equal(resolvedPub), "the sink received the inline key instead of the hosted one")
}

// Precedence is not a fallback chain in the other direction either: once
// jwks_uri is present it is the only source consulted, so a kid it does not
// publish fails even when the inline jwks member does publish it.
func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_KidOnlyInInlineJwks_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, newTestJWKS(t, privKey.Public(), "hosted-key", ""))
	srv.inlineJwks = newTestJWKS(t, privKey.Public(), "inline-key", "")
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "inline-key"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, "no key found in JWKS with kid inline-key")
	require.Empty(t, sink.keys)
}

// A kid the inline set does not publish is a hard failure rather than a silent
// decline: the metadata already stated which keys the issuer signs with, and
// there is no jwks_uri left to try.
func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_KidNotInInlineJwks_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, nil)
	srv.omitJwksUri = true
	srv.inlineJwks = newTestJWKS(t, privKey.Public(), "published-key", "")
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "unpublished-key"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, "no key found in jwks member of discovery metadata")
	require.ErrorContains(t, err, "unpublished-key")
	require.Empty(t, sink.keys)
	require.Zero(t, srv.jwksHits.Load())
}

func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_JwksFetchFails_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, nil)
	srv.jwksStatus = http.StatusInternalServerError
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, "failed to fetch or parse JWKS")
	require.Empty(t, sink.keys)
}

func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_KidNotInJwks_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, newTestJWKS(t, privKey.Public(), "published-key", ""))
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "unpublished-key"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, "no key found in JWKS with kid unpublished-key")
	require.Empty(t, sink.keys)
}

// malformedJwkEntry is an EC key object missing the mandatory x and y
// coordinates, so jwk cannot decode it into a key.
const malformedJwkEntry = `{"kty":"EC","crv":"P-256","kid":"%s"}`

// newTestRawJWKS builds a JWKS body from raw JSON key objects, so a test can
// include an entry jwk.Parse cannot decode.
func newTestRawJWKS(keys ...string) []byte {
	return []byte(`{"keys":[` + strings.Join(keys, ",") + `]}`)
}

// newTestJWKJSON marshals a public key into a single JWK object under the given kid.
func newTestJWKJSON(t *testing.T, pub any, kid string) string {
	t.Helper()
	key, err := jwk.Import[jwk.Key](pub)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	body, err := json.Marshal(key)
	require.NoError(t, err)
	return string(body)
}

// An unparseable entry must reject the whole JWKS. jwk.Fetch, which this
// provider used before jwx v4 removed it, parsed sets strictly; jwx v4's
// default keeps an undecodable entry as a placeholder key that keeps its own
// kid, so a lookup on the attacker-chosen kid would hand that placeholder to
// the sink instead of failing the fetch.
func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_MalformedJwksEntry_RejectsWholeSet(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, newTestRawJWKS(fmt.Sprintf(malformedJwkEntry, "key-1")))
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, "failed to fetch or parse JWKS")
	require.Empty(t, sink.keys, "a placeholder for an unparseable entry may not reach the sink")
}

// Rejecting the set in full also means a usable sibling key in a partly broken
// JWKS is not accepted, which is what jwk.Fetch did.
func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_MalformedJwksEntry_RejectsUsableSiblingKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := newTestOAuthDiscoveryServer(t, newTestRawJWKS(
		fmt.Sprintf(malformedJwkEntry, "broken-key"),
		newTestJWKJSON(t, privKey.Public(), "key-1"),
	))
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, "failed to fetch or parse JWKS")
	require.Empty(t, sink.keys)
}

// jwks_uri comes from discovery metadata at the unverified iss claim, so the
// endpoint is attacker-chosen and the body must stay capped as it was under
// jwk.Fetch. The padding member below is the only thing oversizing this
// document: the provider parses sets strictly, and strict parsing still
// tolerates unknown members, so it would be accepted under the cap.
func Test_OAuthDiscoveryJwkKeyProvider_FetchKeys_OversizedJwks_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	oversized := []byte(`{"keys":[` + newTestJWKJSON(t, privKey.Public(), "key-1") +
		`],"padding":"` + strings.Repeat("a", maxJwksBytes) + `"}`)
	require.Greater(t, len(oversized), maxJwksBytes)

	srv := newTestOAuthDiscoveryServer(t, oversized)
	msg := newTestJWSMessageWithHeaders(t, srv.URL(), privKey, jwa.ES256(), map[string]any{jws.KeyIDKey: "key-1"})

	sink := &testKeySink{}
	p := NewOAuthDiscoveryJwkKeyProvider([]string{"JWT"}, http.DefaultClient)
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, fmt.Sprintf("response exceeds %d bytes", maxJwksBytes))
	require.Empty(t, sink.keys)
}

// The credential and status list token verification paths must refuse an algorithm the metadata
// validators refuse up front, otherwise a strict validator only advertises strictness while
// verification honours the algorithm anyway. HS256 is the case with teeth: it is symmetric, so
// honouring it would mean verifying an issuer signature against a shared secret.
func Test_X509KeyProvider_FetchKeys_RejectedAlg_ReturnsError(t *testing.T) {
	derBytes, _, _ := newTestECDSACert(t)

	p := NewX509KeyProvider(newTestCertChain(t, derBytes))
	sink := &testKeySink{}

	msg := newTestJWSMessageSigned(t, "test", []byte("a-shared-secret-of-sufficient-length"), jwa.HS256())
	err := p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, `unsupported signature algorithm "HS256"`)
	require.Empty(t, sink.keys, "no key may reach the sink for a rejected algorithm")
}

// ML-DSA is the case HS256 cannot cover: jwx registers it from v4.4.0 on and verifies it against
// crypto/mldsa, so the token below carries a signature this build is able to check. Only the
// allow-list stands between it and the sink, which is what makes it worth signing for real rather
// than asserting on the name.
func Test_X509KeyProvider_FetchKeys_MLDSA_ReturnsError(t *testing.T) {
	derBytes, _, _ := newTestECDSACert(t)

	privKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	p := NewX509KeyProvider(newTestCertChain(t, derBytes))
	sink := &testKeySink{}

	msg := newTestJWSMessageSigned(t, "test", privKey, jwa.MLDSA44())
	err = p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, `unsupported signature algorithm "ML-DSA-44"`)
	require.Empty(t, sink.keys)
}

// RFC 9864 deprecates the EdDSA algorithm name in favour of Ed25519, but issuers still sign with
// it and jwx verifies it, so both names must reach the sink. Refusing EdDSA would reject tokens
// this module can verify.
func Test_X509KeyProvider_FetchKeys_EdDSANames_FeedKeyToSink(t *testing.T) {
	derBytes, _, _ := newTestECDSACert(t)

	_, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, alg := range []jwa.SignatureAlgorithm{jwa.EdDSA(), jwa.EdDSAEd25519()} {
		t.Run(alg.String(), func(t *testing.T) {
			p := NewX509KeyProvider(newTestCertChain(t, derBytes))
			sink := &testKeySink{}

			msg := newTestJWSMessageSigned(t, "test", edPrivKey, alg)
			err := p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

			require.NoError(t, err)
			require.Len(t, sink.keys, 1)
			require.Equal(t, alg, sink.keys[0].alg)
		})
	}
}

func Test_DidKeyProvider_FetchKeys_RejectedAlg_ReturnsError(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"

	p := &DidKeyProvider{kidHeader: kidHeader, allowInsecure: true}
	sink := &testKeySink{}

	msg := newTestJWSMessageSigned(t, issuerDID, []byte("a-shared-secret-of-sufficient-length"), jwa.HS256())
	err := p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

	require.ErrorContains(t, err, `unsupported signature algorithm "HS256"`)
	require.Empty(t, sink.keys, "no key may reach the sink for a rejected algorithm")
}

func Test_DidKeyProvider_FetchKeys_EdDSANames_FeedKeyToSink(t *testing.T) {
	const issuerDID = "did:web:example.com"
	const kidHeader = "#key-1"

	pub, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](pub)
	require.NoError(t, err)

	docBytes := newTestDIDDocument(t, issuerDID, issuerDID+kidHeader, pubJWK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docBytes)
	}))
	defer server.Close()

	for _, alg := range []jwa.SignatureAlgorithm{jwa.EdDSA(), jwa.EdDSAEd25519()} {
		t.Run(alg.String(), func(t *testing.T) {
			p := &DidKeyProvider{
				kidHeader:     kidHeader,
				allowInsecure: true,
				httpClient:    &http.Client{Transport: &testRedirectTransport{targetAddr: server.Listener.Addr().String()}},
			}
			sink := &testKeySink{}

			msg := newTestJWSMessageSigned(t, issuerDID, privKey, alg)
			err := p.FetchKeys(context.Background(), sink, msg.Signatures()[0], msg)

			require.NoError(t, err)
			require.Len(t, sink.keys, 1)
			require.Equal(t, alg, sink.keys[0].alg)
		})
	}
}
