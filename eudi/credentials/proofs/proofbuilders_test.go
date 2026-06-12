package proofs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

type fixedClock struct {
	t time.Time
}

func (c fixedClock) Now() time.Time {
	return c.t
}

var testFixedTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func mustGenerateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func mustGetPublicJWK(t *testing.T, privKey *ecdsa.PrivateKey) jwk.Key {
	t.Helper()
	pubJwk, err := jwk.Import(privKey.Public())
	require.NoError(t, err)
	return pubJwk
}

func parseProtectedHeaders(t *testing.T, jwtStr string) jws.Headers {
	t.Helper()
	msg, err := jws.Parse([]byte(jwtStr))
	require.NoError(t, err)
	require.Len(t, msg.Signatures(), 1)
	return msg.Signatures()[0].ProtectedHeaders()
}

func Test_JwtProofBuilder_Build_JWKMethod_WithNonce_Succeeds(t *testing.T) {
	key := mustGenerateECKey(t)
	nonce := "test-nonce-12345"

	builder := NewJwtProofBuilder(
		"https://issuer.example.com",
		"https://server.example.com",
		jwa.ES256(),
		&nonce,
		fixedClock{t: testFixedTime},
		CryptographicBindingMethod_JWK,
	)

	result, err := builder.Build(key)
	require.NoError(t, err)

	jwtStr, ok := result.(string)
	require.True(t, ok, "result should be a string")
	require.NotEmpty(t, jwtStr)

	// Verify signature and parse claims
	pubJwk := mustGetPublicJWK(t, key)
	token, err := jwt.Parse([]byte(jwtStr), jwt.WithKey(jwa.ES256(), pubJwk))
	require.NoError(t, err)

	issuer, _ := token.Issuer()
	require.Equal(t, "https://issuer.example.com", issuer)

	audience, _ := token.Audience()
	require.Contains(t, audience, "https://server.example.com")

	issuedAt, _ := token.IssuedAt()
	require.Equal(t, testFixedTime.Unix(), issuedAt.Unix())

	var nonceClaim string
	err = token.Get("nonce", &nonceClaim)
	require.NoError(t, err, "nonce claim should be present")
	require.Equal(t, nonce, nonceClaim)

	// Verify JWS protected headers
	headers := parseProtectedHeaders(t, jwtStr)

	typ, hasTyp := headers.Type()
	require.True(t, hasTyp)
	require.Equal(t, "openid4vci-proof+jwt", typ)

	alg, hasAlg := headers.Algorithm()
	require.True(t, hasAlg)
	require.Equal(t, jwa.ES256(), alg)

	jwkHeader, hasJwk := headers.JWK()
	require.True(t, hasJwk, "JWK header should be present for JWK binding method")
	require.NotNil(t, jwkHeader)

	_, hasKid := headers.KeyID()
	require.False(t, hasKid, "kid header should not be present for JWK binding method")
}

func Test_JwtProofBuilder_Build_JWKMethod_WithoutNonce_OmitsNonceClaim(t *testing.T) {
	key := mustGenerateECKey(t)

	builder := NewJwtProofBuilder(
		"https://issuer.example.com",
		"https://server.example.com",
		jwa.ES256(),
		nil,
		fixedClock{t: testFixedTime},
		CryptographicBindingMethod_JWK,
	)

	result, err := builder.Build(key)
	require.NoError(t, err)

	jwtStr, ok := result.(string)
	require.True(t, ok)

	pubJwk := mustGetPublicJWK(t, key)
	token, err := jwt.Parse([]byte(jwtStr), jwt.WithKey(jwa.ES256(), pubJwk))
	require.NoError(t, err)

	var nonceVal string
	err = token.Get("nonce", &nonceVal)
	require.Error(t, err, "nonce claim should not be present when no nonce is provided")
}

func Test_JwtProofBuilder_Build_DIDJwkMethod_SetsKidToDIDAssertionMethod(t *testing.T) {
	key := mustGenerateECKey(t)

	builder := NewJwtProofBuilder(
		"https://issuer.example.com",
		"https://server.example.com",
		jwa.ES256(),
		nil,
		fixedClock{t: testFixedTime},
		CryptographicBindingMethod_DID_JWK,
	)

	result, err := builder.Build(key)
	require.NoError(t, err)

	jwtStr, ok := result.(string)
	require.True(t, ok)
	require.NotEmpty(t, jwtStr)

	// Verify signature using the known public key
	pubJwk := mustGetPublicJWK(t, key)
	_, err = jws.Verify([]byte(jwtStr), jws.WithKey(jwa.ES256(), pubJwk))
	require.NoError(t, err)

	headers := parseProtectedHeaders(t, jwtStr)

	typ, hasTyp := headers.Type()
	require.True(t, hasTyp)
	require.Equal(t, "openid4vci-proof+jwt", typ)

	kid, hasKid := headers.KeyID()
	require.True(t, hasKid, "kid header should be present for DID_JWK binding method")
	require.True(t, strings.HasPrefix(kid, "did:jwk:"), "kid should be a did:jwk DID, got: %s", kid)
	require.True(t, strings.HasSuffix(kid, "#0"), "kid should reference the DID assertion method (#0), got: %s", kid)
}

func Test_JwtProofBuilder_Build_COSEMethod_ReturnsUnsupportedError(t *testing.T) {
	key := mustGenerateECKey(t)

	builder := NewJwtProofBuilder(
		"https://issuer.example.com",
		"https://server.example.com",
		jwa.ES256(),
		nil,
		fixedClock{t: testFixedTime},
		CryptographicBindingMethod_COSE,
	)

	_, err := builder.Build(key)

	require.Error(t, err)
	require.ErrorContains(t, err, "unsupported cryptographic binding method")
	require.ErrorContains(t, err, string(CryptographicBindingMethod_COSE))
}

func Test_JwtProofBuilder_Build_UnknownMethod_ReturnsUnsupportedError(t *testing.T) {
	key := mustGenerateECKey(t)
	unknownMethod := CryptographicBindingMethod("unknown-method")

	builder := NewJwtProofBuilder(
		"https://issuer.example.com",
		"https://server.example.com",
		jwa.ES256(),
		nil,
		fixedClock{t: testFixedTime},
		unknownMethod,
	)

	_, err := builder.Build(key)

	require.Error(t, err)
	require.ErrorContains(t, err, "unsupported cryptographic binding method")
	require.ErrorContains(t, err, string(unknownMethod))
}
