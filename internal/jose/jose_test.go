package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/internal/jose"
	"github.com/stretchr/testify/require"
)

type testClaims struct {
	Issuer string `json:"iss,omitempty"`
	Foo    string `json:"foo,omitempty"`
}

// expiringClaims implements jose.Validator, so that Verify checks it and
// VerifyWithoutClaimsValidation does not.
type expiringClaims struct {
	testClaims
	valid bool
}

func (c expiringClaims) ValidateClaims(time.Time) error {
	if c.valid {
		return nil
	}
	return errExpired
}

var errExpired = &expiredError{}

type expiredError struct{}

func (*expiredError) Error() string { return "expired" }

func TestSignAndVerify(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	hmacKey := []byte("a secret of at least 32 bytes ..")

	for _, tc := range []struct {
		name      string
		alg       jwa.SignatureAlgorithm
		signKey   any
		verifyKey any
	}{
		{name: "RS256", alg: jwa.RS256(), signKey: rsaKey, verifyKey: &rsaKey.PublicKey},
		{name: "ES256", alg: jwa.ES256(), signKey: ecKey, verifyKey: &ecKey.PublicKey},
		{name: "HS256", alg: jwa.HS256(), signKey: hmacKey, verifyKey: hmacKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := jose.Sign(testClaims{Issuer: "me", Foo: "bar"}, tc.alg, tc.signKey, nil)
			require.NoError(t, err)

			var claims testClaims
			require.NoError(t, jose.Verify(token, &claims, jose.StaticKey(tc.alg, tc.verifyKey)))
			require.Equal(t, "me", claims.Issuer)
			require.Equal(t, "bar", claims.Foo)

			alg, err := jose.SignatureAlgorithm(token)
			require.NoError(t, err)
			require.Equal(t, tc.alg, alg)
		})
	}
}

func TestSignSetsTypeAndExtraHeaders(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token, err := jose.Sign(testClaims{Foo: "bar"}, jwa.ES256(), key, map[string]any{"kid": "7"})
	require.NoError(t, err)

	require.Equal(t, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "7"}, decodeHeader(t, token))
}

func TestSignLeavesOutNilHeaders(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var chain []string
	token, err := jose.Sign(testClaims{Foo: "bar"}, jwa.ES256(), key, map[string]any{"x5c": chain})
	require.NoError(t, err)

	require.NotContains(t, decodeHeader(t, token), "x5c")
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token, err := jose.Sign(testClaims{Foo: "bar"}, jwa.ES256(), key, nil)
	require.NoError(t, err)

	var claims testClaims
	require.Error(t, jose.Verify(token, &claims, jose.StaticKey(jwa.ES256(), &otherKey.PublicKey)))
}

// A token signed with HMAC must not verify against an RSA public key, even when that public key
// is what the attacker used as the HMAC secret.
func TestVerifyRejectsAlgorithmSubstitution(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	token, err := jose.Sign(testClaims{Foo: "bar"}, jwa.HS256(), publicKeyDer, nil)
	require.NoError(t, err)

	var claims testClaims
	require.Error(t, jose.Verify(token, &claims, jose.StaticKey(jwa.RS256(), &rsaKey.PublicKey)))
}

func TestVerifyValidatesClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token, err := jose.Sign(testClaims{Foo: "bar"}, jwa.ES256(), key, nil)
	require.NoError(t, err)

	claims := expiringClaims{}
	require.ErrorIs(t, jose.Verify(token, &claims, jose.StaticKey(jwa.ES256(), &key.PublicKey)), errExpired)
	require.NoError(t, jose.VerifyWithoutClaimsValidation(token, &claims, jose.StaticKey(jwa.ES256(), &key.PublicKey)))
	require.Equal(t, "bar", claims.Foo)
}

// The key function may be handed claims that are not verified yet, which is what lets a token
// name the key it is signed with in its own body.
func TestVerifyFillsClaimsBeforeCallingKeyFunc(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token, err := jose.Sign(testClaims{Issuer: "me"}, jwa.ES256(), key, nil)
	require.NoError(t, err)

	var claims testClaims
	var issuerSeenByKeyFunc string
	require.NoError(t, jose.Verify(token, &claims, func(jws.Headers) (jwa.SignatureAlgorithm, any, error) {
		issuerSeenByKeyFunc = claims.Issuer
		return jwa.ES256(), &key.PublicKey, nil
	}))
	require.Equal(t, "me", issuerSeenByKeyFunc)
}

func TestParseUnverifiedIgnoresSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token, err := jose.Sign(testClaims{Issuer: "me"}, jwa.ES256(), key, nil)
	require.NoError(t, err)
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	tampered := strings.Join([]string{parts[0], parts[1], base64.RawURLEncoding.EncodeToString([]byte("nope"))}, ".")

	var claims testClaims
	headers, err := jose.ParseUnverified(tampered, &claims)
	require.NoError(t, err)
	require.Equal(t, "me", claims.Issuer)
	alg, ok := headers.Algorithm()
	require.True(t, ok)
	require.Equal(t, jwa.ES256(), alg)

	require.Error(t, jose.Verify(tampered, &claims, jose.StaticKey(jwa.ES256(), &key.PublicKey)))
}

func TestParseRSAKeysFromPEM(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateDer, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	privatePem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDer})
	publicDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	publicPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDer})

	parsedPrivate, err := jose.ParseRSAPrivateKeyFromPEM(privatePem)
	require.NoError(t, err)
	require.True(t, key.Equal(parsedPrivate))

	parsedPublic, err := jose.ParseRSAPublicKeyFromPEM(publicPem)
	require.NoError(t, err)
	require.True(t, key.PublicKey.Equal(parsedPublic))

	_, err = jose.ParseRSAPrivateKeyFromPEM([]byte("not a pem file"))
	require.Error(t, err)
}

func decodeHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	encoded, _, found := strings.Cut(token, ".")
	require.True(t, found)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	header := map[string]any{}
	require.NoError(t, json.Unmarshal(decoded, &header))
	return header
}
