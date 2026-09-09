package irma_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/privacybydesign/irmago/internal/jose"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/require"
)

// The wire format of these claims is the one RFC 7519 registers, and IRMA clients and servers of
// every version have to agree on it, so it is pinned here rather than left to the struct tags.
func TestRegisteredClaimsWireFormat(t *testing.T) {
	claims := irma.RegisteredClaims{
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  irma.ClaimStrings{"audience"},
		ExpiresAt: irma.NewNumericDate(time.Unix(1700000060, 0)),
		NotBefore: irma.NewNumericDate(time.Unix(1700000030, 0)),
		IssuedAt:  irma.NewNumericDate(time.Unix(1700000000, 0)),
		ID:        "id",
	}

	encoded, err := json.Marshal(claims)
	require.NoError(t, err)
	require.JSONEq(t,
		`{"iss":"issuer","sub":"subject","aud":["audience"],"exp":1700000060,"nbf":1700000030,"iat":1700000000,"jti":"id"}`,
		string(encoded),
	)

	var decoded irma.RegisteredClaims
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, claims, decoded)
}

func TestRegisteredClaimsOmitsEmptyFields(t *testing.T) {
	encoded, err := json.Marshal(irma.RegisteredClaims{Subject: "subject"})
	require.NoError(t, err)
	require.JSONEq(t, `{"sub":"subject"}`, string(encoded))
}

// RFC 7519 allows "aud" to be either a single string or an array of them.
func TestClaimStringsAcceptsBothAudienceForms(t *testing.T) {
	var single irma.RegisteredClaims
	require.NoError(t, json.Unmarshal([]byte(`{"aud":"one"}`), &single))
	require.Equal(t, irma.ClaimStrings{"one"}, single.Audience)

	var multiple irma.RegisteredClaims
	require.NoError(t, json.Unmarshal([]byte(`{"aud":["one","two"]}`), &multiple))
	require.Equal(t, irma.ClaimStrings{"one", "two"}, multiple.Audience)

	var wrongType irma.RegisteredClaims
	require.Error(t, json.Unmarshal([]byte(`{"aud":[1]}`), &wrongType))
}

// Claims structs that embed RegisteredClaims inherit its wire format.
func TestEmbeddedRegisteredClaims(t *testing.T) {
	claims := irma.KeyshareAuthRequestClaims{
		RegisteredClaims: irma.RegisteredClaims{ExpiresAt: irma.NewNumericDate(time.Unix(1700000060, 0))},
		Username:         "user",
	}

	encoded, err := json.Marshal(claims)
	require.NoError(t, err)
	require.JSONEq(t, `{"exp":1700000060,"id":"user"}`, string(encoded))

	var decoded irma.KeyshareAuthRequestClaims
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, claims, decoded)
}

// ParseApiServerJwt decodes into a claims struct, which it could not do before this package
// moved to jwx: it handed the JWT library a struct value rather than a pointer, and every call
// failed with "cannot unmarshal object into Go value of type jwt.Claims".
func TestParseApiServerJwt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token, err := jose.Sign(map[string]any{
		"sub":        "disclosure_result",
		"iat":        time.Now().Add(-time.Minute).Unix(),
		"exp":        time.Now().Add(time.Minute).Unix(),
		"attributes": map[string]string{"irma-demo.RU.studentCard.studentID": "s1234567"},
	}, jwa.RS256(), key, nil)
	require.NoError(t, err)

	attributes, err := irma.ParseApiServerJwt(token, &key.PublicKey)
	require.NoError(t, err)
	disclosed := attributes[irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")]
	require.NotNil(t, disclosed)
	require.Equal(t, "s1234567", *disclosed.RawValue)
}

func TestParseApiServerJwtRejectsExpiredToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token, err := jose.Sign(map[string]any{
		"sub": "disclosure_result",
		"exp": time.Now().Add(-time.Minute).Unix(),
	}, jwa.RS256(), key, nil)
	require.NoError(t, err)

	_, err = irma.ParseApiServerJwt(token, &key.PublicKey)
	require.ErrorAs(t, err, &irma.ExpiredError{})
}
