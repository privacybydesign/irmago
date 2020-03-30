package requestorserver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestPresharedKeyAuthenticator_Authenticate(t *testing.T) {
	authenticator := PresharedKeyAuthenticator{presharedkeys: map[string]string{
		"token": "my_requestor",
	}}

	validRequestBody := []byte(`{"request": {"@context":"https://irma.app/ld/request/disclosure/v2","disclose":[[["irma-demo.RU.studentCard.studentID"]]]}}`)

	t.Run("valid", func(t *testing.T) {
		requestHeaders := map[string][]string{
			"Authorization": {"token"},
			"Content-Type":  {"application/json"},
		}

		applies, parsedRequest, requestor, err := authenticator.AuthenticateSession(requestHeaders, validRequestBody)
		if err != nil {
			require.NoError(t, err)
		}
		require.True(t, applies)
		require.Equal(t, "irma-demo.RU.studentCard.studentID", parsedRequest.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
		require.Equal(t, "my_requestor", requestor)
	})

	// tests below here will give warnings
	server.Logger.SetLevel(logrus.ErrorLevel)
	t.Run("invalid content", func(t *testing.T) {
		requestHeaders := map[string][]string{
			"Authorization": {"token"},
			"Content-Type":  {"application/json"},
		}
		invalidRequestBody := []byte(`{}`)

		applies, _, _, err := authenticator.AuthenticateSession(requestHeaders, invalidRequestBody)
		require.Error(t, err)
		require.True(t, applies)
	})

	t.Run("invalid token", func(t *testing.T) {
		requestHeaders := map[string][]string{
			"Authorization": {"invalid"},
			"Content-Type":  {"application/json"},
		}
		applies, _, _, err := authenticator.AuthenticateSession(requestHeaders, validRequestBody)
		require.True(t, applies)
		require.Error(t, err)
	})

	t.Run("no authorization header", func(t *testing.T) {
		requestHeaders := map[string][]string{
			"UnusedHeader": {"token"},
			"Content-Type": {"application/json"},
		}
		applies, _, _, err := authenticator.AuthenticateSession(requestHeaders, validRequestBody)
		require.False(t, applies)
		if err != nil {
			require.NoError(t, err)
		}
	})

	t.Run("without content type", func(t *testing.T) {
		requestHeaders := map[string][]string{
			"Authorization": {"token"},
		}
		applies, _, _, err := authenticator.AuthenticateSession(requestHeaders, validRequestBody)
		require.False(t, applies)
		if err != nil {
			require.NoError(t, err)
		}
	})
}

func TestHmacAuthenticator_Authenticate(t *testing.T) {
	key := []byte("953BCAB6F25F3622619A9A16BE895")
	invalidKey := []byte("A5BB219FFB6199756DF8A284A3392")
	authenticator := HmacAuthenticator{
		hmackeys: map[string]interface{}{
			"my_requestor": key,
		},
		maxRequestAge: 500,
	}
	disclosureRequestData := `{"@context":"https://irma.app/ld/request/disclosure/v2","disclose":[[["irma-demo.RU.studentCard.studentID"]]]}`
	disclosureRequest := &irma.DisclosureRequest{}
	require.NoError(t, json.Unmarshal([]byte(disclosureRequestData), disclosureRequest))

	j := irma.NewServiceProviderJwt("my_requestor", disclosureRequest)
	validJwtData, jErr := j.Sign(jwt.SigningMethodHS256, key)
	require.NoError(t, jErr)

	requestHeaders := map[string][]string{
		"Content-Type": {"text/plain"},
	}

	t.Run("valid", func(t *testing.T) {
		applies, parsedRequest, requestor, err := authenticator.AuthenticateSession(requestHeaders, []byte(validJwtData))
		if err != nil {
			require.NoError(t, err)
		}
		require.True(t, applies)
		require.Equal(t, "irma-demo.RU.studentCard.studentID", parsedRequest.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
		require.Equal(t, "my_requestor", requestor)
	})

	server.Logger.SetLevel(logrus.ErrorLevel)
	t.Run("invalid jwt requestor", func(t *testing.T) {
		j := irma.NewServiceProviderJwt("another_requestor", disclosureRequest)
		invalidJwtData, jErr := j.Sign(jwt.SigningMethodHS256, key)
		require.NoError(t, jErr)

		applies, _, _, err := authenticator.AuthenticateSession(requestHeaders, []byte(invalidJwtData))
		require.True(t, applies)
		require.Error(t, err)
	})

	t.Run("empty jwt data", func(t *testing.T) {
		claims := (*jwt.MapClaims)(&map[string]interface{}{
			"sub":       "verification_request",
			"iss":       "my_requestor",
			"iat":       time.Now().Unix(),
			"sprequest": map[string]interface{}{},
		})
		emptyJwtData, jErr := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		require.NoError(t, jErr)
		applies, _, _, err := authenticator.AuthenticateSession(requestHeaders, []byte(emptyJwtData))
		require.True(t, applies)
		require.Error(t, err)
		require.Equal(t, string(server.ErrorInvalidRequest.Type), err.ErrorName)
	})

	t.Run("old jwt data", func(t *testing.T) {
		j := irma.NewServiceProviderJwt("my_requestor", disclosureRequest)
		j.IssuedAt = (irma.Timestamp)(time.Unix(0, 0))
		invalidJwtData, jErr := j.Sign(jwt.SigningMethodHS256, key)
		require.NoError(t, jErr)
		applies, _, _, err := authenticator.AuthenticateSession(requestHeaders, []byte(invalidJwtData))
		require.True(t, applies)
		require.Error(t, err)
		require.Equal(t, string(server.ErrorUnauthorized.Type), err.ErrorName)
	})

	t.Run("jwt data not yet valid", func(t *testing.T) {
		j := irma.NewServiceProviderJwt("my_requestor", disclosureRequest)
		j.IssuedAt = (irma.Timestamp)(time.Now().AddDate(1, 0, 0))
		invalidJwtData, jErr := j.Sign(jwt.SigningMethodHS256, key)
		require.NoError(t, jErr)
		applies, _, _, err := authenticator.AuthenticateSession(requestHeaders, []byte(invalidJwtData))
		require.True(t, applies)
		require.Error(t, err)
		require.Equal(t, string(server.ErrorInvalidRequest.Type), err.ErrorName)
	})

	t.Run("jwt signed using invalid key", func(t *testing.T) {
		j := irma.NewServiceProviderJwt("my_requestor", disclosureRequest)
		invalidJwtData, jErr := j.Sign(jwt.SigningMethodHS256, invalidKey)
		require.NoError(t, jErr)
		applies, _, _, err := authenticator.AuthenticateSession(requestHeaders, []byte(invalidJwtData))
		require.True(t, applies)
		require.Error(t, err)
	})
}
