package openid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// An issuer whose credential does not hold up against its own certificate
// chain has failed the identity gate, not merely earned a low rung. The wallet
// has to be able to tell the app which of the two happened, so the app can say
// "the request is not trustworthy" instead of "something went wrong".

func Test_openid4vciSession_obtainCredential_issuerValidationFailureIsTyped(t *testing.T) {
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: tamperedTestCredential(t)}},
		})
		_, _ = w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired, credEndpointHandler)
	defer ts.Close()
	sess.holderVerifier = sdjwtvc.NewHolderVerificationProcessor(
		sdjwtvc.CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
	)

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")

	require.Error(t, err)
	require.True(t, eudi.IsPartyValidationFailure(err),
		"a credential that fails to verify against its issuer is an identity gate failure")
}

func Test_openid4vciSession_obtainCredential_protocolFailureIsNotTyped(t *testing.T) {
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_credential_request"}`))
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired, credEndpointHandler)
	defer ts.Close()

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")

	require.Error(t, err)
	require.False(t, eudi.IsPartyValidationFailure(err),
		"a protocol error says nothing about who the issuer is")
}

// tamperedTestCredential builds a well-formed SD-JWT VC and then breaks the
// issuer's signature over it, which is what a party whose vouching does not
// hold up looks like on the wire.
func tamperedTestCredential(t *testing.T) string {
	t.Helper()

	certChain, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	require.NoError(t, err)

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderJwkKey, err := jwk.Import(holderKey)
	require.NoError(t, err)

	credential, err := createTestSdJwtVcWithHolderKey(
		"test.credential.type",
		"https://test-issuer.example.com",
		map[string]string{"name": "Test User"},
		certChain,
		holderJwkKey,
	)
	require.NoError(t, err)

	// The issuer-signed JWT is the first ~-separated part; flip a character of
	// its signature so the chain no longer vouches for these claims.
	parts := strings.SplitN(string(credential), "~", 2)
	require.Len(t, parts, 2)
	jwtParts := strings.Split(parts[0], ".")
	require.Len(t, jwtParts, 3)
	jwtParts[2] = flipFirstRune(t, jwtParts[2])

	return strings.Join(jwtParts, ".") + "~" + parts[1]
}

func flipFirstRune(t *testing.T, s string) string {
	t.Helper()
	require.NotEmpty(t, s)
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}
