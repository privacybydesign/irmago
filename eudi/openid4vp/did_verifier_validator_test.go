package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/privacybydesign/irmago/eudi/dnssec"
	"github.com/stretchr/testify/require"
)

const testDidWeb = "did:web:example.com"

// fakeDnssecVerifier records the hosts it was asked to verify and returns a fixed result.
type fakeDnssecVerifier struct {
	result dnssec.Result
	hosts  []string
}

func (f *fakeDnssecVerifier) Verify(host string) dnssec.Result {
	f.hosts = append(f.hosts, host)
	return f.result
}

// didWebHostOverride redirects all requests to the test server hosting the DID document.
type didWebHostOverride struct {
	targetHost string
}

func (t *didWebHostOverride) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = t.targetHost
	return http.DefaultTransport.RoundTrip(clone)
}

// newDidWebValidatorSetup serves a DID document for did:web:example.com and
// returns a validator resolving against it plus a matching signed auth request JWT.
func newDidWebValidatorSetup(t *testing.T) (*DidVerifierValidator, string) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubJwk, err := jwxjwk.Import(privKey.Public())
	require.NoError(t, err)

	doc := did.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      testDidWeb,
		VerificationMethod: []did.VerificationMethod{
			{
				ID:           testDidWeb + "#key-1",
				Type:         did.VerificationMethodType_JsonWebKey2020,
				Controller:   testDidWeb,
				PublicKeyJwk: &pubJwk,
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/.well-known/did.json", r.URL.Path)
		w.Header().Set("Content-Type", "application/did+json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(server.Close)

	validator := NewDidVerifierValidator(false)
	validator.didWebResolver.HTTPClient = &http.Client{
		Transport: &didWebHostOverride{targetHost: server.Listener.Addr().String()},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, &AuthorizationRequest{
		ClientId: "decentralized_identifier:" + testDidWeb,
		Nonce:    "test-nonce",
	})
	token.Header["typ"] = AuthRequestJwtTyp
	token.Header["kid"] = testDidWeb + "#key-1"
	requestJwt, err := token.SignedString(privKey)
	require.NoError(t, err)

	return validator, requestJwt
}

func Test_DidWeb_WithoutDnssecVerifier_NoWarnings(t *testing.T) {
	validator, requestJwt := newDidWebValidatorSetup(t)

	request, _, _, warnings, err := validator.ParseAndVerifyAuthorizationRequest(requestJwt)
	require.NoError(t, err)
	require.Equal(t, "decentralized_identifier:"+testDidWeb, request.ClientId)
	require.Empty(t, warnings)
}

func Test_DidWeb_DnssecBogus_ReturnsInvalidWarningWithoutBlocking(t *testing.T) {
	validator, requestJwt := newDidWebValidatorSetup(t)
	verifier := &fakeDnssecVerifier{result: dnssec.Result{Status: dnssec.StatusBogus, Detail: "tampered"}}
	validator.SetDnssecVerifier(verifier)

	request, _, _, warnings, err := validator.ParseAndVerifyAuthorizationRequest(requestJwt)
	require.NoError(t, err)
	require.NotNil(t, request)
	require.Equal(t, []clientmodels.SessionWarning{clientmodels.SessionWarning_DidWebDnssecInvalid}, warnings)
	require.Equal(t, []string{"example.com"}, verifier.hosts)
}

func Test_DidWeb_DnssecInsecure_ReturnsMissingWarning(t *testing.T) {
	validator, requestJwt := newDidWebValidatorSetup(t)
	validator.SetDnssecVerifier(&fakeDnssecVerifier{result: dnssec.Result{Status: dnssec.StatusInsecure}})

	_, _, _, warnings, err := validator.ParseAndVerifyAuthorizationRequest(requestJwt)
	require.NoError(t, err)
	require.Equal(t, []clientmodels.SessionWarning{clientmodels.SessionWarning_DidWebDnssecMissing}, warnings)
}

func Test_DidWeb_DnssecSecure_NoWarnings(t *testing.T) {
	validator, requestJwt := newDidWebValidatorSetup(t)
	validator.SetDnssecVerifier(&fakeDnssecVerifier{result: dnssec.Result{Status: dnssec.StatusSecure}})

	_, _, _, warnings, err := validator.ParseAndVerifyAuthorizationRequest(requestJwt)
	require.NoError(t, err)
	require.Empty(t, warnings)
}

func Test_DidWeb_DnssecIndeterminate_NoWarnings(t *testing.T) {
	validator, requestJwt := newDidWebValidatorSetup(t)
	validator.SetDnssecVerifier(&fakeDnssecVerifier{result: dnssec.Result{Status: dnssec.StatusIndeterminate}})

	_, _, _, warnings, err := validator.ParseAndVerifyAuthorizationRequest(requestJwt)
	require.NoError(t, err)
	require.Empty(t, warnings)
}
