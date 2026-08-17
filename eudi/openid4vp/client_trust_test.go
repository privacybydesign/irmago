package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// The tests below drive a whole OpenID4VP session — an authorization request
// served over HTTP, verified, and carried up to the permission screen — and
// assert the rung the wallet puts the verifier on, plus that a rejected
// verifier is reported as such.

// serveAuthRequest publishes an authorization request JWT and returns the
// openid4vp URL a wallet would be handed for it.
func serveAuthRequest(t *testing.T, authRequestJwt string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, authRequestJwt)
	}))
	t.Cleanup(server.Close)
	return "openid4vp://?request_uri=" + url.QueryEscape(server.URL)
}

// newTrustTestClient builds a client that runs sessions against the given
// verifier validator, ranking parties the way the wallet does today.
func newTrustTestClient(validator VerifierValidator) *Client {
	return newTrustTestClientWithLists(validator, nil)
}

// staticClassifier confers one fixed level on every certificate. High mirrors
// production today: the gate only passes chains under the Yivi anchors, and
// those confer high.
type staticClassifier clientmodels.TrustLevel

func (s staticClassifier) Classify(*x509.Certificate) clientmodels.TrustLevel {
	return clientmodels.TrustLevel(s)
}

// newTrustTestClientWithLists is newTrustTestClient with the recognized-list
// channel wired up to checker.
func newTrustTestClientWithLists(validator VerifierValidator, checker *lote.Checker) *Client {
	trustService := services.NewTrustService(checker,
		staticClassifier(clientmodels.TrustLevel_High),
		staticClassifier(clientmodels.TrustLevel_High))
	client, _ := NewClient(nil, []dcql.DcqlCredentialQueryHandler{stubQueryHandler{}}, validator, nil, trustService)
	return client
}

// stubQueryHandler answers every query with one credential the wallet does not
// own. That is enough to build a disclosure plan and reach the permission
// screen, which is where the verifier's rung shows up, without dragging a
// credential store into the test.
type stubQueryHandler struct{}

func (stubQueryHandler) CanHandleCredentialQuery(dcql.CredentialQuery) bool { return true }

func (stubQueryHandler) FindCandidates(dcql.CredentialQuery) (*dcql.CredentialQueryResult, error) {
	return &dcql.CredentialQueryResult{
		ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{
			CredentialId: "https://example.com/vct/email",
			Name:         "Email",
		}},
	}, nil
}

func (stubQueryHandler) PrepareDisclosure([]dcql.DisclosureSelection, string, string) (*dcql.PreparedDisclosure, error) {
	return nil, fmt.Errorf("the stub handler owns nothing to disclose")
}

// withClientName makes the requestor's display name come from client_metadata,
// which keeps the certificate's own scheme data (and its logo, which would need
// a storage-backed configuration to cache) out of the session.
func withClientName(name string) func(token *jwt.Token) {
	return func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{"client_name": name}
	}
}

func TestNewSession_X509Verifier_RanksHigh(t *testing.T) {
	authRequestJwt, validator := setupTest(t, withClientName("Test Verifier"), testdata.PkiOption_None)

	client := newTrustTestClient(validator)
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	requestor := handler.awaitRequestor(t)
	require.Equal(t, clientmodels.TrustLevel_High, requestor.TrustLevel,
		"a verifier whose chain validates against the Yivi anchors is vouched for by Yivi")
	require.True(t, requestor.TrustLevel.IsTrusted())
}

func TestNewSession_DidWebVerifier_RanksLowAndProceeds(t *testing.T) {
	authRequestJwt, validator, _ := setupDidWebTest(t)

	client := newTrustTestClient(validator)
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	// The session reaching the permission screen at all is the fail-soft
	// assertion: nobody vouches for a bare DID, and it still gets to ask.
	requestor := handler.awaitRequestor(t)
	require.Equal(t, clientmodels.TrustLevel_Low, requestor.TrustLevel,
		"nobody vouches for a bare did:web verifier")
	require.False(t, requestor.TrustLevel.IsTrusted())
	require.Equal(t, int32(0), handler.cancels.Load())
}

func TestNewSession_ExpiredVerifierCertificate_ReportsPartyValidationFailed(t *testing.T) {
	// A certificate presented outside its own validity window is a broken
	// request — the gate rejects it, and the app must be able to say the
	// verifier was rejected rather than that the network misbehaved.
	authRequestJwt, validator := setupTest(t, withClientName("Test Verifier"), testdata.PkiOption_ExpiredEndEntity)

	client := newTrustTestClient(validator)
	handler := newSpyHandler()

	client.NewSession(serveAuthRequest(t, authRequestJwt), handler)

	err := handler.awaitFailure(t)
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, err.ErrorType,
		"a rejected verifier must be distinguishable from a network or protocol error")
	require.Equal(t, int32(0), handler.requests.Load(), "nothing may be asked of the user")
	require.Equal(t, int32(0), handler.successes.Load(), "nothing may be disclosed")
}

func TestNewSession_RevokedVerifierCertificate_ReportsPartyValidationFailed(t *testing.T) {
	// Revocation is the CA withdrawing a certificate it issued — an act of
	// distrust, not the absence of trust an untraceable chain shows — and it is
	// how a compromised relying party is cut off. So the session is refused
	// rather than shown at a lower rung, and the app can say the verifier was
	// rejected. (The classifier stub confers high on every certificate here, so
	// nothing but the refusal keeps this request off the screen.)
	authRequestJwt, validator := setupTest(t, withClientName("Test Verifier"), testdata.PkiOption_RevokedEndEntity)

	client := newTrustTestClient(validator)
	handler := newSpyHandler()

	client.NewSession(serveAuthRequest(t, authRequestJwt), handler)

	err := handler.awaitFailure(t)
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, err.ErrorType,
		"a rejected verifier must be distinguishable from a network or protocol error")
	require.Equal(t, int32(0), handler.requests.Load(), "nothing may be asked of the user")
	require.Equal(t, int32(0), handler.successes.Load(), "nothing may be disclosed")
}

func TestNewSession_GenericFailures_CarryNoPartyValidationCode(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newTestClient()
		handler := newSpyHandler()

		client.NewSession("openid4vp://?request_uri="+url.QueryEscape(server.URL), handler)

		require.Empty(t, handler.awaitFailure(t).ErrorType)
	})

	t.Run("protocol", func(t *testing.T) {
		client := newTestClient()
		handler := newSpyHandler()

		client.NewSession("openid4vp://", handler)

		require.Empty(t, handler.awaitFailure(t).ErrorType)
	})
}

// setupDidWebTest publishes a DID document for a loopback did:web verifier and
// returns an authorization request signed with the key in that document, plus
// the verifier's DID — what a trust list would name it by. The verifier has no
// certificate at all: it is the bare-DID case.
func setupDidWebTest(t *testing.T) (authRequestJwt string, validator VerifierValidator, did string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicKey, err := jwk.Import(key.Public())
	require.NoError(t, err)

	// The DID document is served over plain HTTP, which only the developer-mode
	// resolver accepts; the DID names the loopback host and port, percent-encoded
	// as the did:web spec requires.
	var didWeb string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"@context": []string{"https://www.w3.org/ns/did/v1"},
			"id":       didWeb,
			"verificationMethod": []any{map[string]any{
				"id":           didWeb + "#key-1",
				"type":         "JsonWebKey2020",
				"controller":   didWeb,
				"publicKeyJwk": publicKey,
			}},
		}))
	}))
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	// The port separator is percent-encoded; a literal ":" would be read as a
	// path separator.
	didWeb = "did:web:" + strings.ReplaceAll(serverURL.Host, ":", "%3A")

	authRequestJwt = testdata.CreateTestAuthorizationRequestJWTWithClientId(
		"decentralized_identifier:"+didWeb, key, &x509.Certificate{},
		func(token *jwt.Token) { delete(token.Header, "x5c") },
	)
	return authRequestJwt, NewDidVerifierValidator(true), didWeb
}
