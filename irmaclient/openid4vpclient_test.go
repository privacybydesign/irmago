package irmaclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

type testHandler struct {
	t                                  *testing.T
	permissionChannel                  chan bool
	disclosurePermissionRequestDetails *disclosurePermissionRequestDetails
	sessionEndChannel                  chan bool // true if successful
}

func newTestHandler(t *testing.T) *testHandler {
	return &testHandler{
		t:                 t,
		permissionChannel: make(chan bool, 1),
		sessionEndChannel: make(chan bool, 1),
	}
}

func (h *testHandler) awaitPermissionRequest() {
	<-h.permissionChannel
}

func (h *testHandler) awaitSessionEnd() bool {
	return <-h.sessionEndChannel
}

type disclosurePermissionRequestDetails struct {
	satisfiable   bool
	candidates    [][]DisclosureCandidates
	requestorInfo *irma.RequestorInfo
	callback      PermissionHandler
}

func (h *testHandler) RequestVerificationPermission(request *irma.DisclosureRequest,
	satisfiable bool,
	candidates [][]DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback PermissionHandler,
) {
	h.disclosurePermissionRequestDetails = &disclosurePermissionRequestDetails{
		satisfiable:   satisfiable,
		candidates:    candidates,
		requestorInfo: requestorInfo,
		callback:      callback,
	}

	h.permissionChannel <- true
}

func (h *testHandler) Success(result string) {
	h.sessionEndChannel <- true
}

func (h *testHandler) Cancelled() {
	h.sessionEndChannel <- false
}

func (h *testHandler) Failure(err *irma.SessionError) {
	fmt.Printf("\n\nerr: %v\n\n", err.Error())
	h.sessionEndChannel <- false
}

func createOpenID4VPClientForTesting(t *testing.T) *OpenID4VPClient {
	keyBinder := sdjwtvc.NewDefaultKeyBinder()
	storage, err := NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	addTestCredentialsToStorage(storage, keyBinder)
	verifierValidator := NewRequestorSchemeVerifierValidator()
	client, err := NewOpenID4VPClient(storage, verifierValidator, keyBinder)
	require.NoError(t, err)
	return client
}

func TestOpenID4VPClient(t *testing.T) {
	t.Run("disclosing two credentials successfully", testDisclosingTwoCredentials_Success)
}

func testDisclosingTwoCredentials_Success(t *testing.T) {
	url, err := startSessionAtEudiVerifier()
	require.NoError(t, err)

	client := createOpenID4VPClientForTesting(t)

	handler := newTestHandler(t)
	client.NewSession(url, handler)

	handler.awaitPermissionRequest()

	choice := &irma.DisclosureChoice{
		Attributes: [][]*irma.AttributeIdentifier{
			{
				&irma.AttributeIdentifier{
					Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
					CredentialHash: "2gLLz0ZpYXXW6-I1jZ3wBEggQ5eR7KKbdIvJLm5O8y8",
				},
			},
			{
				&irma.AttributeIdentifier{
					Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.mobilenumber.mobilenumber"),
					CredentialHash: "igACXd9kCRN7ypJ8iUS2c3UQ62S-Opjz0LCariGhQ_w",
				},
			},
		},
	}
	proceed := true
	handler.disclosurePermissionRequestDetails.callback(proceed, choice)
	success := handler.awaitSessionEnd()

	require.True(t, success)
}

func createAuthorizationRequestRequest() string {
	return fmt.Sprintf(`
{
  "type": "vp_token",  
  "dcql_query": {
    "credentials": [
      {
        "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "format": "dc+sd-jwt",
        "meta": {
			"vct_values": ["pbdf.sidn-pbdf.email"]
        },
        "claims": [
          {
			"path": ["email"]
          }
        ]
      },
      {
        "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
        "format": "dc+sd-jwt",
        "meta": {
			"vct_values": ["pbdf.sidn-pbdf.mobilenumber"]
        },
        "claims": [
          {
			"path": ["mobilenumber"]
          }
        ]
      }
    ]
  },
  "nonce": "nonce",
  "jar_mode": "by_reference",
  "request_uri_method": "post",
  "issuer_chain": "%s"
}
`,
		string(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
	)
}

func startSessionAtEudiVerifier() (string, error) {
	response, err := http.Post("http://127.0.0.1:8089/ui/presentations",
		"application/json",
		bytes.NewReader([]byte(createAuthorizationRequestRequest())))

	if err != nil {
		return "", err
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return "", err
	}

	var requestRequest map[string]string

	err = json.Unmarshal(body, &requestRequest)
	if err != nil {
		return "", err
	}

	queryParams := url.Values{}

	for key, value := range requestRequest {
		queryParams.Add(key, value)
	}

	url := url.URL{
		Scheme:   "eudi-openid4vp://",
		RawQuery: queryParams.Encode(),
	}

	return url.String(), nil
}

// Some boiler plate functions to satisfy the Handler interface
func (h *testHandler) StatusUpdate(action irma.Action, status irma.ClientStatus)          {}
func (h *testHandler) RequestPin(remainingAttempts int, callback PinHandler)              {}
func (h *testHandler) ClientReturnURLSet(clientReturnURL string)                          {}
func (h *testHandler) PairingRequired(pairingCode string)                                 {}
func (h *testHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {}
func (h *testHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier)  {}
func (h *testHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier)     {}
func (h *testHandler) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier)     {}
func (h *testHandler) RequestIssuancePermission(request *irma.IssuanceRequest,
	satisfiable bool,
	candidates [][]DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback PermissionHandler) {
}
func (h *testHandler) RequestSignaturePermission(request *irma.SignatureRequest,
	satisfiable bool,
	candidates [][]DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback PermissionHandler) {
}
