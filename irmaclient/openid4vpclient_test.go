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
	"github.com/stretchr/testify/require"
)

type testHandler struct {
	permissionChannel chan bool
}

func newTestHandler() *testHandler {
	return &testHandler{
		permissionChannel: make(chan bool, 1),
	}
}

func (h *testHandler) awaitPermissionRequest() {
	<-h.permissionChannel
}

func (h *testHandler) StatusUpdate(action irma.Action, status irma.ClientStatus)          {}
func (h *testHandler) ClientReturnURLSet(clientReturnURL string)                          {}
func (h *testHandler) PairingRequired(pairingCode string)                                 {}
func (h *testHandler) Success(result string)                                              {}
func (h *testHandler) Cancelled()                                                         {}
func (h *testHandler) Failure(err *irma.SessionError)                                     {}
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

func (h *testHandler) RequestVerificationPermission(request *irma.DisclosureRequest,
	satisfiable bool,
	candidates [][]DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback PermissionHandler) {

	jsoon, err := json.Marshal(candidates)
	if err != nil {
		fmt.Printf("failed to marshal: %v", err)
	} else {
		fmt.Printf("request verification permission: %v", string(jsoon))
	}

	h.permissionChannel <- true
}

func (h *testHandler) RequestSignaturePermission(request *irma.SignatureRequest,
	satisfiable bool,
	candidates [][]DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback PermissionHandler) {
}

func (h *testHandler) RequestPin(remainingAttempts int, callback PinHandler) {}

func TestOpenId4VpClient(t *testing.T) {
	storage, err := NewSdJwtVcStorage()
	require.NoError(t, err)

	client, err := NewOpenID4VPClient(storage, nil)
	require.NoError(t, err)

	url, err := GetAuthRequestUri()
	require.NoError(t, err)

	handler := newTestHandler()
	client.NewSession(url, handler)

	handler.awaitPermissionRequest()
}

const requestAuthorizationRequestRequest string = `
{
  "type": "vp_token",  
  "dcql_query": {
    "credentials": [
      {
        "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "format": "dc+sd-jwt",
        "meta": {
			"vct_values": ["pbdf.pbdf.email"]
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
			"vct_values": ["pbdf.pbdf.mobilenumber"]
        },
        "claims": [
          {
			"path": ["mobilenumber"]
          }
        ]
      }
    ],
    "credential_sets": [
      {
        "options": [
          [
            "32f54163-7166-48f1-93d8-ff217bdb0653"
          ]
        ],
        "purpose": "We need to verify your identity"
      }
    ]
  },
  "nonce": "nonce",
  "jar_mode": "by_reference",
  "request_uri_method": "post"
}
`

func GetAuthRequestUri() (string, error) {
	response, err := http.Post("http://0.0.0.0:8080/ui/presentations",
		"application/json",
		bytes.NewReader([]byte(requestAuthorizationRequestRequest)))

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
