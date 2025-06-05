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
	jwtCreator, err := sdjwtvc.NewDefaultEcdsaJwtCreatorWithHolderPrivateKey()
	require.NoError(t, err)

	kbjwtCreator := &sdjwtvc.DefaultKbJwtCreator{
		Clock:      sdjwtvc.NewSystemClock(),
		JwtCreator: jwtCreator,
	}
	storage, err := NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	client, err := NewOpenID4VPClient(storage, kbjwtCreator)
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
					CredentialHash: "kwlv0iugBeRMl9h5KBVatl4o5YWfu8lje6c9I90yFkI",
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

const requestAuthorizationRequestRequest string = `
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
  "issuer_chain": "-----BEGIN CERTIFICATE-----\nMIICIjCCAcigAwIBAgIUTcLOP9EE/e/TCb2cTG0tFfzL8+4wCgYIKoZIzj0EAwIw\nQTELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxIzAhBgNVBAMMGm9wZW5pZDR2\nYy5zdGFnaW5nLnlpdmkuYXBwMB4XDTI1MDYwMjEzMDQxOFoXDTM1MDUzMTEzMDQx\nOFowQTELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxIzAhBgNVBAMMGm9wZW5p\nZDR2Yy5zdGFnaW5nLnlpdmkuYXBwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\nSr7bMrDTDe+R/HI1wywYtEYr+DJa5HdTnI8dsjZer6grPyZ4vxTeOmdjU9wp0Wkz\nfONmyk8xsPePon4AhwCK+aOBnTCBmjAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIF\noDATBgNVHSUEDDAKBggrgQICAAABBzBJBgNVHREEQjBAhiJodHRwczovL29wZW5p\nZDR2Yy5zdGFnaW5nLnlpdmkuYXBwghpvcGVuaWQ0dmMuc3RhZ2luZy55aXZpLmFw\ncDAdBgNVHQ4EFgQUNFp/ITlrNmraTYMsN3jijYUmLXswCgYIKoZIzj0EAwIDSAAw\nRQIgfOmEnTey2tleATASaE7iH22VFy3b1rrYGNhZkUNOLK4CIQD4pNqgAyvOsAMd\nkfM3veqe+fFWKPdlX4Nzj9QMGcXuBQ==\n-----END CERTIFICATE-----"
}
`

func startSessionAtEudiVerifier() (string, error) {
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
