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

type MockClientHandler struct {
	enrollmentChannel chan error
	log               bool
}

func NewMockClientHandler() *MockClientHandler {
	return &MockClientHandler{
		enrollmentChannel: make(chan error),
		log:               false,
	}
}

func (h *MockClientHandler) AwaitEnrollmentResult() error {
	if h.log {
		fmt.Println("AwaitEnrollmentResult()")
	}
	return <-h.enrollmentChannel
}

func (h *MockClientHandler) EnrollmentFailure(manager irma.SchemeManagerIdentifier, err error) {
	if h.log {
		fmt.Println("EnrollmentFailure()")
	}
	h.enrollmentChannel <- err
}

func (h *MockClientHandler) EnrollmentSuccess(manager irma.SchemeManagerIdentifier) {
	if h.log {
		fmt.Println("EnrollmentSuccess()")
	}
	h.enrollmentChannel <- nil
}

func (h *MockClientHandler) ChangePinFailure(manager irma.SchemeManagerIdentifier, err error) {}
func (h *MockClientHandler) ChangePinSuccess()                                                {}
func (h *MockClientHandler) ChangePinIncorrect(manager irma.SchemeManagerIdentifier, attempts int) {
}
func (h *MockClientHandler) ChangePinBlocked(manager irma.SchemeManagerIdentifier, timeout int) {}
func (h *MockClientHandler) UpdateConfiguration(new *irma.IrmaIdentifierSet)                    {}
func (h *MockClientHandler) UpdateAttributes()                                                  {}
func (h *MockClientHandler) Revoked(cred *irma.CredentialIdentifier)                            {}
func (h *MockClientHandler) ReportError(err error) {
	if h.log {
		fmt.Printf("ReportError(): %v\n", err)
	}
}

// =============================================================================

type MockSessionHandler struct {
	t                 *testing.T
	permissionChannel chan *MockPermissionRequest
	sessionEndChannel chan bool // true if successful
	pinRequestChannel chan PinHandler
	log               bool
}

func NewMockSessionHandler(t *testing.T) *MockSessionHandler {
	return &MockSessionHandler{
		t:                 t,
		permissionChannel: make(chan *MockPermissionRequest, 1),
		sessionEndChannel: make(chan bool, 1),
		pinRequestChannel: make(chan PinHandler, 1),
		log:               false,
	}
}

func (h *MockSessionHandler) AwaitPermissionRequest() *MockPermissionRequest {
	return <-h.permissionChannel
}

func (h *MockSessionHandler) AwaitSessionEnd() bool {
	return <-h.sessionEndChannel
}

func (h *MockSessionHandler) AwaitPinRequest() PinHandler {
	return <-h.pinRequestChannel
}

type MockPermissionRequest struct {
	Satisfiable       bool
	Candidates        [][]DisclosureCandidates
	RequestorInfo     *irma.RequestorInfo
	PermissionHandler PermissionHandler
	SignedMessage     string
}

func (h *MockSessionHandler) RequestVerificationPermission(request *irma.DisclosureRequest,
	satisfiable bool,
	candidates [][]DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback PermissionHandler,
) {
	h.permissionChannel <- &MockPermissionRequest{
		Satisfiable:       satisfiable,
		Candidates:        candidates,
		RequestorInfo:     requestorInfo,
		PermissionHandler: callback,
	}
}

func (h *MockSessionHandler) Success(result string) {
	if h.log {
		fmt.Printf("session success: %s\n", result)
	}
	h.sessionEndChannel <- true
}

func (h *MockSessionHandler) Cancelled() {
	if h.log {
		fmt.Println("session cancelled")
	}
	h.sessionEndChannel <- false
}

func (h *MockSessionHandler) Failure(err *irma.SessionError) {
	if h.log {
		fmt.Printf("session failed, err: %v\n\n", err.Error())
	}
	h.sessionEndChannel <- false
}

// Some boiler plate functions to satisfy the Handler interface

func (h *MockSessionHandler) StatusUpdate(action irma.Action, status irma.ClientStatus) {
	if h.log {
		fmt.Printf("status update: %v, %v\n", action, status)
	}
}

func (h *MockSessionHandler) RequestPin(remainingAttempts int, callback PinHandler) {
	if h.log {
		fmt.Printf("request pin, remaining attempts: %v\n", remainingAttempts)
	}
	h.pinRequestChannel <- callback
}

func (h *MockSessionHandler) ClientReturnURLSet(clientReturnURL string) {}
func (h *MockSessionHandler) PairingRequired(pairingCode string) {
	if h.log {
		fmt.Printf("pairing required: %v\n", pairingCode)
	}
}

func (h *MockSessionHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	if h.log {
		fmt.Printf("keyshare blocked: %v, duration: %v\n", manager, duration)
	}
}

func (h *MockSessionHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	if h.log {
		fmt.Printf("keyshare enrollment incomplete: %v\n", manager)
	}
}

func (h *MockSessionHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	if h.log {
		fmt.Printf("keyshare enrollment missing: %v\n", manager)
	}
}

func (h *MockSessionHandler) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	if h.log {
		fmt.Printf("keyshare enrollment deleted: %v\n", manager)
	}
}

func (h *MockSessionHandler) RequestIssuancePermission(request *irma.IssuanceRequest,
	satisfiable bool,
	candidates [][]DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback PermissionHandler,
) {
	if h.log {
		candidatesJson, err := json.MarshalIndent(candidates, "", "    ")
		require.NoError(h.t, err)
		fmt.Printf("candidates: %v, satisfiable: %v\n", string(candidatesJson), satisfiable)
	}

	h.permissionChannel <- &MockPermissionRequest{
		Satisfiable:       satisfiable,
		Candidates:        candidates,
		RequestorInfo:     requestorInfo,
		PermissionHandler: callback,
	}
}
func (h *MockSessionHandler) RequestSignaturePermission(request *irma.SignatureRequest,
	satisfiable bool,
	candidates [][]DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback PermissionHandler) {
	if h.log {
		fmt.Printf("request signature permission: candidates: %v\n", candidates)
	}
	h.permissionChannel <- &MockPermissionRequest{
		Satisfiable:       satisfiable,
		Candidates:        candidates,
		RequestorInfo:     requestorInfo,
		PermissionHandler: callback,
		SignedMessage:     request.Message,
	}
}

func (h *MockSessionHandler) RequestAuthorizationCodeFlowIssuancePermission(request *irma.AuthorizationCodeIssuanceRequest, serverName *irma.RequestorInfo, callback PermissionHandler) {
	callback(false, nil)
}

func StartTestSessionAtEudiVerifier(openid4vpHost string, startSessionRequest string) (string, error) {
	apiUrl := fmt.Sprintf("%s/ui/presentations", openid4vpHost)
	response, err := http.Post(apiUrl,
		"application/json",
		bytes.NewReader([]byte(startSessionRequest)))

	if err != nil {
		return "", fmt.Errorf("failed to post session request to eudi verifier: %v", err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return "", fmt.Errorf("failed to read body of response from eudi verifier while starting session: %v", err)
	}

	var requestRequest map[string]string

	err = json.Unmarshal(body, &requestRequest)
	if err != nil {
		return "", fmt.Errorf("failed to parse request request body into json: %v (%v)", err, string(body))
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
