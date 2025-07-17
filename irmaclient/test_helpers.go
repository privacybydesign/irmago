package irmaclient

import (
	"fmt"
	"testing"

	irma "github.com/privacybydesign/irmago"
)

type MockClientHandler struct {
	enrollmentChannel chan error
}

func NewMockClientHandler() *MockClientHandler {
	return &MockClientHandler{
		enrollmentChannel: make(chan error),
	}
}

func (h *MockClientHandler) AwaitEnrollmentResult() error {
	return <-h.enrollmentChannel
}

func (h *MockClientHandler) EnrollmentFailure(manager irma.SchemeManagerIdentifier, err error) {
	h.enrollmentChannel <- err
}

func (h *MockClientHandler) EnrollmentSuccess(manager irma.SchemeManagerIdentifier) {
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
func (h *MockClientHandler) ReportError(err error)                                              {}

// =============================================================================

type TestHandler struct {
	t                                  *testing.T
	permissionChannel                  chan bool
	disclosurePermissionRequestDetails *disclosurePermissionRequestDetails
	sessionEndChannel                  chan bool // true if successful
	pinRequestChannel                  chan PinHandler
	log                                bool
}

func NewTestHandler(t *testing.T) *TestHandler {
	return &TestHandler{
		t:                 t,
		permissionChannel: make(chan bool, 1),
		sessionEndChannel: make(chan bool, 1),
		pinRequestChannel: make(chan PinHandler, 1),
	}
}

func (h *TestHandler) AwaitPermissionRequest() {
	<-h.permissionChannel
}

func (h *TestHandler) AwaitSessionEnd() bool {
	return <-h.sessionEndChannel
}

func (h *TestHandler) ProceedIssuance() {
	if h.log {
		fmt.Printf("proceed issuance\n")
	}
	h.disclosurePermissionRequestDetails.callback(true, nil)
}

func (h *TestHandler) AwaitPinRequest() PinHandler {
	return <-h.pinRequestChannel
}

type disclosurePermissionRequestDetails struct {
	satisfiable   bool
	candidates    [][]DisclosureCandidates
	requestorInfo *irma.RequestorInfo
	callback      PermissionHandler
}

func (h *TestHandler) RequestVerificationPermission(request *irma.DisclosureRequest,
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

func (h *TestHandler) Success(result string) {
	if h.log {
		fmt.Printf("session success: %s\n", result)
	}
	h.sessionEndChannel <- true
}

func (h *TestHandler) Cancelled() {
	if h.log {
		fmt.Println("session cancelled")
	}
	h.sessionEndChannel <- false
}

func (h *TestHandler) Failure(err *irma.SessionError) {
	if h.log {
		fmt.Printf("session failed, err: %v\n\n", err.Error())
	}
	h.sessionEndChannel <- false
}

// Some boiler plate functions to satisfy the Handler interface
func (h *TestHandler) StatusUpdate(action irma.Action, status irma.ClientStatus) {
	if h.log {
		fmt.Printf("status update: %v, %v\n", action, status)
	}
}

func (h *TestHandler) RequestPin(remainingAttempts int, callback PinHandler) {
	if h.log {
		fmt.Printf("request pin, remaining attempts: %v\n", remainingAttempts)
	}
	h.pinRequestChannel <- callback
}

func (h *TestHandler) ClientReturnURLSet(clientReturnURL string) {}
func (h *TestHandler) PairingRequired(pairingCode string) {
	if h.log {
		fmt.Printf("pairing required: %v\n", pairingCode)
	}
}

func (h *TestHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	if h.log {
		fmt.Printf("keyshare blocked: %v, duration: %v\n", manager, duration)
	}
}

func (h *TestHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	if h.log {
		fmt.Printf("keyshare enrollment incomplete: %v\n", manager)
	}
}

func (h *TestHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	if h.log {
		fmt.Printf("keyshare enrollment missing: %v\n", manager)
	}
}

func (h *TestHandler) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	if h.log {
		fmt.Printf("keyshare enrollment deleted: %v\n", manager)
	}
}

func (h *TestHandler) RequestIssuancePermission(request *irma.IssuanceRequest,
	satisfiable bool,
	candidates [][]DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback PermissionHandler,
) {
	if h.log {
		fmt.Printf("candidates: %v, satisfiable: %v\n", candidates, satisfiable)
	}

	h.disclosurePermissionRequestDetails = &disclosurePermissionRequestDetails{
		satisfiable:   satisfiable,
		candidates:    candidates,
		requestorInfo: requestorInfo,
		callback:      callback,
	}

	h.permissionChannel <- true
}
func (h *TestHandler) RequestSignaturePermission(request *irma.SignatureRequest,
	satisfiable bool,
	candidates [][]DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback PermissionHandler) {
}
