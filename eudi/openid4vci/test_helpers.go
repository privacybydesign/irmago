package openid4vci

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// authCodeRequest bundles the callback with the state the grant handler generated for the
// session, so tests can echo the correct state back (or deliberately echo a wrong one).
type authCodeRequest struct {
	callback AuthCodeHandler
	state    string
}

type MockSessionHandler struct {
	t                             *testing.T
	sessionEndChannel             chan bool // true if successful
	authCodeRequestChannel        chan authCodeRequest
	tokenRequestChannel           chan TokenHandler
	tokenPermissionRequestChannel chan TokenPermissionHandler
	permissionRequestChannel      chan PermissionHandler
	log                           bool
}

func newMockSessionHandler(t *testing.T) *MockSessionHandler {
	return &MockSessionHandler{
		t:                             t,
		sessionEndChannel:             make(chan bool, 1),
		authCodeRequestChannel:        make(chan authCodeRequest, 1),
		tokenRequestChannel:           make(chan TokenHandler, 1),
		tokenPermissionRequestChannel: make(chan TokenPermissionHandler, 1),
		permissionRequestChannel:      make(chan PermissionHandler, 1),
		log:                           false,
	}
}

func (h *MockSessionHandler) AwaitSessionEnd() bool {
	return <-h.sessionEndChannel
}

func (h *MockSessionHandler) AwaitAuthCodeRequest() authCodeRequest {
	return <-h.authCodeRequestChannel
}

func (h *MockSessionHandler) Success(result string, issuedCredentials []*clientmodels.Credential) {
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

func (h *MockSessionHandler) Failure(err *clientmodels.SessionError) {
	if h.log {
		fmt.Printf("session failed, err: %v\n\n", err.WrappedError)
	}
	h.sessionEndChannel <- false
}

func (h *MockSessionHandler) RequestAuthorizationCodeFlowPermission(request *clientmodels.AuthorizationCodeFlowRequest,
	requestorInfo *clientmodels.TrustedParty,
	callback AuthCodeHandler,
) {
	if h.log {
		issuanceRequestJson, err := json.MarshalIndent(request, "", "    ")
		require.NoError(h.t, err)
		fmt.Printf("OpenID4VCIIssuanceRequest: %v\n", string(issuanceRequestJson))
	}

	h.authCodeRequestChannel <- authCodeRequest{callback: callback, state: request.OpenID4VCIState}
}

func (h *MockSessionHandler) RequestPreAuthorizedCodeFlowPermission(
	request *clientmodels.PreAuthorizedCodeFlowPermissionRequest,
	requestorInfo *clientmodels.TrustedParty,
	callback TokenPermissionHandler,
) {
	if h.log {
		fmt.Printf("OpenID4VCIPreAuthorizedCodeTokenRequest")
	}

	h.tokenPermissionRequestChannel <- callback
}

func (h *MockSessionHandler) RequestPermission(
	offeredCredentials []*clientmodels.Credential,
	requestorInfo *clientmodels.TrustedParty,
	callback PermissionHandler,
) {
	if h.log {
		fmt.Printf("RequestPermission: %d offered credentials\n", len(offeredCredentials))
	}

	h.permissionRequestChannel <- callback
}
