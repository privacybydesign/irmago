package sessiontest

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestClientHandler struct {
	t       *testing.T
	c       chan error
	revoked *irma.CredentialIdentifier
	storage string
}

func (i *TestClientHandler) UpdateConfiguration(new *irma.IrmaIdentifierSet) {}
func (i *TestClientHandler) UpdateAttributes()                               {}
func (i *TestClientHandler) Revoked(cred *irma.CredentialIdentifier) {
	i.revoked = cred
}
func (i *TestClientHandler) EnrollmentSuccess(manager irma.SchemeManagerIdentifier) {
	select {
	case i.c <- nil: // nop
	default: // nop
	}
}
func (i *TestClientHandler) EnrollmentFailure(manager irma.SchemeManagerIdentifier, err error) {
	select {
	case i.c <- err: // nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinSuccess() {
	select {
	case i.c <- nil: // nop
	default: // nop
	}
}
func (i *TestClientHandler) ChangePinFailure(manager irma.SchemeManagerIdentifier, err error) {
	select {
	case i.c <- err: //nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinIncorrect(manager irma.SchemeManagerIdentifier, attempts int) {
	err := errors.New("incorrect pin")
	select {
	case i.c <- err: //nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinBlocked(manager irma.SchemeManagerIdentifier, timeout int) {
	err := errors.New("blocked account")
	select {
	case i.c <- err: //nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ReportError(err error) {
	select {
	case i.c <- err: //nop
	default:
		i.t.Fatal(err)
	}
}

type TestHandler struct {
	t                  *testing.T
	c                  chan *SessionResult
	client             *irmaclient.Client
	expectedServerName *irma.RequestorInfo
	wait               time.Duration
	result             string
	pairingCodeChan    chan string
	clientTransport    *irma.HTTPTransport
	frontendTransport  *irma.HTTPTransport
}

func (th TestHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	th.Failure(&irma.SessionError{Err: errors.New("KeyshareEnrollmentIncomplete")})
}
func (th TestHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	th.Failure(&irma.SessionError{Err: errors.New("KeyshareBlocked")})
}
func (th TestHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	th.Failure(&irma.SessionError{Err: errors.Errorf("Missing keyshare server %s", manager.String())})
}
func (th TestHandler) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	th.Failure(&irma.SessionError{Err: errors.Errorf("Keyshare enrollment deleted for %s", manager.String())})
}
func (th TestHandler) StatusUpdate(action irma.Action, status irma.ClientStatus) {}
func (th *TestHandler) Success(result string) {
	th.result = result
	th.c <- nil
}
func (th TestHandler) Cancelled() {
	th.Failure(&irma.SessionError{Err: errors.New("Cancelled")})
}
func (th TestHandler) Failure(err *irma.SessionError) {
	select {
	case th.c <- &SessionResult{Err: err}:
	default:
		th.t.Fatal(err)
	}
}
func (th TestHandler) ClientReturnURLSet(clientReturnUrl string) {}
func (th TestHandler) RequestVerificationPermission(request *irma.DisclosureRequest, satisfiable bool, candidates [][]irmaclient.DisclosureCandidates, ServerName *irma.RequestorInfo, callback irmaclient.PermissionHandler) {
	if !satisfiable {
		th.Failure(&irma.SessionError{ErrorType: irma.ErrorType("UnsatisfiableRequest")})
		return
	}
	var choice irma.DisclosureChoice
	for _, cand := range candidates {
		var ids []*irma.AttributeIdentifier
		var err error
		for _, c := range cand {
			ids, err = c.Choose()
			if err == nil {
				break
			}
		}
		require.NoError(th.t, err)
		choice.Attributes = append(choice.Attributes, ids)
	}
	if th.expectedServerName != nil {
		assert.Equal(th.t, th.expectedServerName, ServerName)
	}
	if th.wait != 0 {
		time.Sleep(th.wait)
	}
	callback(true, &choice)
}
func (th TestHandler) RequestIssuancePermission(request *irma.IssuanceRequest, satisfiable bool, candidates [][]irmaclient.DisclosureCandidates, ServerName *irma.RequestorInfo, callback irmaclient.PermissionHandler) {
	th.RequestVerificationPermission(&request.DisclosureRequest, satisfiable, candidates, ServerName, callback)
}
func (th TestHandler) RequestSignaturePermission(request *irma.SignatureRequest, satisfiable bool, candidates [][]irmaclient.DisclosureCandidates, ServerName *irma.RequestorInfo, callback irmaclient.PermissionHandler) {
	th.RequestVerificationPermission(&request.DisclosureRequest, satisfiable, candidates, ServerName, callback)
}
func (th TestHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	callback(true)
}
func (th TestHandler) RequestPin(remainingAttempts int, callback irmaclient.PinHandler) {
	callback(true, "12345")
}
func (th TestHandler) PairingRequired(pairingCode string) {
	// Send pairing code via channel to calling test. This is done such that
	// calling tests can detect it when this handler is skipped unexpectedly.
	if th.pairingCodeChan != nil {
		th.pairingCodeChan <- pairingCode
		return
	}
	th.Failure(&irma.SessionError{ErrorType: irma.ErrorType("Pairing required")})
}

func (th *TestHandler) SetClientTransport(transport *irma.HTTPTransport) {
	th.clientTransport = transport
}

type SessionResult struct {
	Err              error
	SignatureResult  *irma.SignedMessage
	DisclosureResult *irma.Disclosure
	Missing          [][]irmaclient.DisclosureCandidates
}

// UnsatisfiableTestHandler is a session handler that expects RequestVerificationPermission
// to be called for an unsatisfiable session. If called a second time, it checks
// that the session has beome satifsiable and finishes it.
type UnsatisfiableTestHandler struct {
	TestHandler
	called bool
}

func (th *UnsatisfiableTestHandler) Success(result string) {
	if !th.called {
		th.Failure(&irma.SessionError{ErrorType: irma.ErrorType("Unsatisfiable request succeeded early")})
	} else {
		th.c <- nil
	}
}

func (th *UnsatisfiableTestHandler) RequestVerificationPermission(request *irma.DisclosureRequest, satisfiable bool, candidates [][]irmaclient.DisclosureCandidates, ServerName *irma.RequestorInfo, callback irmaclient.PermissionHandler) {
	if !th.called {
		if satisfiable {
			th.Failure(&irma.SessionError{ErrorType: irma.ErrorType("Unsatisfiable request succeeded")})
			return
		}
		th.called = true
		th.c <- &SessionResult{Missing: candidates}
	} else {
		th.TestHandler.RequestVerificationPermission(request, satisfiable, candidates, ServerName, callback)
	}
}

// Override TestHandler.Cancelled() so we can cancel future RequestVerificationPermission() invocations
func (th *UnsatisfiableTestHandler) Cancelled() {}

// ManualTestHandler embeds a TestHandler to inherit its methods.
// Below we overwrite the methods that require behaviour specific to manual settings.
type ManualTestHandler struct {
	TestHandler
	action irma.Action
}

func (th *ManualTestHandler) StatusUpdate(action irma.Action, status irma.ClientStatus) {
	th.action = action
}

func (th *ManualTestHandler) Success(result string) {
	if len(result) == 0 {
		th.c <- nil
		return
	}

	var err error
	retval := &SessionResult{}
	switch th.action {
	case irma.ActionSigning:
		retval.SignatureResult = &irma.SignedMessage{}
		err = json.Unmarshal([]byte(result), retval.SignatureResult)
	case irma.ActionDisclosing:
		retval.DisclosureResult = &irma.Disclosure{}
		err = json.Unmarshal([]byte(result), retval.DisclosureResult)
	}
	if err != nil {
		th.Failure(&irma.SessionError{
			Err:       err,
			ErrorType: irma.ErrorSerialization,
		})
		return
	}

	th.c <- retval
}
func (th *ManualTestHandler) RequestSignaturePermission(request *irma.SignatureRequest, satisfiable bool, candidates [][]irmaclient.DisclosureCandidates, requesterName *irma.RequestorInfo, ph irmaclient.PermissionHandler) {
	th.RequestVerificationPermission(&request.DisclosureRequest, satisfiable, candidates, requesterName, ph)
}
func (th *ManualTestHandler) RequestIssuancePermission(request *irma.IssuanceRequest, satisfiable bool, candidates [][]irmaclient.DisclosureCandidates, issuerName *irma.RequestorInfo, ph irmaclient.PermissionHandler) {
	ph(true, nil)
}

// These handlers should not be called, fail test if they are called
func (th *ManualTestHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	th.Failure(&irma.SessionError{Err: errors.New("Unexpected session type")})
}
func (th *ManualTestHandler) RequestVerificationPermission(request *irma.DisclosureRequest, satisfiable bool, candidates [][]irmaclient.DisclosureCandidates, verifierName *irma.RequestorInfo, ph irmaclient.PermissionHandler) {
	if !satisfiable {
		th.Failure(&irma.SessionError{ErrorType: irma.ErrorType("UnsatisfiableRequest")})
		return
	}
	var choice irma.DisclosureChoice
	for _, cand := range candidates {
		var ids []*irma.AttributeIdentifier
		var err error
		for _, c := range cand {
			ids, err = c.Choose()
			if err == nil {
				break
			}
		}
		require.NoError(th.t, err)
		choice.Attributes = append(choice.Attributes, ids)
	}
	ph(true, &choice)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
