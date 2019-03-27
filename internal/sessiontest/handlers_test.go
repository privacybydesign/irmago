package sessiontest

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

type TestClientHandler struct {
	t *testing.T
	c chan error
}

func (i *TestClientHandler) UpdateConfiguration(new *irma.IrmaIdentifierSet) {}
func (i *TestClientHandler) UpdateAttributes()                               {}
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
func (i *TestClientHandler) ChangePinSuccess(manager irma.SchemeManagerIdentifier) {
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

type TestHandler struct {
	t                  *testing.T
	c                  chan *SessionResult
	client             *irmaclient.Client
	expectedServerName irma.TranslatedString
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
func (th TestHandler) StatusUpdate(action irma.Action, status irma.Status) {}
func (th TestHandler) Success(result string) {
	th.c <- nil
}
func (th TestHandler) Cancelled() {
	th.Failure(&irma.SessionError{Err: errors.New("Cancelled")})
}
func (th TestHandler) Failure(err *irma.SessionError) {
	th.t.Logf("Session failed: %+v\n", *err)
	select {
	case th.c <- &SessionResult{Err: err}:
	default:
		th.t.Fatal(err)
	}
}
func (th TestHandler) UnsatisfiableRequest(serverName irma.TranslatedString, missing map[int]map[int]irma.AttributeCon) {
	th.Failure(&irma.SessionError{
		ErrorType: irma.ErrorType("UnsatisfiableRequest"),
	})
}
func (th TestHandler) RequestVerificationPermission(request *irma.DisclosureRequest, candidates [][][]*irma.AttributeIdentifier, ServerName irma.TranslatedString, callback irmaclient.PermissionHandler) {
	var choice irma.DisclosureChoice
	for _, cand := range candidates {
		choice.Attributes = append(choice.Attributes, cand[0])
	}
	if len(th.expectedServerName) != 0 {
		require.Equal(th.t, th.expectedServerName, ServerName)
	}
	callback(true, &choice)
}
func (th TestHandler) RequestIssuancePermission(request *irma.IssuanceRequest, candidates [][][]*irma.AttributeIdentifier, ServerName irma.TranslatedString, callback irmaclient.PermissionHandler) {
	th.RequestVerificationPermission(request.DisclosureRequest, candidates, ServerName, callback)
}
func (th TestHandler) RequestSignaturePermission(request *irma.SignatureRequest, candidates [][][]*irma.AttributeIdentifier, ServerName irma.TranslatedString, callback irmaclient.PermissionHandler) {
	th.RequestVerificationPermission(request.DisclosureRequest, candidates, ServerName, callback)
}
func (th TestHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	callback(true)
}
func (th TestHandler) RequestPin(remainingAttempts int, callback irmaclient.PinHandler) {
	callback(true, "12345")
}

type SessionResult struct {
	Err              error
	SignatureResult  *irma.SignedMessage
	DisclosureResult *irma.Disclosure
}

// ManualTestHandler embeds a TestHandler to inherit its methods.
// Below we overwrite the methods that require behaviour specific to manual settings.
type ManualTestHandler struct {
	TestHandler
	action irma.Action
}

func (th *ManualTestHandler) StatusUpdate(action irma.Action, status irma.Status) {
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
func (th *ManualTestHandler) RequestSignaturePermission(request *irma.SignatureRequest, candidates [][][]*irma.AttributeIdentifier, requesterName irma.TranslatedString, ph irmaclient.PermissionHandler) {
	th.RequestVerificationPermission(request.DisclosureRequest, candidates, requesterName, ph)
}
func (th *ManualTestHandler) RequestIssuancePermission(request *irma.IssuanceRequest, candidates [][][]*irma.AttributeIdentifier, issuerName irma.TranslatedString, ph irmaclient.PermissionHandler) {
	ph(true, nil)
}

// These handlers should not be called, fail test if they are called
func (th *ManualTestHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	th.Failure(&irma.SessionError{Err: errors.New("Unexpected session type")})
}
func (th *ManualTestHandler) RequestVerificationPermission(request *irma.DisclosureRequest, candidates [][][]*irma.AttributeIdentifier, verifierName irma.TranslatedString, ph irmaclient.PermissionHandler) {
	var choice irma.DisclosureChoice
	for _, cand := range candidates {
		choice.Attributes = append(choice.Attributes, cand[0])
	}
	ph(true, &choice)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
