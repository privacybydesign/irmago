package irmaclient

import (
	"fmt"
	"testing"

	"github.com/privacybydesign/irmago"
)

type ManualSessionHandler struct {
	permissionHandler PermissionHandler
	pinHandler        PinHandler
	t                 *testing.T
	c                 chan *irma.SessionError
}

var client *Client

func TestManualSession(t *testing.T) {
	request := "{\"nonce\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"

	channel := make(chan *irma.SessionError)
	manualSessionHandler := ManualSessionHandler{t: t, c: channel}

	client = parseStorage(t)
	TestAndroidParse(t)

	client.NewManualSession(request, &manualSessionHandler)

	teardown(t)

	if err := <-channel; err != nil {
		t.Fatal(*err)
	}
}

func TestManualKeyShareSession(t *testing.T) {
	keyshareRequest := "{\"nonce\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"test.test.mijnirma.email\"]}]}"

	channel := make(chan *irma.SessionError)
	manualSessionHandler := ManualSessionHandler{t: t, c: channel}

	client = parseStorage(t)
	TestAndroidParse(t)

	client.NewManualSession(keyshareRequest, &manualSessionHandler)

	teardown(t)

	if err := <-channel; err != nil {
		t.Fatal(*err)
	}
}

func (sh *ManualSessionHandler) Success(irmaAction irma.Action, result string) {
	sh.c <- nil
}
func (sh *ManualSessionHandler) UnsatisfiableRequest(irmaAction irma.Action, missingAttributes irma.AttributeDisjunctionList) {
	sh.t.Fail()
}

// Done in irma bridge?
func (sh *ManualSessionHandler) StatusUpdate(irmaAction irma.Action, status irma.Status) {}
func (sh *ManualSessionHandler) RequestPin(remainingAttempts int, ph PinHandler) {
	ph(true, "12345")
}
func (sh *ManualSessionHandler) RequestSignaturePermission(request irma.SignatureRequest, requesterName string, ph PermissionHandler) {
	c := irma.DisclosureChoice{request.Candidates[0]}
	ph(true, &c)
}

// These handlers should not be called, fail test if they are called
func (sh *ManualSessionHandler) Cancelled(irmaAction irma.Action) { sh.t.Fail() }
func (sh *ManualSessionHandler) MissingKeyshareEnrollment(manager irma.SchemeManagerIdentifier) {
	sh.t.Fail()
}
func (sh *ManualSessionHandler) RequestIssuancePermission(request irma.IssuanceRequest, issuerName string, ph PermissionHandler) {
	sh.t.Fail()
}
func (sh *ManualSessionHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	sh.t.Fail()
}
func (sh *ManualSessionHandler) RequestVerificationPermission(request irma.DisclosureRequest, verifierName string, ph PermissionHandler) {
	sh.t.Fail()
}
func (sh *ManualSessionHandler) Failure(irmaAction irma.Action, err *irma.SessionError) {
	fmt.Println(err.Err)
	sh.t.Fail()
}
func (sh *ManualSessionHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	sh.Failure(irma.ActionUnknown, &irma.SessionError{ErrorType: irma.ErrorKeyshareBlocked})
}
func (sh *ManualSessionHandler) KeyshareRegistrationIncomplete(manager irma.SchemeManagerIdentifier) {
	sh.c <- &irma.SessionError{Err: errors.New("KeyshareRegistrationIncomplete")}
}
