package irmaclient

import (
	"fmt"

	"github.com/go-errors/errors"

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
	client = parseStorage(t)

	request := "{\"nonce\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"

	channel := make(chan *irma.SessionError)
	manualSessionHandler := ManualSessionHandler{t: t, c: channel}

	client.NewManualSession(request, &manualSessionHandler)

	teardown(t)

	if err := <-channel; err != nil {
		t.Fatal(*err)
	}
}

func TestManualKeyShareSession(t *testing.T) {
	client = parseStorage(t)

	keyshareRequest := "{\"nonce\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"test.test.mijnirma.email\"]}]}"

	channel := make(chan *irma.SessionError)
	manualSessionHandler := ManualSessionHandler{t: t, c: channel}

	client.NewManualSession(keyshareRequest, &manualSessionHandler)

	teardown(t)

	if err := <-channel; err != nil {
		t.Fatal(*err)
	}
}

func (sh *ManualSessionHandler) Success(irmaAction irma.Action, result string) {
	sh.c <- nil
}
func (sh *ManualSessionHandler) UnsatisfiableRequest(irmaAction irma.Action, serverName string, missingAttributes irma.AttributeDisjunctionList) {
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
func (sh *ManualSessionHandler) Cancelled(irmaAction irma.Action) {
	sh.c <- &irma.SessionError{Err: errors.New("Session was cancelled")}
}
func (sh *ManualSessionHandler) MissingKeyshareEnrollment(manager irma.SchemeManagerIdentifier) {
	sh.c <- &irma.SessionError{Err: errors.Errorf("Missing keyshare server %s", manager.String())}
}
func (sh *ManualSessionHandler) RequestIssuancePermission(request irma.IssuanceRequest, issuerName string, ph PermissionHandler) {
	sh.c <- &irma.SessionError{Err: errors.New("Unexpected session type")}
}
func (sh *ManualSessionHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	sh.c <- &irma.SessionError{Err: errors.New("Unexpected session type")}
}
func (sh *ManualSessionHandler) RequestVerificationPermission(request irma.DisclosureRequest, verifierName string, ph PermissionHandler) {
	sh.c <- &irma.SessionError{Err: errors.New("Unexpected session type")}
}
func (sh *ManualSessionHandler) Failure(irmaAction irma.Action, err *irma.SessionError) {
	fmt.Println(err.Err)
	sh.c <- err
}
