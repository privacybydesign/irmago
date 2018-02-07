package irmaclient

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
)

type ManualSessionHandler struct {
	permissionHandler PermissionHandler
	pinHandler        PinHandler
	t                 *testing.T
	c                 chan *irma.SessionError
	sigRequest        *irma.SignatureRequest
}

var client *Client

// Issue BSN credential using sessionHelper
func issue(t *testing.T, ms ManualSessionHandler) {
	name := "testip"

	jwtcontents := getIssuanceJwt(name)
	sessionHandlerHelper(t, jwtcontents, "issue", client, &ms)
}

// Flip one bit in the proof string if invalidate is set to true
var invalidate bool

func corruptProofString(proof string) string {
	if invalidate {
		proofBytes := []byte(proof)

		flipLoc := 15
		if proofBytes[flipLoc] == 0x33 {
			proofBytes[flipLoc] = 0x32
		} else {
			proofBytes[flipLoc] = 0x33
		}
		return string(proofBytes)
	}
	return proof
}

func TestManualSession(t *testing.T) {
	invalidate = false
	channel := make(chan *irma.SessionError)
	client = parseStorage(t)

	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	sigRequestJSON := []byte(request)
	sigRequest := &irma.SignatureRequest{}
	json.Unmarshal(sigRequestJSON, sigRequest)

	ms := ManualSessionHandler{
		t:          t,
		c:          channel,
		sigRequest: sigRequest,
	}

	client.NewManualSession(request, &ms)

	if err := <-channel; err != nil {
	  test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	test.ClearTestStorage(t)
}

func TestManualKeyShareSession(t *testing.T) {
	invalidate = false
	channel := make(chan *irma.SessionError)

	keyshareRequestString := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"test.test.mijnirma.email\"]}]}"
	keyshareRequestJSON := []byte(keyshareRequestString)
	keyshareRequest := &irma.SignatureRequest{}
	json.Unmarshal(keyshareRequestJSON, keyshareRequest)

	manualSessionHandler := ManualSessionHandler{
		t:          t,
		c:          channel,
		sigRequest: keyshareRequest,
	}

	client = parseStorage(t)

	client.NewManualSession(keyshareRequestString, &manualSessionHandler)

	if err := <-channel; err != nil {
	  test.ClearTestStorage(t)
		t.Fatal(*err)
	}
	test.ClearTestStorage(t)
}

func TestManualSessionMultiProof(t *testing.T) {
	invalidate = false
	client = parseStorage(t)

	// First, we need to issue an extra credential (BSN)
	is := ManualSessionHandler{t: t, c: make(chan *irma.SessionError)}
	go issue(t, is)
	if err := <-is.c; err != nil {
		fmt.Println("Error during initial issueing!")
		t.Fatal(*err)
	}

	// Request to sign with both BSN and StudentID
	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]},{\"label\":\"BSN\",\"attributes\":[\"irma-demo.MijnOverheid.root.BSN\"]}]}"

	channel := make(chan *irma.SessionError)
	sigRequestJSON := []byte(request)
	sigRequest := &irma.SignatureRequest{}
	json.Unmarshal(sigRequestJSON, sigRequest)

	ms := ManualSessionHandler{
		t:          t,
		c:          channel,
		sigRequest: sigRequest,
	}

	client.NewManualSession(request, &ms)

	if err := <-channel; err != nil {
	  test.ClearTestStorage(t)
		t.Fatal(*err)
	}
	test.ClearTestStorage(t)
}

func TestManualSessionInvalidProof(t *testing.T) {
	invalidate = true
	channel := make(chan *irma.SessionError)
	client = parseStorage(t)

	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	sigRequestJSON := []byte(request)
	sigRequest := &irma.SignatureRequest{}
	json.Unmarshal(sigRequestJSON, sigRequest)

	ms := ManualSessionHandler{
		t:          t,
		c:          channel,
		sigRequest: sigRequest,
	}

	client.NewManualSession(request, &ms)

	if err := <-channel; err.ErrorType != "Proof does not verify" {
    test.ClearTestStorage(t)
		t.Fatal(*err)
	}
	test.ClearTestStorage(t)
}

func (sh *ManualSessionHandler) Success(irmaAction irma.Action, result string) {
	switch irmaAction {
	case irma.ActionSigning:
		// Make proof corrupt if we want to test invalid proofs
		result = corruptProofString(result)

		if !verifySig(client, result, sh.sigRequest) {
			sh.c <- &irma.SessionError{
				ErrorType: irma.ErrorType("Proof does not verify"),
			}
			return
		}
	}
	sh.c <- nil
}
func (sh *ManualSessionHandler) UnsatisfiableRequest(irmaAction irma.Action, missingAttributes irma.AttributeDisjunctionList) {
	// This function is called from main thread, which blocks go channel, so need go routine here
	go func() {
		sh.c <- &irma.SessionError{
			ErrorType: irma.ErrorType("UnsatisfiableRequest"),
		}
	}()
}

func (sh *ManualSessionHandler) StatusUpdate(irmaAction irma.Action, status irma.Status) {}

func (sh *ManualSessionHandler) RequestPin(remainingAttempts int, ph PinHandler) {
	ph(true, "12345")
}
func (sh *ManualSessionHandler) RequestSignaturePermission(request irma.SignatureRequest, requesterName string, ph PermissionHandler) {
	var attributes []*irma.AttributeIdentifier
	for _, cand := range request.Candidates {
		attributes = append(attributes, cand[0])
	}
	c := irma.DisclosureChoice{attributes}
	ph(true, &c)
}
func (sh *ManualSessionHandler) RequestIssuancePermission(request irma.IssuanceRequest, issuerName string, ph PermissionHandler) {
	ph(true, nil)
}

// These handlers should not be called, fail test if they are called
func (sh *ManualSessionHandler) Cancelled(irmaAction irma.Action) {
	sh.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.New("Session was cancelled")})
}
func (sh *ManualSessionHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	sh.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.Errorf("Missing keyshare server %s", manager.String())})
}
func (sh *ManualSessionHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	sh.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.New("Unexpected session type")})
}
func (sh *ManualSessionHandler) RequestVerificationPermission(request irma.DisclosureRequest, verifierName string, ph PermissionHandler) {
	sh.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.New("Unexpected session type")})
}
func (sh *ManualSessionHandler) Failure(irmaAction irma.Action, err *irma.SessionError) {
	fmt.Println(err.Err)
	select {
	case sh.c <- err:
		// nop
	default:
		sh.t.Fatal(err)
	}
}
func (sh *ManualSessionHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	sh.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.New("KeyshareBlocked")})
}
func (sh *ManualSessionHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	sh.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.New("KeyshareEnrollmentIncomplete")})
}
