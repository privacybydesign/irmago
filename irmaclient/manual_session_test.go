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
	errorChannel      chan *irma.SessionError
	resultChannel     chan *irma.SignatureProofResult
	sigRequest        *irma.SignatureRequest // Request used to create signature
	sigVerifyRequest  *irma.SignatureRequest // Request used to verify signature
}

var client *Client

// Issue BSN credential using sessionHelper
func issue(t *testing.T, ms ManualSessionHandler) {
	name := "testip"

	jwtcontents := getIssuanceJwt(name, true, "")
	sessionHandlerHelper(t, jwtcontents, "issue", client, &ms)
}

// Flip one bit in the proof string if invalidate is set to true
var invalidate bool

func corruptProofString(proof string) string {
	if invalidate {
		proofBytes := []byte(proof)

		// 15 because this is somewhere in a bigint in the json string
		proofBytes[15] ^= 0x01
		return string(proofBytes)
	}
	return proof
}

// Create a ManualSessionHandler for unit tests
func createManualSessionHandler(request string, invalidRequest string, t *testing.T) ManualSessionHandler {
	errorChannel := make(chan *irma.SessionError)
	resultChannel := make(chan *irma.SignatureProofResult)

	sigRequestJSON := []byte(request)
	invalidSigRequestJSON := []byte(invalidRequest)
	sigRequest := &irma.SignatureRequest{}
	invalidSigRequest := &irma.SignatureRequest{}
	json.Unmarshal(sigRequestJSON, sigRequest)
	json.Unmarshal(invalidSigRequestJSON, invalidSigRequest)

	return ManualSessionHandler{
		t:                t,
		errorChannel:     errorChannel,
		resultChannel:    resultChannel,
		sigRequest:       sigRequest,
		sigVerifyRequest: invalidSigRequest,
	}
}

func TestManualSession(t *testing.T) {
	invalidate = false

	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(request, request, t)

	client = parseStorage(t)
	client.NewManualSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	result := <-ms.resultChannel
	if ps := result.ProofStatus; ps != irma.VALID {
		t.Logf("Invalid proof result: %v Expected: %v", ps, irma.VALID)
		t.Fail()
	}
	if attrStatus := result.ToAttributeResultList()[0].AttributeProofStatus; attrStatus != irma.PRESENT {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.PRESENT)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

// Test if the session fails with unsatisfiable error if we cannot satify the signature request
func TestManualSessionUnsatisfiable(t *testing.T) {
	invalidate = false

	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":{\"irma-demo.RU.studentCard.studentID\": \"123\"}}]}"
	ms := createManualSessionHandler(request, request, t)

	client = parseStorage(t)
	client.NewManualSession(request, &ms)

	// Fail test if we won't get UnsatisfiableRequest error
	if err := <-ms.errorChannel; err.ErrorType != irma.ErrorType("UnsatisfiableRequest") {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}
	test.ClearTestStorage(t)
}

// Test if proof verification fails with status 'ERROR_CRYPTO' if we verify it with an invalid nonce
func TestManualSessionInvalidNonce(t *testing.T) {
	invalidate = false

	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	invalidRequest := "{\"nonce\": 1, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"

	ms := createManualSessionHandler(request, invalidRequest, t)

	client = parseStorage(t)
	client.NewManualSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	if result := <-ms.resultChannel; result.ProofStatus != irma.INVALID_CRYPTO {
		t.Logf("Invalid proof result: %v Expected: %v", result.ProofStatus, irma.INVALID_CRYPTO)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with a non-matching signature request
func TestManualSessionInvalidRequest(t *testing.T) {
	invalidate = false

	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	invalidRequest := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.university\"]}]}"

	ms := createManualSessionHandler(request, invalidRequest, t)

	client = parseStorage(t)
	client.NewManualSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	result := <-ms.resultChannel
	if ps := result.ProofStatus; ps != irma.MISSING_ATTRIBUTES {
		t.Logf("Invalid proof result: %v Expected: %v", ps, irma.MISSING_ATTRIBUTES)
		t.Fail()
	}

	// First attribute result is MISSING, because it is in the request but not disclosed
	if attrStatus := result.ToAttributeResultList()[0].AttributeProofStatus; attrStatus != irma.MISSING {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.MISSING)
		t.Fail()
	}
	// Second attribute result is EXTRA, since it is disclosed, but not matching the sigrequest
	if attrStatus := result.ToAttributeResultList()[1].AttributeProofStatus; attrStatus != irma.EXTRA {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.EXTRA)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with invalid attribute values
func TestManualSessionInvalidAttributeValue(t *testing.T) {
	invalidate = false

	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":{\"irma-demo.RU.studentCard.studentID\": \"456\"}}]}"
	invalidRequest := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":{\"irma-demo.RU.studentCard.studentID\": \"123\"}}]}"

	ms := createManualSessionHandler(request, invalidRequest, t)

	client = parseStorage(t)
	client.NewManualSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	result := <-ms.resultChannel
	if ps := result.ProofStatus; ps != irma.MISSING_ATTRIBUTES {
		t.Logf("Invalid proof result: %v Expected: %v", ps, irma.MISSING_ATTRIBUTES)
		t.Fail()
	}
	if attrStatus := result.ToAttributeResultList()[0].AttributeProofStatus; attrStatus != irma.INVALID_VALUE {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.INVALID_VALUE)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

func TestManualKeyShareSession(t *testing.T) {
	invalidate = false

	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"test.test.mijnirma.email\"]}]}"

	ms := createManualSessionHandler(request, request, t)

	client = parseStorage(t)
	client.NewManualSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	if result := <-ms.resultChannel; result.ProofStatus != irma.VALID {
		t.Logf("Invalid proof result: %v Expected: %v", result.ProofStatus, irma.VALID)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

func TestManualSessionMultiProof(t *testing.T) {
	invalidate = false
	client = parseStorage(t)

	// First, we need to issue an extra credential (BSN)
	is := ManualSessionHandler{t: t, errorChannel: make(chan *irma.SessionError)}
	go issue(t, is)
	if err := <-is.errorChannel; err != nil {
		fmt.Println("Error during initial issueing!")
		t.Fatal(*err)
	}

	// Request to sign with both BSN and StudentID
	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]},{\"label\":\"BSN\",\"attributes\":[\"irma-demo.MijnOverheid.root.BSN\"]}]}"

	ms := createManualSessionHandler(request, request, t)

	client.NewManualSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	result := <-ms.resultChannel
	if ps := result.ProofStatus; ps != irma.VALID {
		t.Logf("Invalid proof result: %v Expected: %v", result.ProofStatus, irma.VALID)
		t.Fail()
	}
	if attrStatus := result.ToAttributeResultList()[0].AttributeProofStatus; attrStatus != irma.PRESENT {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.PRESENT)
		t.Fail()
	}
	if attrStatus := result.ToAttributeResultList()[1].AttributeProofStatus; attrStatus != irma.PRESENT {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.PRESENT)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

func TestManualSessionInvalidProof(t *testing.T) {
	invalidate = true

	request := "{\"nonce\": 0, \"context\": 0, \"message\":\"I owe you everything\",\"messageType\":\"STRING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(request, request, t)

	client = parseStorage(t)
	client.NewManualSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	if result := <-ms.resultChannel; result.ProofStatus != irma.INVALID_CRYPTO {
		t.Logf("Invalid proof result: %v Expected: %v", result.ProofStatus, irma.INVALID_CRYPTO)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

func (sh *ManualSessionHandler) Success(irmaAction irma.Action, result string) {
	switch irmaAction {
	case irma.ActionSigning:
		// Make proof corrupt if we want to test invalid proofs
		result = corruptProofString(result)

		go func() {
			sh.resultChannel <- irma.VerifySig(client.Configuration, result, sh.sigVerifyRequest)
		}()
	}
	sh.errorChannel <- nil
}
func (sh *ManualSessionHandler) UnsatisfiableRequest(irmaAction irma.Action, serverName string, missingAttributes irma.AttributeDisjunctionList) {
	// This function is called from main thread, which blocks go channel, so need go routine here
	go func() {
		sh.errorChannel <- &irma.SessionError{
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
	sh.errorChannel <- &irma.SessionError{Err: errors.New("Session was cancelled")}
}
func (sh *ManualSessionHandler) MissingKeyshareEnrollment(manager irma.SchemeManagerIdentifier) {
	sh.errorChannel <- &irma.SessionError{Err: errors.Errorf("Missing keyshare server %s", manager.String())}
}
func (sh *ManualSessionHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	sh.errorChannel <- &irma.SessionError{Err: errors.New("Unexpected session type")}
}
func (sh *ManualSessionHandler) RequestVerificationPermission(request irma.DisclosureRequest, verifierName string, ph PermissionHandler) {
	sh.errorChannel <- &irma.SessionError{Err: errors.New("Unexpected session type")}
}
func (sh *ManualSessionHandler) Failure(irmaAction irma.Action, err *irma.SessionError) {
	fmt.Println(err.Err)
	sh.errorChannel <- err
}
func (sh *ManualSessionHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	sh.errorChannel <- &irma.SessionError{Err: errors.New("KeyshareBlocked")}
}
func (sh *ManualSessionHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	sh.errorChannel <- &irma.SessionError{Err: errors.New("KeyshareEnrollmentIncomplete")}
}
func (sh *ManualSessionHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	sh.errorChannel <- &irma.SessionError{Err: errors.Errorf("Missing keyshare server %s", manager.String())}
}
func (sh *ManualSessionHandler) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	sh.errorChannel <- &irma.SessionError{Err: errors.Errorf("Keyshare enrollment deleted for %s", manager.String())}
}
