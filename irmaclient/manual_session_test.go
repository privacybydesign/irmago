package irmaclient

import (
	"encoding/json"
	"fmt"

	"testing"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
)

var client *Client

// Issue BSN credential using sessionHelper
func issue(t *testing.T, ms ManualSessionHandler) {
	name := "testip"

	jwtcontents := getIssuanceJwt(name, true, "")
	sessionHandlerHelper(t, jwtcontents, "issue", client, &ms)
}

// Flip one bit in the proof string if invalidate is set to true
var invalidate bool

func corruptAndConvertProofString(proof string) []byte {
	proofBytes := []byte(proof)
	if invalidate {
		// 42 because this is somewhere in a bigint in the json string
		proofBytes[42] ^= 0x01
	}
	return proofBytes
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

	request := "{\"nonce\": 42, \"context\": 1337, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(request, request, t)

	client = parseStorage(t)
	client.NewSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	result := <-ms.resultChannel
	if ps := result.ProofStatus; ps != irma.ProofStatusValid {
		t.Logf("Invalid proof result: %v Expected: %v", ps, irma.ProofStatusValid)
		t.Fatal()
	}
	if attrStatus := result.ToAttributeResultList()[0].AttributeProofStatus; attrStatus != irma.AttributeProofStatusPresent {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.AttributeProofStatusPresent)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

// Test if the session fails with unsatisfiable error if we cannot satify the signature request
func TestManualSessionUnsatisfiable(t *testing.T) {
	invalidate = false

	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":{\"irma-demo.RU.studentCard.studentID\": \"123\"}}]}"
	ms := createManualSessionHandler(request, request, t)

	client = parseStorage(t)
	client.NewSession(request, &ms)

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

	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	invalidRequest := "{\"nonce\": 1, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"

	ms := createManualSessionHandler(request, invalidRequest, t)

	client = parseStorage(t)
	client.NewSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	if result := <-ms.resultChannel; result.ProofStatus != irma.ProofStatusUnmatchedRequest {
		t.Logf("Invalid proof result: %v Expected: %v", result.ProofStatus, irma.ProofStatusUnmatchedRequest)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with a non-matching signature request
func TestManualSessionInvalidRequest(t *testing.T) {
	invalidate = false

	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	invalidRequest := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.university\"]}]}"

	ms := createManualSessionHandler(request, invalidRequest, t)

	client = parseStorage(t)
	client.NewSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	result := <-ms.resultChannel
	if ps := result.ProofStatus; ps != irma.ProofStatusMissingAttributes {
		t.Logf("Invalid proof result: %v Expected: %v", ps, irma.ProofStatusMissingAttributes)
		t.Fail()
	}

	// First attribute result is MISSING, because it is in the request but not disclosed
	if attrStatus := result.ToAttributeResultList()[0].AttributeProofStatus; attrStatus != irma.AttributeProofStatusMissing {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.AttributeProofStatusMissing)
		t.Fail()
	}
	// Second attribute result is EXTRA, since it is disclosed, but not matching the sigrequest
	if attrStatus := result.ToAttributeResultList()[1].AttributeProofStatus; attrStatus != irma.AttributeProofStatusExtra {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.AttributeProofStatusExtra)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with invalid attribute values
func TestManualSessionInvalidAttributeValue(t *testing.T) {
	invalidate = false

	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":{\"irma-demo.RU.studentCard.studentID\": \"456\"}}]}"
	invalidRequest := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":{\"irma-demo.RU.studentCard.studentID\": \"123\"}}]}"

	ms := createManualSessionHandler(request, invalidRequest, t)

	client = parseStorage(t)
	client.NewSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	result := <-ms.resultChannel
	if ps := result.ProofStatus; ps != irma.ProofStatusMissingAttributes {
		t.Logf("Invalid proof result: %v Expected: %v", ps, irma.ProofStatusMissingAttributes)
		t.Fail()
	}
	if attrStatus := result.ToAttributeResultList()[0].AttributeProofStatus; attrStatus != irma.AttributeProofStatusInvalidValue {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.AttributeProofStatusInvalidValue)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

func TestManualKeyShareSession(t *testing.T) {
	invalidate = false

	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"test.test.mijnirma.email\"]}]}"

	ms := createManualSessionHandler(request, request, t)

	client = parseStorage(t)
	client.NewSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	if result := <-ms.resultChannel; result.ProofStatus != irma.ProofStatusValid {
		t.Logf("Invalid proof result: %v Expected: %v", result.ProofStatus, irma.ProofStatusValid)
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
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]},{\"label\":\"BSN\",\"attributes\":[\"irma-demo.MijnOverheid.root.BSN\"]}]}"

	ms := createManualSessionHandler(request, request, t)

	client.NewSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	result := <-ms.resultChannel
	if ps := result.ProofStatus; ps != irma.ProofStatusValid {
		t.Logf("Invalid proof result: %v Expected: %v", result.ProofStatus, irma.ProofStatusValid)
		t.Fail()
	}
	if attrStatus := result.ToAttributeResultList()[0].AttributeProofStatus; attrStatus != irma.AttributeProofStatusPresent {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.AttributeProofStatusPresent)
		t.Fail()
	}
	if attrStatus := result.ToAttributeResultList()[1].AttributeProofStatus; attrStatus != irma.AttributeProofStatusPresent {
		t.Logf("Invalid attribute result value: %v Expected: %v", attrStatus, irma.AttributeProofStatusPresent)
		t.Fail()
	}
	test.ClearTestStorage(t)
}

func TestManualSessionInvalidProof(t *testing.T) {
	invalidate = true

	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(request, request, t)

	client = parseStorage(t)
	client.NewSession(request, &ms)

	if err := <-ms.errorChannel; err != nil {
		test.ClearTestStorage(t)
		t.Fatal(*err)
	}

	// No errors, obtain proof result from channel
	if result := <-ms.resultChannel; result.ProofStatus != irma.ProofStatusInvalidCrypto {
		t.Logf("Invalid proof result: %v Expected: %v", result.ProofStatus, irma.ProofStatusInvalidCrypto)
		t.Fail()
	}
	test.ClearTestStorage(t)
}
