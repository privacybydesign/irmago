package sessiontest

import (
	"encoding/json"
	"testing"

	"github.com/mhe/gabi"
	"github.com/mhe/gabi/big"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

// Create a ManualTestHandler for unit tests
func createManualSessionHandler(t *testing.T, client *irmaclient.Client) *ManualTestHandler {
	return &ManualTestHandler{
		TestHandler: TestHandler{
			t:      t,
			c:      make(chan *SessionResult),
			client: client,
		},
	}
}

func manualSessionHelper(t *testing.T, client *irmaclient.Client, h *ManualTestHandler, request string, verifyAs string, corrupt bool) ([]*irma.DisclosedAttribute, irma.ProofStatus) {
	if client == nil {
		client = parseStorage(t)
		defer test.ClearTestStorage(t)
	}

	client.NewSession(request, h)

	result := <-h.c
	if result.Err != nil {
		require.NoError(t, result.Err)
	}

	switch h.action {
	case irma.ActionDisclosing:
		verifyasRequest := &irma.DisclosureRequest{}
		err := json.Unmarshal([]byte(verifyAs), verifyasRequest)
		require.NoError(t, err)
		list, status, err := irma.ProofList(result.VerificationResult).Verify(client.Configuration, verifyasRequest)
		require.NoError(t, err)
		return list, status
	case irma.ActionSigning:
		var verifyasRequest *irma.SignatureRequest
		if verifyAs != "" {
			verifyasRequest = &irma.SignatureRequest{}
			err := json.Unmarshal([]byte(verifyAs), verifyasRequest)
			require.NoError(t, err)
		}

		if corrupt {
			// Interesting: modifying C results in INVALID_CRYPTO; modifying A or an attribute results in INVALID_TIMESTAMP
			i := result.SignatureResult.Signature[0].(*gabi.ProofD).C
			i.Add(i, big.NewInt(16))
		}
		list, status, err := result.SignatureResult.Verify(client.Configuration, verifyasRequest)
		require.NoError(t, err)
		return list, status
	default:
		return nil, ""
	}
}

func TestManualSession(t *testing.T) {
	request := "{\"nonce\": 42, \"context\": 1337, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(t, nil)

	attrs, status := manualSessionHelper(t, nil, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	require.Equal(t, irma.AttributeProofStatusPresent, attrs[0].Status)
	attrs, status = manualSessionHelper(t, nil, ms, request, "", false)
	require.Equal(t, irma.ProofStatusValid, status)
	require.Equal(t, irma.AttributeProofStatusExtra, attrs[0].Status)
}

// Test if proof verification fails with status 'ERROR_CRYPTO' if we verify it with an invalid nonce
func TestManualSessionInvalidNonce(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	invalidRequest := "{\"nonce\": 1, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(t, nil)
	_, status := manualSessionHelper(t, nil, ms, request, invalidRequest, false)

	require.Equal(t, irma.ProofStatusUnmatchedRequest, status)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with a non-matching signature request
func TestManualSessionInvalidRequest(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	invalidRequest := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.university\"]}]}"
	ms := createManualSessionHandler(t, nil)
	attrs, status := manualSessionHelper(t, nil, ms, request, invalidRequest, false)

	require.Equal(t, irma.ProofStatusMissingAttributes, status)
	// First attribute result is MISSING, because it is in the request but not disclosed
	require.Equal(t, irma.AttributeProofStatusMissing, attrs[0].Status)
	// Second attribute result is EXTRA, since it is disclosed, but not matching the sigrequest
	require.Equal(t, irma.AttributeProofStatusExtra, attrs[1].Status)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with invalid attribute values
func TestManualSessionInvalidAttributeValue(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":{\"irma-demo.RU.studentCard.studentID\": \"456\"}}]}"
	invalidRequest := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":{\"irma-demo.RU.studentCard.studentID\": \"123\"}}]}"
	ms := createManualSessionHandler(t, nil)
	attrs, status := manualSessionHelper(t, nil, ms, request, invalidRequest, false)

	require.Equal(t, irma.ProofStatusMissingAttributes, status)
	require.Equal(t, irma.AttributeProofStatusInvalidValue, attrs[0].Status)
}

func TestManualKeyShareSession(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"test.test.mijnirma.email\"]}]}"
	ms := createManualSessionHandler(t, nil)

	_, status := manualSessionHelper(t, nil, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	_, status = manualSessionHelper(t, nil, ms, request, "", false)
	require.Equal(t, irma.ProofStatusValid, status)
}

func TestManualSessionMultiProof(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	// First, we need to issue an extra credential (BSN)
	sessionHelper(t, getIssuanceRequest(true), "issue", client)

	// Request to sign with both BSN and StudentID
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]},{\"label\":\"BSN\",\"attributes\":[\"irma-demo.MijnOverheid.root.BSN\"]}]}"

	ms := createManualSessionHandler(t, client)

	attrs, status := manualSessionHelper(t, client, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	require.Equal(t, irma.AttributeProofStatusPresent, attrs[0].Status)
	require.Equal(t, irma.AttributeProofStatusPresent, attrs[1].Status)
	attrs, status = manualSessionHelper(t, client, ms, request, "", false)
	require.Equal(t, irma.ProofStatusValid, status)
	require.Equal(t, irma.AttributeProofStatusExtra, attrs[0].Status)
	require.Equal(t, irma.AttributeProofStatusExtra, attrs[1].Status)
}

func TestManualSessionInvalidProof(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(t, nil)
	_, status := manualSessionHelper(t, nil, ms, request, request, true)

	require.Equal(t, irma.ProofStatusInvalid, status)
}

func TestManualDisclosureSession(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"disclosing\", \"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(t, nil)
	attrs, status := manualSessionHelper(t, nil, ms, request, request, false)

	require.Equal(t, irma.AttributeProofStatusPresent, attrs[0].Status)
	require.Equal(t, "456", attrs[0].Value["en"])
	require.Equal(t, irma.ProofStatusValid, status)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with a non-matching disclosure request
func TestManualDisclosureSessionInvalidRequest(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"disclosing\", \"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	invalidRequest := "{\"nonce\": 0, \"context\": 0, \"type\": \"disclosing\", \"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.university\"]}]}"
	ms := createManualSessionHandler(t, nil)
	attrs, status := manualSessionHelper(t, nil, ms, request, invalidRequest, false)

	require.Equal(t, irma.ProofStatusMissingAttributes, status)
	// First attribute result is MISSING, because it is in the request but not disclosed
	require.Equal(t, irma.AttributeProofStatusMissing, attrs[0].Status)
	// Second attribute result is EXTRA, since it is disclosed, but not matching the sigrequest
	require.Equal(t, irma.AttributeProofStatusExtra, attrs[1].Status)
}
