package sessiontest

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
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

func manualSessionHelper(t *testing.T, client *irmaclient.Client, h *ManualTestHandler, request, verifyAs irma.SessionRequest, corrupt bool) ([][]*irma.DisclosedAttribute, irma.ProofStatus) {
	if client == nil {
		var handler *TestClientHandler
		client, handler = parseStorage(t)
		defer test.ClearTestStorage(t, client, handler.storage)
	}

	bts, err := json.Marshal(request)
	require.NoError(t, err)

	go client.NewSession(string(bts), h)

	result := <-h.c
	if result.Err != nil {
		require.NoError(t, result.Err)
	}

	switch h.action {
	case irma.ActionDisclosing:
		r, _ := verifyAs.(*irma.DisclosureRequest)
		list, status, err := result.DisclosureResult.Verify(client.Configuration, r)
		require.NoError(t, err)
		return list, status
	case irma.ActionSigning:
		if corrupt {
			// Interesting: modifying C results in INVALID_CRYPTO; modifying A or an attribute results in INVALID_TIMESTAMP
			i := result.SignatureResult.Signature[0].(*gabi.ProofD).C
			i.Add(i, big.NewInt(16))
		}
		r, _ := verifyAs.(*irma.SignatureRequest)
		list, status, err := result.SignatureResult.Verify(client.Configuration, r)
		require.NoError(t, err)
		return list, status
	default:
		return nil, ""
	}
}

func TestManualSession(t *testing.T) {
	request := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	request.Nonce = big.NewInt(42)

	ms := createManualSessionHandler(t, nil)

	attrs, status := manualSessionHelper(t, nil, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	require.Equal(t, irma.AttributeProofStatusPresent, attrs[0][0].Status)
	attrs, status = manualSessionHelper(t, nil, ms, request, nil, false)
	require.Equal(t, irma.ProofStatusValid, status)
	require.Equal(t, irma.AttributeProofStatusExtra, attrs[0][0].Status)
}

// Test if proof verification fails with status 'ERROR_CRYPTO' if we verify it with an invalid nonce
func TestManualSessionInvalidNonce(t *testing.T) {
	request := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	invalidRequest := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	invalidRequest.Nonce = big.NewInt(1)

	ms := createManualSessionHandler(t, nil)
	_, status := manualSessionHelper(t, nil, ms, request, invalidRequest, false)

	require.Equal(t, irma.ProofStatusUnmatchedRequest, status)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with a non-matching signature request
func TestManualSessionInvalidRequest(t *testing.T) {
	request := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	invalidRequest := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"))
	ms := createManualSessionHandler(t, nil)
	_, status := manualSessionHelper(t, nil, ms, request, invalidRequest, false)

	require.Equal(t, irma.ProofStatusMissingAttributes, status)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with invalid attribute values
func TestManualSessionInvalidAttributeValue(t *testing.T) {
	wrong, correct := "123", "456"
	request := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	request.Disclose[0][0][0].Value = &correct
	invalidRequest := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	invalidRequest.Disclose[0][0][0].Value = &wrong

	ms := createManualSessionHandler(t, nil)
	_, status := manualSessionHelper(t, nil, ms, request, invalidRequest, false)
	require.Equal(t, irma.ProofStatusMissingAttributes, status)
}

func TestManualSessionMultiProof(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)

	// First, we need to issue an extra credential (BSN)
	doSession(t, getMultipleIssuanceRequest(), client, nil, nil, nil, nil, nil)

	// Request to sign with both BSN and StudentID
	request := irma.NewSignatureRequest("I owe you everything",
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
		irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.fullName.familyname"))

	ms := createManualSessionHandler(t, client)

	attrs, status := manualSessionHelper(t, client, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	require.Equal(t, irma.AttributeProofStatusPresent, attrs[0][0].Status)
	require.Equal(t, irma.AttributeProofStatusPresent, attrs[1][0].Status)
	attrs, status = manualSessionHelper(t, client, ms, request, nil, false)
	require.Equal(t, irma.ProofStatusValid, status)
	require.Equal(t, irma.AttributeProofStatusExtra, attrs[0][0].Status)
	require.Equal(t, irma.AttributeProofStatusExtra, attrs[0][1].Status)
}

func TestManualSessionInvalidProof(t *testing.T) {
	request := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	ms := createManualSessionHandler(t, nil)
	_, status := manualSessionHelper(t, nil, ms, request, request, true)

	require.Equal(t, irma.ProofStatusInvalid, status)
}

func TestManualDisclosureSession(t *testing.T) {
	request := irma.NewDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	ms := createManualSessionHandler(t, nil)
	attrs, status := manualSessionHelper(t, nil, ms, request, request, false)

	require.Equal(t, irma.AttributeProofStatusPresent, attrs[0][0].Status)
	require.Equal(t, "456", attrs[0][0].Value["en"])
	require.Equal(t, irma.ProofStatusValid, status)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with a non-matching disclosure request
func TestManualDisclosureSessionInvalidRequest(t *testing.T) {
	request := irma.NewDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	invalidRequest := irma.NewDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"))
	ms := createManualSessionHandler(t, nil)
	_, status := manualSessionHelper(t, nil, ms, request, invalidRequest, false)

	require.Equal(t, irma.ProofStatusMissingAttributes, status)
}
