// +build !local_tests

package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestManualKeyShareSession(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"test.test.mijnirma.email\"]}]}"
	ms := createManualSessionHandler(t, nil)

	_, status := manualSessionHelper(t, nil, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	_, status = manualSessionHelper(t, nil, ms, request, "", false)
	require.Equal(t, irma.ProofStatusValid, status)
}

func TestRequestorIssuanceKeyshareSession(t *testing.T) {
	testRequestorIssuance(t, true)
}

// Use the existing keyshare enrollment and credentials
// in a keyshare session of each session type.
// Use keyshareuser.sql to enroll the user at the keyshare server.
func TestKeyshareSessions(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	expiry := irma.Timestamp(irma.NewMetadataAttribute(0).Expiry())
	issuanceRequest := getCombinedIssuanceRequest(id)
	issuanceRequest.Credentials = append(issuanceRequest.Credentials,
		&irma.CredentialRequest{
			Validity:         &expiry,
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes:       map[string]string{"email": "testusername"},
		},
	)
	sessionHelper(t, issuanceRequest, "issue", client)

	disclosureRequest := getDisclosureRequest(id)
	disclosureRequest.Content = append(disclosureRequest.Content,
		&irma.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, disclosureRequest, "verification", client)

	sigRequest := getSigningRequest(id)
	sigRequest.Content = append(sigRequest.Content,
		&irma.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, sigRequest, "signature", client)
}
