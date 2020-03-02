// +build !local_tests

package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

func TestManualKeyshareSession(t *testing.T) {
	request := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"))
	ms := createManualSessionHandler(t, nil)

	_, status := manualSessionHelper(t, nil, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	_, status = manualSessionHelper(t, nil, ms, request, nil, false)
	require.Equal(t, irma.ProofStatusValid, status)
}

func TestRequestorIssuanceKeyshareSession(t *testing.T) {
	testRequestorIssuance(t, true, nil)
}

func TestKeyshareRegister(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	require.NoError(t, client.KeyshareRemoveAll())
	require.NoError(t, client.RemoveStorage())

	client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, <-handler.c)

	require.Len(t, client.CredentialInfoList(), 1)

	sessionHelper(t, getIssuanceRequest(true), "issue", client)
	keyshareSessions(t, client)
}

// Use the existing keyshare enrollment and credentials
// in a keyshare session of each session type.
// Use keyshareuser.sql to enroll the user at the keyshare server.
func TestKeyshareSessions(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	keyshareSessions(t, client)
}

func keyshareSessions(t *testing.T, client *irmaclient.Client) {
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
	disclosureRequest.AddSingle(irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"), nil, nil)
	sessionHelper(t, disclosureRequest, "verification", client)

	sigRequest := getSigningRequest(id)
	sigRequest.AddSingle(irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"), nil, nil)
	sessionHelper(t, sigRequest, "signature", client)
}

func TestIssuanceCombinedMultiSchemeSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")
	request := getCombinedIssuanceRequest(id)
	sessionHelper(t, request, "issue", nil)

	sessionHelper(t, irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes: map[string]string{
				"email": "example@example.com",
			},
		},
	}, irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")), "issue", nil)
}

func TestKeyshareRevocation(t *testing.T) {
	t.Run("Keyshare", func(t *testing.T) {
		startRevocationServer(t, true)
		defer stopRevocationServer()
		client, handler := parseStorage(t)
		defer test.ClearTestStorage(t, handler.storage)

		testRevocation(t, revKeyshareTestAttr, client, handler)
	})

	t.Run("Both", func(t *testing.T) {
		startRevocationServer(t, true)
		defer stopRevocationServer()
		client, handler := parseStorage(t)
		defer test.ClearTestStorage(t, handler.storage)

		testRevocation(t, revKeyshareTestAttr, client, handler)
		testRevocation(t, revocationTestAttr, client, handler)
	})
}
