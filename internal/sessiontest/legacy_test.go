package sessiontest

import (
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestSessionUsingLegacyStorage(t *testing.T) {
	test.SetTestStorageDir("client_legacy")
	defer test.SetTestStorageDir("client")

	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	// Test whether credential from legacy storage is still usable
	idStudentCard := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(idStudentCard)
	sessionHelper(t, request, "verification", client)

	// Issue new credential
	sessionHelper(t, getMultipleIssuanceRequest(), "issue", client)

	// Test whether credential is still there
	idRoot := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.fullName.familyname")
	sessionHelper(t, getDisclosureRequest(idRoot), "verification", client)

	// Re-open client
	require.NoError(t, client.Close())
	client, handler = parseExistingStorage(t, handler.storage)

	// Test whether credential is still there after the storage has been reloaded
	sessionHelper(t, getDisclosureRequest(idRoot), "verification", client)
}
