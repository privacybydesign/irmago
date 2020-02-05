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

	client, _ := parseStorage(t)
	defer test.ClearTestStorage(t)

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
	client, _ = parseExistingStorage(t)

	// Test whether credential is still there after the storage has been reloaded
	sessionHelper(t, getDisclosureRequest(idRoot), "verification", client)
}
