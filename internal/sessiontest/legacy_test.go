package sessiontest

import (
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSessionUsingLegacyStorage(t *testing.T) {
	test.SetTestStorageDir("legacy_teststorage")
	defer test.SetTestStorageDir("teststorage")

	client, _ := parseStorage(t)

	// Issue new credential
	sessionHelper(t, getMultipleIssuanceRequest(), "issue", client)

	// Close client to prevent database to be opened twice
	err := client.Close()
	require.NoError(t, err)

	// Test whether credential is still there
	require.NoError(t, err)
	id := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	sessionHelper(t, getDisclosureRequest(id), "verification", client)
}
