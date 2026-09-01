package client

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A credential whose type is no longer in the configuration must not fail the
// whole conversion: the good credentials still come back, and the unknown one is
// isolated as a ProblematicCredential carrying its storage hash so it stays
// deletable. This is the core of the "one corrupt credential can't blank the
// overview" guarantee.
func TestCredentialInfoListToSchemaless_UnknownTypeIsIsolated(t *testing.T) {
	conf := &irma.Configuration{
		CredentialTypes: map[irma.CredentialTypeIdentifier]*irma.CredentialType{},
	}
	unknown := &irma.CredentialInfo{
		SchemeManagerID:  "irma-demo",
		IssuerID:         "acme",
		ID:               "gone",
		Hash:             "hash-unknown",
		CredentialFormat: clientmodels.Format_Idemix,
		Attributes:       map[irma.AttributeTypeIdentifier]irma.TranslatedString{},
	}

	good, problematic := credentialInfoListToSchemaless(conf, irma.CredentialInfoList{unknown}, "en")

	assert.Empty(t, good, "unknown-type credential must not appear as a good credential")
	require.Len(t, problematic, 1)
	assert.Equal(t, "irma-demo.acme.gone", problematic[0].CredentialId)
	assert.Equal(t, "hash-unknown", problematic[0].CredentialInstanceIds[clientmodels.Format_Idemix],
		"problematic credential must carry its hash so it can be deleted")
}

// An empty input yields empty (non-nil) slices, never a nil-map panic.
func TestCredentialInfoListToSchemaless_EmptyInput(t *testing.T) {
	conf := &irma.Configuration{
		CredentialTypes: map[irma.CredentialTypeIdentifier]*irma.CredentialType{},
	}
	good, problematic := credentialInfoListToSchemaless(conf, irma.CredentialInfoList{}, "en")
	assert.Empty(t, good)
	assert.Empty(t, problematic)
}

// Deleting a credential whose type is not in the configuration — the very
// credential a ProblematicCredential points at — must still yield a removal log
// entry (without attributes, since there is no type to name them) rather than
// dereference the missing type.
func TestCreateRemovalLog_UnknownTypeLogsWithoutAttributes(t *testing.T) {
	conf := &irma.Configuration{
		CredentialTypes: map[irma.CredentialTypeIdentifier]*irma.CredentialType{},
	}
	id := irma.NewCredentialTypeIdentifier("irma-demo.acme.gone")

	entry, err := createRemovalLog(conf, id,
		map[irma.AttributeTypeIdentifier]irma.TranslatedString{},
		[]clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc})

	require.NoError(t, err)
	require.Contains(t, entry.Removed, id)
	assert.Empty(t, entry.Removed[id])
	assert.Equal(t, []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc}, entry.RemovedFormats)
}

// The activity log must render the removal of a credential whose type is not in
// the configuration: the entry falls back to the bare identifiers instead of
// dereferencing the missing type and taking the whole log down.
func TestRawLogEntryToLogInfo_RemovalOfUnknownTypeRenders(t *testing.T) {
	client := newClientOnFreshStorage(t)()
	defer client.Close()

	id := irma.NewCredentialTypeIdentifier("irma-demo.acme.gone")
	entry := &irmaclient.LogEntry{
		Time:           irmaclient.LogTime(time.Now()),
		Type:           irmaclient.ActionRemoval,
		Removed:        map[irma.CredentialTypeIdentifier][]irma.TranslatedString{id: {}},
		RemovedFormats: []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
	}

	info, err := client.rawLogEntryToLogInfo(entry)

	require.NoError(t, err)
	require.Equal(t, clientmodels.LogType_CredentialRemoval, info.Type)
	require.NotNil(t, info.RemovalLog)
	require.Len(t, info.RemovalLog.Credentials, 1)
	cred := info.RemovalLog.Credentials[0]
	assert.Equal(t, "irma-demo.acme.gone", cred.CredentialId)
	assert.Equal(t, "irma-demo.acme.gone", cred.Name, "the type id is the only label left")
	assert.Equal(t, "irma-demo.acme", cred.Issuer.Id)
	assert.Empty(t, cred.Attributes)
	assert.Equal(t, []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc}, cred.Formats)
}
