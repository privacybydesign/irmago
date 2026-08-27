package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
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
