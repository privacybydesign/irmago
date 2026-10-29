package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The scheme's ShouldBeSingleton reaches the client on a credential type, so
// the app can say "fetch again" (the new card replaces the old one) instead
// of "add another".
func TestGetCredentialDescriptor_IsSingleton(t *testing.T) {
	conf := loadTestIrmaConfiguration(t)

	single, err := getCredentialDescriptor(conf, irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.singleton"), "en")
	require.NoError(t, err)
	assert.True(t, single.IsSingleton)

	many, err := getCredentialDescriptor(conf, irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"), "en")
	require.NoError(t, err)
	assert.False(t, many.IsSingleton)
}

// A disclosure candidate is built from the wallet credential and keeps its
// singleton flag.
func TestFindCredential_KeepsIsSingleton(t *testing.T) {
	creds := []*clientmodels.Credential{{
		CredentialId:          "irma-demo.MijnOverheid.singleton",
		CredentialInstanceIds: map[clientmodels.CredentialFormat]string{clientmodels.Format_Idemix: "h1"},
		IsSingleton:           true,
	}}
	found := findCredential(creds, "h1")
	require.NotNil(t, found)
	assert.True(t, found.IsSingleton)
}
