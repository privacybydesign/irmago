package irmago

import "testing"
import (
	"github.com/mhe/gabi"
	"github.com/stretchr/testify/assert"
)

func TestAndroidParse(t *testing.T) {
	gabi.MetaStore.ParseFolder("testdata/irma_configuration")
	Manager.Init("testdata/storage")
	err := Manager.ParseAndroidStorage()

	assert.NoError(t, err, "ParseAndroidStorage failed")
	assert.NotEmpty(t, Manager.credentials, "No credentials deserialized")
	assert.Contains(t, Manager.credentials, "irma-demo.RU.studentCard", "irma-demo.RU.studentCard not deserialized")
	assert.NotEmpty(t, Manager.credentials, "irma-demo.RU.studentCard not deserialized")
	cred := Manager.credentials["irma-demo.RU.studentCard"][0]
	assert.NotNil(t, cred.Attributes[0], "Metadata attribute of irma-demo.RU.studentCard should not be nil")

	assert.True(t,
		Manager.credentials["irma-demo.RU.studentCard"][0].Signature.Verify(cred.PublicKey(), cred.Attributes),
		"Credential should be valid",
	)
}
