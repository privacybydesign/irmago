package irmago

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseStore(t *testing.T) {
	err := MetaStore.ParseFolder("testdata/irma_configuration")
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, MetaStore.issuers["irma-demo.RU"].CurrentPublicKey().N, "irma-demo.RU public key has no modulus")
	assert.Equal(t, MetaStore.managers["irma-demo"].HRName, "Irma Demo", "irma-demo scheme manager has unexpected name")
	assert.Equal(t,
		"Radboud Universiteit Nijmegen",
		MetaStore.issuers["irma-demo.RU"].HRName,
		"irma-demo.RU issuer has unexpected name")
	assert.Equal(t,
		"Student Card",
		MetaStore.credentials["irma-demo.RU.studentCard"].HRShortName,
		"irma-demo.RU.studentCard has unexpected name")
}
