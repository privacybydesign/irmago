package irmago

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseStore(t *testing.T) {
	err := MetaStore.ParseFolder("testdata/irma_configuration")
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, MetaStore.Issuers["irma-demo.RU"].CurrentPublicKey().N, "irma-demo.RU public key has no modulus")
	assert.Equal(t, MetaStore.SchemeManagers["irma-demo"].HRName, "Irma Demo", "irma-demo scheme manager has unexpected name")
	assert.Equal(t,
		"Radboud Universiteit Nijmegen",
		MetaStore.Issuers["irma-demo.RU"].HRName,
		"irma-demo.RU issuer has unexpected name")
	assert.Equal(t,
		"Student Card",
		MetaStore.Credentials["irma-demo.RU.studentCard"].HRShortName,
		"irma-demo.RU.studentCard has unexpected name")
}

func TestInts(t *testing.T) {
	t.Log(big.NewInt(2900).Bytes())
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, 2900)
	t.Log(bytes)
	t.Log(binary.BigEndian.Uint16(bytes))
}
