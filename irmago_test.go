package irmago

import (
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	if len(MetaStore.SchemeManagers) == 0 { // FIXME
		MetaStore.ParseFolder("testdata/irma_configuration")
	}
	Manager = newCredentialManager()
	err := os.RemoveAll("testdata/storage/test")
	if err != nil {
		fmt.Println("Could not delete test storage")
		os.Exit(1)
	}
	err = os.Mkdir("testdata/storage/test", 0755)
	if err != nil {
		fmt.Println("Could not create test storage")
		os.Exit(1)
	}

	retCode := m.Run()

	err = os.RemoveAll("testdata/storage/test")
	if err != nil {
		fmt.Println("Could not delete test storage")
		os.Exit(1)
	}

	os.Exit(retCode)
}

// A convenience function for initializing big integers from known correct (10
// base) strings. Use with care, errors are ignored.
func s2big(s string) (r *big.Int) {
	r, _ = new(big.Int).SetString(s, 10)
	return
}

func parseAndroidStorage(t *testing.T) {
	err := Manager.Init("testdata/storage/test")
	assert.NoError(t, err, "Manager.Init() failed")
	err = Manager.ParseAndroidStorage()
	assert.NoError(t, err, "ParseAndroidStorage failed")
}

func verifyStoreIsUnmarshaled(t *testing.T) {
	cred, err := Manager.Credential("irma-demo.RU.studentCard", 0)
	assert.NoError(t, err, "could not fetch credential")
	assert.NotNil(t, cred, "Credential should exist")
	assert.NotNil(t, cred.Attributes[0], "Metadata attribute of irma-demo.RU.studentCard should not be nil")

	assert.True(t,
		cred.Signature.Verify(cred.PublicKey(), cred.Attributes),
		"Credential should be valid",
	)
}

func TestAndroidParse(t *testing.T) {
	parseAndroidStorage(t)
	verifyStoreIsUnmarshaled(t)
}

func TestUnmarshaling(t *testing.T) {
	parseAndroidStorage(t)

	Manager = newCredentialManager()
	Manager.Init("testdata/storage/test")

	verifyStoreIsUnmarshaled(t)
}

func TestParseStore(t *testing.T) {
	err := MetaStore.ParseFolder("testdata/irma_configuration")
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, MetaStore.Issuers["irma-demo.RU"].CurrentPublicKey().N, "irma-demo.RU public key has no modulus")
	assert.Equal(t,
		"Irma Demo",
		MetaStore.SchemeManagers["irma-demo"].HRName.Translation("en"),
		"irma-demo scheme manager has unexpected name")
	assert.Equal(t,
		"Radboud Universiteit Nijmegen",
		MetaStore.Issuers["irma-demo.RU"].HRName.Translation("en"),
		"irma-demo.RU issuer has unexpected name")
	assert.Equal(t,
		"Student Card",
		MetaStore.Credentials["irma-demo.RU.studentCard"].HRShortName.Translation("en"),
		"irma-demo.RU.studentCard has unexpected name")

	assert.Equal(t,
		"studentID",
		MetaStore.Credentials["irma-demo.RU.studentCard"].Attributes[2].ID,
		"irma-demo.RU.studentCard.studentID has unexpected name")

	// Hash algorithm pseudocode:
	// Base64(SHA256("irma-demo.RU.studentCard")[0:16])
	assert.Contains(t, MetaStore.reverseHashes, "1stqlPad5edpfS1Na1U+DA==",
		"irma-demo.RU.studentCard had improper hash")
	assert.Contains(t, MetaStore.reverseHashes, "CLjnADMBYlFcuGOT7Z0xRg==",
		"irma-demo.MijnOverheid.root had improper hash")
}

func TestMetadataAttribute(t *testing.T) {
	metadata := NewMetadataAttribute()
	if metadata.Version() != 0x02 {
		t.Errorf("Unexpected metadata version: %d", metadata.Version())
	}

	expiry := metadata.SigningDate().Unix() + int64(metadata.ValidityDuration()*ExpiryFactor)
	if !time.Unix(expiry, 0).Equal(metadata.Expiry()) {
		t.Errorf("Invalid signing date")
	}

	if metadata.KeyCounter() != 0 {
		t.Errorf("Unexpected key counter")
	}
}

func TestMetadataCompatibility(t *testing.T) {
	err := MetaStore.ParseFolder("testdata/irma_configuration")
	if err != nil {
		t.Fatal(err)
	}

	// An actual metadata attribute of an IRMA credential extracted from the IRMA app
	attr := MetadataFromInt(s2big("49043481832371145193140299771658227036446546573739245068"))
	assert.NotNil(t, attr.CredentialType(), "attr.CredentialType() should not be nil")

	assert.Equal(t,
		"irma-demo.RU.studentCard",
		attr.CredentialType().Identifier(),
		"Metadata credential type was not irma-demo.RU.studentCard",
	)
	assert.Equal(t, byte(0x02), attr.Version(), "Unexpected metadata version")
	assert.Equal(t, time.Unix(1499904000, 0), attr.SigningDate(), "Unexpected signing date")
	assert.Equal(t, time.Unix(1516233600, 0), attr.Expiry(), "Unexpected expiry date")
	assert.Equal(t, 2, attr.KeyCounter(), "Unexpected key counter")
}
