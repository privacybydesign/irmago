package irmago

import "testing"
import (
	"os"

	"fmt"
	"github.com/mhe/gabi"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	if len(gabi.MetaStore.SchemeManagers) == 0 { // FIXME
		gabi.MetaStore.ParseFolder("testdata/irma_configuration")
	}
	Manager = newCredentialManager()
	err := os.RemoveAll("testdata/storage/test")
	if err != nil {
		fmt.Errorf("Could not delete test storage")
		os.Exit(1)
	}
	err = os.Mkdir("testdata/storage/test", 0755)
	if err != nil {
		fmt.Errorf("Could not create test storage")
		os.Exit(1)
	}

	retCode := m.Run()

	err = os.RemoveAll("testdata/storage/test")
	if err != nil {
		fmt.Errorf("Could not delete test storage")
		os.Exit(1)
	}

	os.Exit(retCode)
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
