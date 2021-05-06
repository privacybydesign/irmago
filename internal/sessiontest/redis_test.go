package sessiontest

import (
	"github.com/alicebob/miniredis"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/require"
	"testing"
)

var mr *miniredis.Miniredis

func startRedis(t *testing.T) {
	if mr == nil {
		var err error
		mr, err = miniredis.Run()
		require.NoError(t, err)
	} else {
		mr.FlushAll()
	}
	testConfigurationHandler = func(c *server.Configuration) {
		c.StoreType = "redis"
		c.RedisSettings.Host = mr.Host()
		c.RedisSettings.Port = mr.Port()
	}
}

func stopRedis() {
	testConfigurationHandler = defaultTestConfiguration
	if mr != nil {
		mr.Close()
	}
}

func TestRedis(t *testing.T) {
	startRedis(t)
	defer stopRedis()

	// run all session_test tests
	t.Run("TestSigningSession", TestSigningSession)
	t.Run("TestDisclosureSession", TestDisclosureSession)
	t.Run("TestNoAttributeDisclosureSession", TestNoAttributeDisclosureSession)
	t.Run("TestEmptyDisclosure", TestEmptyDisclosure)
	t.Run("TestIssuanceSession", TestIssuanceSession)
	t.Run("TestMultipleIssuanceSession", TestMultipleIssuanceSession)
	t.Run("TestDefaultCredentialValidity", TestDefaultCredentialValidity)
	t.Run("TestIssuanceDisclosureEmptyAttributes", TestIssuanceDisclosureEmptyAttributes)
	t.Run("TestIssuanceOptionalZeroLengthAttributes", TestIssuanceOptionalZeroLengthAttributes)
	t.Run("TestIssuanceOptionalSetAttributes", TestIssuanceOptionalSetAttributes)
	t.Run("TestIssuanceSameAttributesNotSingleton", TestIssuanceSameAttributesNotSingleton)
	t.Run("TestLargeAttribute", TestLargeAttribute)
	t.Run("TestIssuanceSingletonCredential", TestIssuanceSingletonCredential)
	t.Run("TestUnsatisfiableDisclosureSession", TestUnsatisfiableDisclosureSession)
	t.Run("TestAttributeByteEncoding", TestAttributeByteEncoding)
	t.Run("TestOutdatedClientIrmaConfiguration", TestOutdatedClientIrmaConfiguration)
	t.Run("TestDisclosureNewAttributeUpdateSchemeManager", TestDisclosureNewAttributeUpdateSchemeManager)
	t.Run("TestIssueNewAttributeUpdateSchemeManager", TestIssueNewAttributeUpdateSchemeManager)
	t.Run("TestIrmaServerPrivateKeysFolder", TestIrmaServerPrivateKeysFolder)
	t.Run("TestIssueOptionalAttributeUpdateSchemeManager", TestIssueOptionalAttributeUpdateSchemeManager)
	t.Run("TestIssueNewCredTypeUpdateSchemeManager", TestIssueNewCredTypeUpdateSchemeManager)
	t.Run("TestDisclosureNewCredTypeUpdateSchemeManager", TestDisclosureNewCredTypeUpdateSchemeManager)
	t.Run("TestDisclosureNonexistingCredTypeUpdateSchemeManager", TestDisclosureNonexistingCredTypeUpdateSchemeManager)
	t.Run("TestStaticQRSession", TestStaticQRSession)
	t.Run("TestIssuedCredentialIsStored", TestIssuedCredentialIsStored)
	t.Run("TestBlindIssuanceSession", TestBlindIssuanceSession)
	t.Run("TestBlindIssuanceSessionDifferentAmountOfRandomBlinds", TestBlindIssuanceSessionDifferentAmountOfRandomBlinds)
	t.Run("TestPOSTSizeLimit", TestPOSTSizeLimit)
	t.Run("TestChainedSessions", TestChainedSessions)
}
