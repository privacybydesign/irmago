package sessiontest

import (
	"testing"
)

func TestRedis(t *testing.T) {
	testWithRedis = true
	defer func() { testWithRedis = false }()

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
