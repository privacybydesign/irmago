package sessiontest

import (
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestSessionUsingLegacyStorage(t *testing.T) {
	test.SetTestStorageDir("client_legacy")
	defer test.SetTestStorageDir("client")

	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	// Test whether credential from legacy storage is still usable
	idStudentCard := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(idStudentCard)
	sessionHelper(t, request, "verification", client)

	// Issue new credential
	sessionHelper(t, getMultipleIssuanceRequest(), "issue", client)

	// Test whether credential is still there
	idRoot := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.fullName.familyname")
	sessionHelper(t, getDisclosureRequest(idRoot), "verification", client)

	// Re-open client
	require.NoError(t, client.Close())
	client, handler = parseExistingStorage(t, handler.storage)

	// Test whether credential is still there after the storage has been reloaded
	sessionHelper(t, getDisclosureRequest(idRoot), "verification", client)
}

func TestWithoutPairingSupport(t *testing.T) {
	defaultMaxVersion := maxClientVersion
	defer func() {
		maxClientVersion = defaultMaxVersion
	}()
	maxClientVersion = &irma.ProtocolVersion{Major: 2, Minor: 6}

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
	t.Run("TestIssuancePairing", TestIssuancePairing)
	t.Run("TestLargeAttribute", TestLargeAttribute)
	t.Run("TestIssuanceSingletonCredential", TestIssuanceSingletonCredential)
	t.Run("TestUnsatisfiableDisclosureSession", TestUnsatisfiableDisclosureSession)
	t.Run("TestAttributeByteEncoding", TestAttributeByteEncoding)
	t.Run("TestOutdatedClientIrmaConfiguration", TestOutdatedClientIrmaConfiguration)
	t.Run("TestDisclosureNewAttributeUpdateSchemeManager", TestDisclosureNewAttributeUpdateSchemeManager)
	t.Run("TestIssueNewAttributeUpdateSchemeManager", TestIssueNewAttributeUpdateSchemeManager)
	t.Run("TestIssueOptionalAttributeUpdateSchemeManager", TestIssueOptionalAttributeUpdateSchemeManager)
	t.Run("TestIssueNewCredTypeUpdateSchemeManager", TestIssueNewCredTypeUpdateSchemeManager)
	t.Run("TestDisclosureNewCredTypeUpdateSchemeManager", TestDisclosureNewCredTypeUpdateSchemeManager)
	t.Run("TestDisclosureNonexistingCredTypeUpdateSchemeManager", TestDisclosureNonexistingCredTypeUpdateSchemeManager)
	t.Run("TestStaticQRSession", TestStaticQRSession)
	t.Run("TestIssuedCredentialIsStored", TestIssuedCredentialIsStored)
	t.Run("TestPOSTSizeLimit", TestPOSTSizeLimit)
	t.Run("TestDisablePairing", TestDisablePairing)
}
