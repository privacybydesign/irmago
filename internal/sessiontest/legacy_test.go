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
	doSession(t, request, client, nil, nil, nil, nil)

	// Issue new credential
	doSession(t, getMultipleIssuanceRequest(), client, nil, nil, nil, nil)

	// Test whether credential is still there
	idRoot := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.fullName.familyname")
	doSession(t, getDisclosureRequest(idRoot), client, nil, nil, nil, nil)

	// Re-open client
	require.NoError(t, client.Close())
	client, handler = parseExistingStorage(t, handler.storage)

	// Test whether credential is still there after the storage has been reloaded
	doSession(t, getDisclosureRequest(idRoot), client, nil, nil, nil, nil)
}

func TestWithoutPairingSupport(t *testing.T) {
	t.Run("TestSigningSession", curry(testSigningSession, nil, optionOldClient))
	t.Run("TestDisclosureSession", curry(testDisclosureSession, nil, optionOldClient))
	t.Run("TestNoAttributeDisclosureSession", curry(testNoAttributeDisclosureSession, nil, optionOldClient))
	t.Run("TestEmptyDisclosure", curry(testEmptyDisclosure, nil, optionOldClient))
	t.Run("TestIssuanceSession", curry(testIssuanceSession, nil, optionOldClient))
	t.Run("TestMultipleIssuanceSession", curry(testMultipleIssuanceSession, nil, optionOldClient))
	t.Run("TestDefaultCredentialValidity", curry(testDefaultCredentialValidity, nil, optionOldClient))
	t.Run("TestIssuanceDisclosureEmptyAttributes", curry(testIssuanceDisclosureEmptyAttributes, nil, optionOldClient))
	t.Run("TestIssuanceOptionalZeroLengthAttributes", curry(testIssuanceOptionalZeroLengthAttributes, nil, optionOldClient))
	t.Run("TestIssuanceOptionalSetAttributes", curry(testIssuanceOptionalSetAttributes, nil, optionOldClient))
	t.Run("TestIssuanceSameAttributesNotSingleton", curry(testIssuanceSameAttributesNotSingleton, nil, optionOldClient))
	t.Run("TestIssuancePairing", curry(testIssuancePairing, nil, optionOldClient))
	t.Run("TestLargeAttribute", curry(testLargeAttribute, nil, optionOldClient))
	t.Run("TestIssuanceSingletonCredential", curry(testIssuanceSingletonCredential, nil, optionOldClient))
	t.Run("TestUnsatisfiableDisclosureSession", curry(testUnsatisfiableDisclosureSession, nil, optionOldClient))
	t.Run("TestAttributeByteEncoding", curry(testAttributeByteEncoding, nil, optionOldClient))
	t.Run("TestIssuedCredentialIsStored", curry(testIssuedCredentialIsStored, nil, optionOldClient))
	t.Run("TestDisablePairing", curry(testDisablePairing, nil, optionOldClient))

	t.Run("TestOutdatedClientIrmaConfiguration", curry(testOutdatedClientIrmaConfiguration, IrmaServerConfiguration, optionOldClient))
	t.Run("TestDisclosureNewAttributeUpdateSchemeManager", curry(testDisclosureNewAttributeUpdateSchemeManager, IrmaServerConfiguration, optionOldClient))

	t.Run("TestStaticQRSession", curry(testStaticQRSession, nil, optionOldClient))
}
