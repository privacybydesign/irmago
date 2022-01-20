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
	t.Run("TestSigningSession", curry(testSigningSession, nil, optionPrePairingClient))
	t.Run("TestDisclosureSession", curry(testDisclosureSession, nil, optionPrePairingClient))
	t.Run("TestNoAttributeDisclosureSession", curry(testNoAttributeDisclosureSession, nil, optionPrePairingClient))
	t.Run("TestEmptyDisclosure", curry(testEmptyDisclosure, nil, optionPrePairingClient))
	t.Run("TestIssuanceSession", curry(testIssuanceSession, nil, optionPrePairingClient))
	t.Run("TestMultipleIssuanceSession", curry(testMultipleIssuanceSession, nil, optionPrePairingClient))
	t.Run("TestDefaultCredentialValidity", curry(testDefaultCredentialValidity, nil, optionPrePairingClient))
	t.Run("TestIssuanceDisclosureEmptyAttributes", curry(testIssuanceDisclosureEmptyAttributes, nil, optionPrePairingClient))
	t.Run("TestIssuanceOptionalZeroLengthAttributes", curry(testIssuanceOptionalZeroLengthAttributes, nil, optionPrePairingClient))
	t.Run("TestIssuanceOptionalSetAttributes", curry(testIssuanceOptionalSetAttributes, nil, optionPrePairingClient))
	t.Run("TestIssuanceSameAttributesNotSingleton", curry(testIssuanceSameAttributesNotSingleton, nil, optionPrePairingClient))
	t.Run("TestIssuancePairing", curry(testIssuancePairing, nil, optionPrePairingClient))
	t.Run("TestLargeAttribute", curry(testLargeAttribute, nil, optionPrePairingClient))
	t.Run("TestIssuanceSingletonCredential", curry(testIssuanceSingletonCredential, nil, optionPrePairingClient))
	t.Run("TestUnsatisfiableDisclosureSession", curry(testUnsatisfiableDisclosureSession, nil, optionPrePairingClient))
	t.Run("TestAttributeByteEncoding", curry(testAttributeByteEncoding, nil, optionPrePairingClient))
	t.Run("TestIssuedCredentialIsStored", curry(testIssuedCredentialIsStored, nil, optionPrePairingClient))
	t.Run("TestDisablePairing", curry(testDisablePairing, nil, optionPrePairingClient))

	t.Run("TestOutdatedClientIrmaConfiguration", curry(testOutdatedClientIrmaConfiguration, IrmaServerConfiguration, optionPrePairingClient))
	t.Run("TestDisclosureNewAttributeUpdateSchemeManager", curry(testDisclosureNewAttributeUpdateSchemeManager, IrmaServerConfiguration, optionPrePairingClient))

	t.Run("TestStaticQRSession", curry(testStaticQRSession, nil, optionPrePairingClient))
}
