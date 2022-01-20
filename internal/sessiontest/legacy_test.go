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
	t.Run("SigningSession", curry(testSigningSession, nil, optionPrePairingClient))
	t.Run("DisclosureSession", curry(testDisclosureSession, nil, optionPrePairingClient))
	t.Run("NoAttributeDisclosureSession", curry(testNoAttributeDisclosureSession, nil, optionPrePairingClient))
	t.Run("EmptyDisclosure", curry(testEmptyDisclosure, nil, optionPrePairingClient))
	t.Run("IssuanceSession", curry(testIssuanceSession, nil, optionPrePairingClient))
	t.Run("MultipleIssuanceSession", curry(testMultipleIssuanceSession, nil, optionPrePairingClient))
	t.Run("DefaultCredentialValidity", curry(testDefaultCredentialValidity, nil, optionPrePairingClient))
	t.Run("IssuanceDisclosureEmptyAttributes", curry(testIssuanceDisclosureEmptyAttributes, nil, optionPrePairingClient))
	t.Run("IssuanceOptionalZeroLengthAttributes", curry(testIssuanceOptionalZeroLengthAttributes, nil, optionPrePairingClient))
	t.Run("IssuanceOptionalSetAttributes", curry(testIssuanceOptionalSetAttributes, nil, optionPrePairingClient))
	t.Run("IssuanceSameAttributesNotSingleton", curry(testIssuanceSameAttributesNotSingleton, nil, optionPrePairingClient))
	t.Run("IssuancePairing", curry(testIssuancePairing, nil, optionPrePairingClient))
	t.Run("LargeAttribute", curry(testLargeAttribute, nil, optionPrePairingClient))
	t.Run("IssuanceSingletonCredential", curry(testIssuanceSingletonCredential, nil, optionPrePairingClient))
	t.Run("UnsatisfiableDisclosureSession", curry(testUnsatisfiableDisclosureSession, nil, optionPrePairingClient))
	t.Run("AttributeByteEncoding", curry(testAttributeByteEncoding, nil, optionPrePairingClient))
	t.Run("IssuedCredentialIsStored", curry(testIssuedCredentialIsStored, nil, optionPrePairingClient))
	t.Run("DisablePairing", curry(testDisablePairing, nil, optionPrePairingClient))

	t.Run("OutdatedClientIrmaConfiguration", curry(testOutdatedClientIrmaConfiguration, IrmaServerConfiguration, optionPrePairingClient))
	t.Run("DisclosureNewAttributeUpdateSchemeManager", curry(testDisclosureNewAttributeUpdateSchemeManager, IrmaServerConfiguration, optionPrePairingClient))

	t.Run("StaticQRSession", curry(testStaticQRSession, nil, optionPrePairingClient))
}
