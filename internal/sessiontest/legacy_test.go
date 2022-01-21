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
	t.Run("SigningSession", apply(testSigningSession, nil, optionPrePairingClient))
	t.Run("DisclosureSession", apply(testDisclosureSession, nil, optionPrePairingClient))
	t.Run("NoAttributeDisclosureSession", apply(testNoAttributeDisclosureSession, nil, optionPrePairingClient))
	t.Run("EmptyDisclosure", apply(testEmptyDisclosure, nil, optionPrePairingClient))
	t.Run("IssuanceSession", apply(testIssuanceSession, nil, optionPrePairingClient))
	t.Run("MultipleIssuanceSession", apply(testMultipleIssuanceSession, nil, optionPrePairingClient))
	t.Run("DefaultCredentialValidity", apply(testDefaultCredentialValidity, nil, optionPrePairingClient))
	t.Run("IssuanceDisclosureEmptyAttributes", apply(testIssuanceDisclosureEmptyAttributes, nil, optionPrePairingClient))
	t.Run("IssuanceOptionalZeroLengthAttributes", apply(testIssuanceOptionalZeroLengthAttributes, nil, optionPrePairingClient))
	t.Run("IssuanceOptionalSetAttributes", apply(testIssuanceOptionalSetAttributes, nil, optionPrePairingClient))
	t.Run("IssuanceSameAttributesNotSingleton", apply(testIssuanceSameAttributesNotSingleton, nil, optionPrePairingClient))
	t.Run("IssuancePairing", apply(testIssuancePairing, nil, optionPrePairingClient))
	t.Run("LargeAttribute", apply(testLargeAttribute, nil, optionPrePairingClient))
	t.Run("IssuanceSingletonCredential", apply(testIssuanceSingletonCredential, nil, optionPrePairingClient))
	t.Run("UnsatisfiableDisclosureSession", apply(testUnsatisfiableDisclosureSession, nil, optionPrePairingClient))
	t.Run("AttributeByteEncoding", apply(testAttributeByteEncoding, nil, optionPrePairingClient))
	t.Run("IssuedCredentialIsStored", apply(testIssuedCredentialIsStored, nil, optionPrePairingClient))
	t.Run("DisablePairing", apply(testDisablePairing, nil, optionPrePairingClient))

	t.Run("OutdatedClientIrmaConfiguration", apply(testOutdatedClientIrmaConfiguration, IrmaServerConfiguration, optionPrePairingClient))
	t.Run("DisclosureNewAttributeUpdateSchemeManager", apply(testDisclosureNewAttributeUpdateSchemeManager, IrmaServerConfiguration, optionPrePairingClient))

	t.Run("StaticQRSession", apply(testStaticQRSession, nil, optionPrePairingClient))
}
