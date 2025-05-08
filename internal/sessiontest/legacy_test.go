package sessiontest

import (
	"github.com/privacybydesign/irmago/server/irmaserver"
	"testing"
)

func TestWithoutPairingSupport(t *testing.T) {
	irmaserver.AcceptInsecureProtocolVersions = true
	defer func() { irmaserver.AcceptInsecureProtocolVersions = false }()

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
