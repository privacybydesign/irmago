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
	t.Run("TestSigningSession", curry(testSigningSession, nil, sessionOptionOldClient))
	t.Run("TestDisclosureSession", curry(testDisclosureSession, nil, sessionOptionOldClient))
	t.Run("TestNoAttributeDisclosureSession", curry(testNoAttributeDisclosureSession, nil, sessionOptionOldClient))
	t.Run("TestEmptyDisclosure", curry(testEmptyDisclosure, nil, sessionOptionOldClient))
	t.Run("TestIssuanceSession", curry(testIssuanceSession, nil, sessionOptionOldClient))
	t.Run("TestMultipleIssuanceSession", curry(testMultipleIssuanceSession, nil, sessionOptionOldClient))
	t.Run("TestDefaultCredentialValidity", curry(testDefaultCredentialValidity, nil, sessionOptionOldClient))
	t.Run("TestIssuanceDisclosureEmptyAttributes", curry(testIssuanceDisclosureEmptyAttributes, nil, sessionOptionOldClient))
	t.Run("TestIssuanceOptionalZeroLengthAttributes", curry(testIssuanceOptionalZeroLengthAttributes, nil, sessionOptionOldClient))
	t.Run("TestIssuanceOptionalSetAttributes", curry(testIssuanceOptionalSetAttributes, nil, sessionOptionOldClient))
	t.Run("TestIssuanceSameAttributesNotSingleton", curry(testIssuanceSameAttributesNotSingleton, nil, sessionOptionOldClient))
	t.Run("TestIssuancePairing", curry(testIssuancePairing, nil, sessionOptionOldClient))
	t.Run("TestLargeAttribute", curry(testLargeAttribute, nil, sessionOptionOldClient))
	t.Run("TestIssuanceSingletonCredential", curry(testIssuanceSingletonCredential, nil, sessionOptionOldClient))
	t.Run("TestUnsatisfiableDisclosureSession", curry(testUnsatisfiableDisclosureSession, nil, sessionOptionOldClient))
	t.Run("TestAttributeByteEncoding", curry(testAttributeByteEncoding, nil, sessionOptionOldClient))
	t.Run("TestIssuedCredentialIsStored", curry(testIssuedCredentialIsStored, nil, sessionOptionOldClient))
	t.Run("TestDisablePairing", curry(testDisablePairing, nil, sessionOptionOldClient))

	t.Run("TestOutdatedClientIrmaConfiguration", curry(testOutdatedClientIrmaConfiguration, IrmaLibraryConfiguration, sessionOptionOldClient))
	t.Run("TestDisclosureNewAttributeUpdateSchemeManager", curry(testDisclosureNewAttributeUpdateSchemeManager, IrmaLibraryConfiguration, sessionOptionOldClient))

	t.Run("TestStaticQRSession", curry(testStaticQRSession, nil, sessionOptionOldClient))
}
