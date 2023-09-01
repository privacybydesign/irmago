package sessiontest

/*
This file contains the integration tests for the irmaclient library.
A subset of tests from session_test.go and keyshare_test.go can be run against specific versions of the IRMA server and keyshare server.
In this way we test the backwards compatibility of the irmaclient library.
The other way around, the backwards compatibility of the IRMA server and keyshare server, can be tested by checking out the
source code of an older irmago version and run an older version of this test against a newer server version.
This integration test is being introduced after irmago v0.13.2, so older irmaclient versions cannot be tested using this setup.

This test only runs if you pass IRMAGO_INTEGRATION_TESTS=Y to go test, i.e.: IRMAGO_INTEGRATION_TESTS=Y go test -run TestClientIntegration -p 1 ./...
Before running this test, you should start the IRMA server and keyshare server manually.

First, ensure you installed the desired irma version.
To start the IRMA server, run the following command:
$ irma server -s testdata/irma_configuration --url http://localhost:port -p 48682 -k testdata/privatekeys

To start the keyshare server, run the following commands:
$ docker-compose up -d
$ irma keyshare server -c testdata/configurations/keyshareserver.yml
*/

import (
	"os"
	"strings"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
)

func TestClientIntegration(t *testing.T) {
	if !strings.HasPrefix(strings.ToUpper(os.Getenv("IRMAGO_INTEGRATION_TESTS")), "Y") {
		t.Skip("Set IRMAGO_INTEGRATION_TESTS=Y to run this test")
	}

	// Tests without keyshare server.
	t.Run("DisclosureSession", apply(testDisclosureSession, nil, optionReuseServer, optionForceNoAuth))
	t.Run("NoAttributeDisclosureSession", apply(testNoAttributeDisclosureSession, nil, optionReuseServer, optionForceNoAuth))
	t.Run("EmptyDisclosure", apply(testEmptyDisclosure, nil, optionReuseServer, optionForceNoAuth))
	t.Run("SigningSession", apply(testSigningSession, nil, optionReuseServer, optionForceNoAuth))
	t.Run("IssuanceSession", apply(testIssuanceSession, nil, optionReuseServer, optionForceNoAuth))
	t.Run("MultipleIssuanceSession", apply(testMultipleIssuanceSession, nil, optionReuseServer, optionForceNoAuth))
	t.Run("DefaultCredentialValidity", apply(testDefaultCredentialValidity, nil, optionReuseServer, optionForceNoAuth))
	t.Run("IssuanceDisclosureEmptyAttributes", apply(testIssuanceDisclosureEmptyAttributes, nil, optionReuseServer, optionForceNoAuth))
	t.Run("IssuanceOptionalZeroLengthAttributes", apply(testIssuanceOptionalZeroLengthAttributes, nil, optionReuseServer, optionForceNoAuth))
	t.Run("IssuanceOptionalSetAttributes", apply(testIssuanceOptionalSetAttributes, nil, optionReuseServer, optionForceNoAuth))
	t.Run("IssuanceSameAttributesNotSingleton", apply(testIssuanceSameAttributesNotSingleton, nil, optionReuseServer, optionForceNoAuth))
	t.Run("IssuancePairing", apply(testIssuancePairing, nil, optionReuseServer, optionForceNoAuth))
	t.Run("PairingRejected", apply(testPairingRejected, nil, optionReuseServer, optionForceNoAuth))
	t.Run("LargeAttribute", apply(testLargeAttribute, nil, optionReuseServer, optionForceNoAuth))
	t.Run("IssuanceSingletonCredential", apply(testIssuanceSingletonCredential, nil, optionReuseServer, optionForceNoAuth))
	t.Run("UnsatisfiableDisclosureSession", apply(testUnsatisfiableDisclosureSession, nil, optionReuseServer, optionForceNoAuth))
	t.Run("AttributeByteEncoding", apply(testAttributeByteEncoding, nil, optionReuseServer, optionForceNoAuth))
	t.Run("IssuedCredentialIsStored", apply(testIssuedCredentialIsStored, nil, optionReuseServer, optionForceNoAuth))
	t.Run("BlindIssuanceSession", apply(testBlindIssuanceSession, nil, optionReuseServer, optionForceNoAuth))
	t.Run("DisablePairing", apply(testDisablePairing, nil, optionReuseServer, optionForceNoAuth))
	t.Run("DisclosureMultipleAttrs", apply(testDisclosureMultipleAttrs, nil, optionReuseServer, optionForceNoAuth))
	t.Run("CombinedSessionMultipleAttributes", apply(testCombinedSessionMultipleAttributes, nil, optionReuseServer, optionForceNoAuth))
	t.Run("ConDisCon", apply(testConDisCon, nil, optionReuseServer, optionForceNoAuth))
	t.Run("OptionalDisclosure", apply(testOptionalDisclosure, nil, optionReuseServer, optionForceNoAuth))

	// Test with keyshare server.
	t.Run("KeyshareSessions", func(t *testing.T) {
		storage := test.CreateTestStorage(t)
		client, handler := parseExistingStorage(t, storage)
		defer test.ClearTestStorage(t, client, handler.storage)

		// Fresh irmaclient storage was used, so we need to do some initialization.
		client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
		req := getIssuanceRequest(false)
		doSession(t, req, client, nil, nil, nil, nil, optionReuseServer, optionForceNoAuth)

		keyshareSessions(t, client, nil, optionReuseServer, optionForceNoAuth)
	})
}
