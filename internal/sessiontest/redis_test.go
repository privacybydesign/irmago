package sessiontest

import (
	"encoding/json"
	"github.com/alicebob/miniredis"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/require"
	"testing"
)

func startRedis(t *testing.T) *miniredis.Miniredis {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	testConfigurationHandler = func(c *server.Configuration) {
		mr.FlushAll() // Flush Redis memory between different runs of the IRMA server to prevent side effects.
		c.StoreType = "redis"
		c.RedisSettings = &server.RedisSettings{}
		c.RedisSettings.Addr = mr.Host() + ":" + mr.Port()
	}
	return mr
}

func stopRedis(mr *miniredis.Miniredis) {
	testConfigurationHandler = defaultTestConfiguration
	mr.Close()
}

func TestRedis(t *testing.T) {
	mr := startRedis(t)
	defer stopRedis(mr)

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
	t.Run("TestUnknownRequestorToken", TestUnknownRequestorToken)
}

func TestRedisFailingOnStart(t *testing.T) {
	mr := startRedis(t)

	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)

	StartIrmaServer(t, false, "")
	defer StopIrmaServer()

	// Stop the Redis server early to check whether the IRMA server fails correctly
	stopRedis(mr)

	_, _, err := irmaServer.StartSession(request, nil)
	require.Error(t, err)
}

func TestRedisFailingInSession(t *testing.T) {
	mr := startRedis(t)

	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)

	StartIrmaServer(t, false, "")
	defer StopIrmaServer()
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	qr, token, err := irmaServer.StartSession(request, nil)
	require.NoError(t, err)
	qrjson, err := json.Marshal(qr)
	require.NoError(t, err)

	// Stop the Redis server early to check whether the IRMA client fails correctly
	stopRedis(mr)

	clientChan := make(chan *SessionResult)
	h := &TestHandler{t, clientChan, client, nil, 0, ""}
	client.NewSession(string(qrjson), h)
	clientResult := <-h.c
	require.Error(t, clientResult.Err)
	_, err = irmaServer.GetSessionResult(token)
	require.Error(t, err)
}

// TODO: Add test(s) with 2 IRMA servers and Redis; maybe including some nasty corner cases
