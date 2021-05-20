package sessiontest

import (
	"encoding/json"
	"fmt"
	"github.com/alicebob/miniredis"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func startRedis(t *testing.T) *miniredis.Miniredis {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	return mr
}

func redisConfigDecorator(mr *miniredis.Miniredis, fn func() *requestorserver.Configuration) func() *requestorserver.Configuration {
	return func() *requestorserver.Configuration {
		mr.FlushAll() // Flush Redis memory between different runs of the IRMA server to prevent side effects.
		c := fn()
		c.StoreType = "redis"
		c.RedisSettings = &server.RedisSettings{}
		c.RedisSettings.Addr = mr.Host() + ":" + mr.Port()
		return c
	}
}

type DummyLoadBalancer struct {
	sync.Mutex
	t           *testing.T
	irmaServers []int
	index       int
}

func (lb *DummyLoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	lb.Lock()

	// Replace URL with URL of IRMA server
	port := lb.irmaServers[lb.index]
	relayURL := fmt.Sprintf("http://localhost:%d%s", port, r.URL.Path)

	// Send the request to the IRMA server
	relayReq, err := http.NewRequest(r.Method, relayURL, r.Body)
	require.NoError(lb.t, err)
	relayReq.Header = r.Header.Clone()
	relayResp, err := http.DefaultClient.Do(relayReq)
	require.NoError(lb.t, err)

	// Write the IRMA server response to our response writer
	w.WriteHeader(relayResp.StatusCode)
	_, err = io.Copy(w, relayResp.Body)
	require.NoError(lb.t, err)
	for key, values := range relayResp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	err = relayResp.Body.Close()
	require.NoError(lb.t, err)

	// Make sure next IRMA server receives the next request
	lb.index = (lb.index + 1) % len(lb.irmaServers)
	lb.Unlock()
}

func startLoadBalancer(t *testing.T, irmaServers []int) *http.Server {
	lb := &http.Server{
		Addr:    "localhost:48682",
		Handler: &DummyLoadBalancer{t: t, irmaServers: irmaServers, index: 0},
	}
	go func() {
		_ = lb.ListenAndServe()
	}()
	return lb
}

func TestRedis(t *testing.T) {
	// TODO: Consider whether it is necessary to execute all tests against Redis storage
	defaultIrmaServerConfiguration := IrmaServerConfiguration
	defaultJwtServerConfiguration := JwtServerConfiguration

	mr := startRedis(t)
	IrmaServerConfiguration = redisConfigDecorator(mr, IrmaServerConfiguration)
	JwtServerConfiguration = redisConfigDecorator(mr, JwtServerConfiguration)
	defer func() {
		mr.Close()
		IrmaServerConfiguration = defaultIrmaServerConfiguration
		JwtServerConfiguration = defaultJwtServerConfiguration
	}()

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

func TestRedisRedundancy(t *testing.T) {
	mr := startRedis(t)
	defer mr.Close()

	ports := []int{48690, 48691, 48692}
	servers := make([]*requestorserver.Server, len(ports))

	for i, port := range ports {
		c := redisConfigDecorator(mr, IrmaServerConfiguration)()
		c.Configuration.URL = fmt.Sprintf("http://localhost:%d/irma", port)
		c.Port = port
		rs := StartRequestorServer(t, c)
		servers[i] = rs
	}
	lb := startLoadBalancer(t, ports)
	defer func() {
		err := lb.Close()
		require.NoError(t, err)
		for _, s := range servers {
			s.Stop()
		}
	}()

	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)

	sessionHelperWithConfig(t, request, "verification", nil, nil)
}

// Tests whether the right error is returned by the client's Failure handler
func TestRedisSessionFailure(t *testing.T) {
	mr := startRedis(t)

	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)

	// Make sure Redis is used in the IrmaServerConfiguration
	defaultIrmaServerConfiguration := IrmaServerConfiguration
	IrmaServerConfiguration = redisConfigDecorator(mr, IrmaServerConfiguration)
	defer func() {
		IrmaServerConfiguration = defaultIrmaServerConfiguration
	}()

	StartIrmaServer(t, false, "")
	defer StopIrmaServer()
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	qr, _, err := irmaServer.StartSession(request, nil)
	require.NoError(t, err)
	qrjson, err := json.Marshal(qr)
	require.NoError(t, err)

	// Stop the Redis server early to check whether the IRMA client fails correctly
	mr.Close()

	clientChan := make(chan *SessionResult)
	h := &TestHandler{t, clientChan, client, nil, 0, ""}
	client.NewSession(string(qrjson), h)
	clientResult := <-h.c

	require.Error(t, clientResult.Err)
	serr, ok := clientResult.Err.(*irma.SessionError)
	require.True(t, ok)
	require.Equal(t, server.ErrorInternal.Status, serr.RemoteError.Status)
	require.Equal(t, string(server.ErrorInternal.Type), serr.RemoteError.ErrorName)
}

func TestRedisLibraryErrors(t *testing.T) {
	mr := startRedis(t)

	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)

	// Make sure Redis is used in the IrmaServerConfiguration
	defaultIrmaServerConfiguration := IrmaServerConfiguration
	IrmaServerConfiguration = redisConfigDecorator(mr, IrmaServerConfiguration)
	defer func() {
		IrmaServerConfiguration = defaultIrmaServerConfiguration
	}()

	StartIrmaServer(t, false, "")
	defer StopIrmaServer()

	// Stop the Redis server early to check whether the IRMA server fails correctly
	mr.Close()

	token := "Sxqcpng37mAdBKgoAJXl"

	_, _, err := irmaServer.StartSession(request, nil)
	require.Error(t, err)
	_, err = irmaServer.GetSessionResult(token)
	require.Error(t, err)
	err = irmaServer.CancelSession(token)
	require.Error(t, err)
	_, err = irmaServer.GetRequest(token)
	require.Error(t, err)
}

func TestRedisHTTPErrors(t *testing.T) {
	mr := startRedis(t)

	config := redisConfigDecorator(mr, JwtServerConfiguration)()
	rs := StartRequestorServer(t, config)
	defer rs.Stop()

	// Stop the Redis server early to check whether the IRMA client fails correctly
	mr.Close()

	checkError := func(err error) {
		serr, ok := err.(*irma.SessionError)
		require.True(t, ok)
		require.NotNil(t, serr.RemoteError)
		require.Equal(t, server.ErrorInternal.Status, serr.RemoteError.Status)
		require.Equal(t, string(server.ErrorInternal.Type), serr.RemoteError.ErrorName)
	}

	url := fmt.Sprintf("http://localhost:%d", config.Port)
	transport := irma.NewHTTPTransport(url, false)
	transport.SetHeader("Authorization", TokenAuthenticationKey)

	// Check error response of POST /session requestor endpoint
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)
	err := transport.Post("session", nil, request)
	checkError(err)

	// Check error response of requestor endpoints for sessions
	transport.Server += "session/Sxqcpng37mAdBKgoAJXl/"
	err = transport.Get("result", nil)
	checkError(err)
	err = transport.Get("result-jwt", nil)
	checkError(err)
	err = transport.Get("getproof", nil)
	checkError(err)
	err = transport.Get("status", nil)
	checkError(err)
	// TODO: Check for sse endpoint. We don't know yet whether this will be implemented for Redis.

	// Check error response of irma endpoints
	transport.Server = strings.Replace(transport.Server, "/session/", "/irma/session/", 1)
	err = transport.Post("", nil, struct{}{})
	checkError(err)
	err = transport.Delete()
	checkError(err)
	err = transport.Post("commitments", nil, struct{}{})
	checkError(err)
	err = transport.Post("proofs", nil, struct{}{})
	checkError(err)
	err = transport.Get("status", nil)
	checkError(err)
	// TODO: Check for sse endpoint. We don't know yet whether this will be implemented for Redis.
}
