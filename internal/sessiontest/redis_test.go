package sessiontest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/stretchr/testify/require"
)

func startRedis(t *testing.T, enableTLS bool) (*miniredis.Miniredis, string) {
	mr := miniredis.NewMiniRedis()

	if !enableTLS {
		require.NoError(t, mr.Start())
		return mr, ""
	}

	// By default, the IRMA server will use the system cert pool. This cannot be unit tested in an acceptable way.
	// Therefore, in the standard Redis tests, we use a generated self-signed certificate.
	certPair, cert := generateCertPair(t)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certPair},
	}
	require.NoError(t, mr.StartTLS(tlsConfig))
	return mr, cert
}

func redisRequestorConfigDecorator(mr *miniredis.Miniredis, cert string, certfile string, fn func() *requestorserver.Configuration) func() *requestorserver.Configuration {
	return func() *requestorserver.Configuration {
		c := fn()
		redisConfigDecorator(mr, cert, certfile, func() *server.Configuration { return c.Configuration })()
		return c
	}
}

func redisConfigDecorator(mr *miniredis.Miniredis, cert string, certfile string, fn func() *server.Configuration) func() *server.Configuration {
	return func() *server.Configuration {
		mr.FlushAll() // Flush Redis memory between different runs of the IRMA server to prevent side effects.
		c := fn()
		c.StoreType = "redis"
		c.RedisSettings = &server.RedisSettings{}
		c.RedisSettings.Addr = mr.Host() + ":" + mr.Port()

		if cert != "" {
			c.RedisSettings.TLSCertificate = cert
		} else if certfile != "" {
			c.RedisSettings.TLSCertificateFile = certfile
		} else {
			c.RedisSettings.DisableTLS = true
		}
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
	// Here and elsewhere when generically testing Redis, we populate the RedisSettings.TLSCertificate field
	// with a generated self-signed certificate.
	mr, cert := startRedis(t, true)
	defer mr.Close()

	t.Run("SigningSession", curry(testSigningSession, redisRequestorConfigDecorator(mr, cert, "", IrmaServerConfiguration)))
	t.Run("DisclosureSession", curry(testDisclosureSession, redisRequestorConfigDecorator(mr, cert, "", IrmaServerConfiguration)))
	t.Run("IssuanceSession", curry(testIssuanceSession, redisRequestorConfigDecorator(mr, cert, "", IrmaServerConfiguration)))
	t.Run("IssuedCredentialIsStored", curry(testIssuedCredentialIsStored, redisRequestorConfigDecorator(mr, cert, "", IrmaServerConfiguration)))

	t.Run("ChainedSessions", curry(testChainedSessions, redisConfigDecorator(mr, cert, "", IrmaLibraryConfiguration)))
	t.Run("UnknownRequestorToken", curry(testUnknownRequestorToken, redisConfigDecorator(mr, cert, "", IrmaLibraryConfiguration)))
}

func TestRedisTLSConfig(t *testing.T) {
	mr, cert := startRedis(t, true)
	defer mr.Close()

	// Check that specifying a certificate for Redis is not allowed when Redis TLS is disabled
	configFunc := redisRequestorConfigDecorator(mr, cert, "", IrmaServerConfiguration)
	config := configFunc()
	config.RedisSettings.DisableTLS = true
	_, err := requestorserver.New(config)
	require.EqualError(t, err, "Redis TLS config failed: Redis TLS cannot be disabled when a Redis TLS certificate is specified.")

	// Check that specifying a path to a certificate for Redis is not allowed when Redis TLS is disabled
	config = configFunc()
	config.RedisSettings.DisableTLS = true
	config.RedisSettings.TLSCertificate = ""
	config.RedisSettings.TLSCertificateFile = "/path/to/cert"
	_, err = requestorserver.New(config)
	require.EqualError(t, err, "Redis TLS config failed: Redis TLS cannot be disabled when a Redis TLS certificate is specified.")

	// Check that specifying both a certificate and a path to a(nother) certificate is not allowed
	config = configFunc()
	config.RedisSettings.TLSCertificateFile = "/path/to/cert"
	_, err = requestorserver.New(config)
	require.EqualError(t, err, "Redis TLS config failed: provide either key or path to key")
}

func TestRedisWithTLSCertFile(t *testing.T) {
	mr, cert := startRedis(t, true)
	defer mr.Close()

	// Write the generated certificate to a temp file so RedisSettings.TLSCertificateFile in the Redis
	// config decorator can be populated with the certfile.
	file, err := os.CreateTemp("", "")
	require.NoError(t, err)
	_, err = file.Write([]byte(cert))
	require.NoError(t, err)
	certfile := file.Name()
	defer func() {
		require.NoError(t, os.Remove(certfile))
	}()

	t.Run("TestDisclosureSession", curry(testDisclosureSession, redisConfigDecorator(mr, "", certfile, IrmaLibraryConfiguration)))
}

func TestRedisWithoutTLS(t *testing.T) {
	mr, _ := startRedis(t, false)
	defer mr.Close()

	t.Run("TestDisclosureSession", curry(testDisclosureSession, redisConfigDecorator(mr, "", "", IrmaLibraryConfiguration)))
}

func checkErrorInternal(t *testing.T, err error) {
	serr, ok := err.(*irma.SessionError)
	require.True(t, ok)
	require.NotNil(t, serr.RemoteError)
	require.Equal(t, server.ErrorInternal.Status, serr.RemoteError.Status)
	require.Equal(t, string(server.ErrorInternal.Type), serr.RemoteError.ErrorName)
}

func checkErrorSessionUnknown(t *testing.T, err error) {
	serr, ok := err.(*irma.SessionError)
	require.True(t, ok)
	require.NotNil(t, serr.RemoteError)
	require.Equal(t, server.ErrorSessionUnknown.Status, serr.RemoteError.Status)
	require.Equal(t, string(server.ErrorSessionUnknown.Type), serr.RemoteError.ErrorName)
}

func TestRedisUpdates(t *testing.T) {
	mr, cert := startRedis(t, true)
	defer mr.Close()

	irmaServer := StartIrmaServer(t, redisConfigDecorator(mr, cert, "", IrmaLibraryConfiguration)())
	defer irmaServer.Stop()
	qr, token, _, err := irmaServer.irma.StartSession(irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
	), nil)
	require.NoError(t, err)

	var o interface{}
	transport := irma.NewHTTPTransport(qr.URL, false)
	transport.SetHeader(irma.MinVersionHeader, "2.5")
	transport.SetHeader(irma.MaxVersionHeader, "2.5")
	clientToken, err := mr.Get("token:" + string(token))
	require.NoError(t, err)

	initialData, _ := mr.Get("session:" + clientToken)
	require.NoError(t, transport.Get("", &o))
	updatedData, _ := mr.Get("session:" + clientToken)
	require.NoError(t, transport.Get("", &o))
	latestData, _ := mr.Get("session:" + clientToken)

	// First Get should update the data stored in Redis
	require.NotEqual(t, updatedData, initialData)
	// Second Get should not update the data stored in Redis
	require.Equal(t, updatedData, latestData)

	// lock session for token
	require.NoError(t, mr.Set("lock:"+clientToken, "bla"))
	defer mr.Del("lock:" + clientToken)

	// try to update locked session
	err = transport.Get("", &o)
	checkErrorInternal(t, err)
}

func TestRedisRedundancy(t *testing.T) {
	mr, cert := startRedis(t, true)
	defer mr.Close()

	ports := []int{48690, 48691, 48692}
	servers := make([]*requestorserver.Server, len(ports))

	for i, port := range ports {
		c := redisRequestorConfigDecorator(mr, cert, "", JwtServerConfiguration)()
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

	doSession(t, request, nil, nil, nil, nil, nil, sessionOptionReuseServer)
}

// Tests whether the right error is returned by the client's Failure handler
func TestRedisSessionFailure(t *testing.T) {
	mr, cert := startRedis(t, true)

	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)

	irmaServer := StartIrmaServer(t, redisConfigDecorator(mr, cert, "", IrmaLibraryConfiguration)())
	defer irmaServer.Stop()
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	qr, _, _, err := irmaServer.irma.StartSession(request, nil)
	require.NoError(t, err)
	qrjson, err := json.Marshal(qr)
	require.NoError(t, err)

	// Stop the Redis server early to check whether the IRMA client fails correctly
	mr.Close()

	clientChan := make(chan *SessionResult)
	h := &TestHandler{t, clientChan, client, nil, 0, "", nil, nil, nil}
	client.NewSession(string(qrjson), h)
	clientResult := <-h.c

	require.Error(t, clientResult.Err)
	serr, ok := clientResult.Err.(*irma.SessionError)
	require.True(t, ok)
	require.Equal(t, server.ErrorInternal.Status, serr.RemoteError.Status)
	require.Equal(t, string(server.ErrorInternal.Type), serr.RemoteError.ErrorName)
}

func TestRedisLibraryErrors(t *testing.T) {
	mr, cert := startRedis(t, true)

	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)

	irmaServer := StartIrmaServer(t, redisConfigDecorator(mr, cert, "", IrmaLibraryConfiguration)())
	defer irmaServer.Stop()

	// Stop the Redis server early to check whether the IRMA server fails correctly
	mr.Close()

	token := irma.RequestorToken("Sxqcpng37mAdBKgoAJXl")

	_, _, _, err := irmaServer.irma.StartSession(request, nil)
	require.Error(t, err)
	_, err = irmaServer.irma.GetSessionResult(token)
	require.Error(t, err)
	err = irmaServer.irma.CancelSession(token)
	require.Error(t, err)
	_, err = irmaServer.irma.GetRequest(token)
	require.Error(t, err)
}

func TestRedisHTTPErrors(t *testing.T) {
	mr, cert := startRedis(t, true)

	config := redisRequestorConfigDecorator(mr, cert, "", JwtServerConfiguration)()
	rs := StartRequestorServer(t, config)
	defer rs.Stop()

	// Stop the Redis server early to check whether the IRMA client fails correctly
	mr.Close()

	url := fmt.Sprintf("http://localhost:%d", config.Port)
	transport := irma.NewHTTPTransport(url, false)
	transport.SetHeader("Authorization", TokenAuthenticationKey)

	// Check error response of POST /session requestor endpoint
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)
	err := transport.Post("session", nil, request)
	checkErrorInternal(t, err)

	// Check error response of requestor endpoints for sessions
	transport.Server += "session/Sxqcpng37mAdBKgoAJXl/"
	err = transport.Get("result", nil)
	checkErrorInternal(t, err)
	err = transport.Get("result-jwt", nil)
	checkErrorInternal(t, err)
	err = transport.Get("getproof", nil)
	checkErrorInternal(t, err)
	err = transport.Get("status", nil)
	checkErrorInternal(t, err)
	// TODO: Check for sse endpoint. We don't know yet whether this will be implemented for Redis.

	// Check error response of irma endpoints
	transport.Server = strings.Replace(transport.Server, "/session/", "/irma/session/", 1)
	err = transport.Post("", nil, struct{}{})
	checkErrorInternal(t, err)
	err = transport.Delete()
	checkErrorInternal(t, err)
	err = transport.Post("commitments", nil, struct{}{})
	checkErrorInternal(t, err)
	err = transport.Post("proofs", nil, struct{}{})
	checkErrorInternal(t, err)
	err = transport.Get("status", nil)
	checkErrorInternal(t, err)
	// TODO: Check for sse endpoint. We don't know yet whether this will be implemented for Redis.
}

func generateCertPair(t *testing.T) (tls.Certificate, string) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"IRMA"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certOut := &bytes.Buffer{}
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))

	keyOut := &bytes.Buffer{}
	b, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))

	certPEM := certOut.Bytes()
	certPair, err := tls.X509KeyPair(certPEM, keyOut.Bytes())
	require.NoError(t, err)

	return certPair, string(certPEM)
}
