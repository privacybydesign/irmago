package sessiontest

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/privacybydesign/irmago/server/requestorserver"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

type (
	option int

	stopper interface {
		Stop()
	}

	sessionHandler interface {
		irmaclient.Handler

		// SetClientTransport sets the transport used by the client (required by pairing tests).
		SetClientTransport(*irma.HTTPTransport)
	}

	requestorSessionResult struct {
		*server.SessionResult
		clientResult *SessionResult
		Missing      [][]irmaclient.DisclosureCandidates
		Dismisser    irmaclient.SessionDismisser
	}
)

const (
	optionUnsatisfiableRequest option = 1 << iota
	optionRetryPost
	optionIgnoreError
	optionReuseServer
	optionClientWait
	optionWait
	optionPrePairingClient
)

func processOptions(options ...option) option {
	var opts option = 0
	for _, o := range options {
		opts |= o
	}
	return opts
}

func (o option) enabled(opt option) bool {
	return o&opt > 0
}

// startServer ensures that an IRMA server or library is running, if and when required, as specified
// by the parameters:
// - If irmaServer is not nil or optionReuseServer is enabled, this function does nothing.
// - Otherwise an IRMA server or library is started, depending on the type of conf.
func startServer(t *testing.T, opts option, irmaServer *IrmaServer, conf interface{}) (stopper, interface{}, bool) {
	if irmaServer != nil {
		if opts.enabled(optionReuseServer) {
			require.FailNow(t, "either specify irmaServer or optionReuseServer, not both")
			return nil, nil, false
		}
		if conf != nil {
			require.FailNow(t, "either specify irmaServer or conf, not both")
			return nil, nil, false
		}
		return irmaServer, nil, false
	}
	if opts.enabled(optionReuseServer) {
		return nil, nil, false
	}

	switch typedConf := conf.(type) {
	case func() *server.Configuration:
		c := typedConf()
		irmaServer = StartIrmaServer(t, c)
		return irmaServer, c, true
	case func() *requestorserver.Configuration:
		c := typedConf()
		rs := StartRequestorServer(t, c)
		return rs, c, true
	default:
		c := RequestorServerAuthConfiguration()
		rs := StartRequestorServer(t, c)
		return rs, c, true
	}
}

// startSessionAtServer starts an IRMA session using the specified session request, against an IRMA server
// or library, as determined by the type of serv.
func startSessionAtServer(t *testing.T, serv stopper, conf interface{}, request interface{}) *server.SessionPackage {
	switch s := serv.(type) {
	case *IrmaServer:
		qr, requestorToken, frontendRequest, err := s.irma.StartSession(request, nil)
		require.NoError(t, err)
		return &server.SessionPackage{
			SessionPtr:      qr,
			Token:           requestorToken,
			FrontendRequest: frontendRequest,
		}
	default:
		var (
			sesPkg  server.SessionPackage
			err     error
			useJWTs bool
		)
		if conf != nil {
			useJWTs = !conf.(*requestorserver.Configuration).DisableRequestorAuthentication
		} else {
			useJWTs = true
		}
		url := "http://localhost:48682"
		if useJWTs {
			skbts, err := ioutil.ReadFile(filepath.Join(testdata, "jwtkeys", "requestor1-sk.pem"))
			require.NoError(t, err)
			sk, err := jwt.ParseRSAPrivateKeyFromPEM(skbts)
			require.NoError(t, err)
			j, err := irma.SignSessionRequest(request.(irma.SessionRequest), jwt.SigningMethodRS256, sk, "requestor1")
			require.NoError(t, err)
			err = irma.NewHTTPTransport(url, false).Post("session", &sesPkg, j)
			require.NoError(t, err)
		} else {
			err = irma.NewHTTPTransport(url, false).Post("session", &sesPkg, request)
		}
		require.NoError(t, err)
		return &sesPkg
	}
}

func startSessionAtClient(t *testing.T, sesPkg *server.SessionPackage, client *irmaclient.Client, sessionHandler sessionHandler) (*irma.HTTPTransport, irmaclient.SessionDismisser) {
	j, err := json.Marshal(sesPkg.SessionPtr)
	require.NoError(t, err)
	dismisser := client.NewSession(string(j), sessionHandler)
	clientTransport := extractClientTransport(dismisser)
	sessionHandler.SetClientTransport(clientTransport)
	return clientTransport, dismisser
}

// getSessionResult retrieves the session result from the IRMA server or library.
func getSessionResult(t *testing.T, sesPkg *server.SessionPackage, serv stopper, opts option) *server.SessionResult {
	if opts.enabled(optionWait) {
		require.IsType(t, &IrmaServer{}, serv)
		waitSessionFinished(t, serv.(*IrmaServer).irma, sesPkg.Token)
	} else {
		// wait for server to finish processing the session
		time.Sleep(100 * time.Millisecond)
	}

	switch s := serv.(type) {
	case *IrmaServer:
		result, err := s.irma.GetSessionResult(sesPkg.Token)
		require.NoError(t, err)
		return result
	default:
		var res string
		err := irma.NewHTTPTransport("http://localhost:48682/session/"+string(sesPkg.Token), false).Get("result-jwt", &res)
		require.NoError(t, err)

		bts, err := ioutil.ReadFile(jwtPrivkeyPath)
		require.NoError(t, err)
		sk, err := jwt.ParseRSAPrivateKeyFromPEM(bts)
		require.NoError(t, err)

		// Validate JWT
		claims := struct {
			jwt.StandardClaims
			*server.SessionResult
		}{}
		_, err = jwt.ParseWithClaims(res, &claims, func(_ *jwt.Token) (interface{}, error) {
			return &sk.PublicKey, nil
		})
		require.NoError(t, err)

		// Check default expiration time
		require.True(t, claims.IssuedAt+irma.DefaultJwtValidity == claims.ExpiresAt)
		return claims.SessionResult
	}
}

func createSessionHandler(
	t *testing.T,
	opts option,
	client *irmaclient.Client,
	sesPkg *server.SessionPackage,
	frontendOptionsHandler func(handler *TestHandler),
	pairingHandler func(handler *TestHandler),
) (sessionHandler, chan *SessionResult) {
	clientChan := make(chan *SessionResult, 2)
	requestor := expectedRequestorInfo(t, client.Configuration)
	handler := TestHandler{t: t, c: clientChan, client: client, expectedServerName: requestor}
	if opts.enabled(optionUnsatisfiableRequest) {
		return &UnsatisfiableTestHandler{TestHandler: handler}, clientChan
	}

	if frontendOptionsHandler != nil || pairingHandler != nil {
		handler.pairingCodeChan = make(chan string)
		handler.frontendTransport = irma.NewHTTPTransport(sesPkg.SessionPtr.URL, false)
		handler.frontendTransport.SetHeader(irma.AuthorizationHeader, string(sesPkg.FrontendRequest.Authorization))
	}
	if opts.enabled(optionClientWait) {
		handler.wait = 2 * time.Second
	}
	return &handler, clientChan
}

func waitSessionFinished(t *testing.T, irmaServer *irmaserver.Server, token irma.RequestorToken) *server.SessionResult {
	for {
		res, err := irmaServer.GetSessionResult(token)
		require.NoError(t, err)
		if res.Status.Finished() {
			return res
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// doSession performs an IRMA session using the specified session request.
//
// It uses the specified client if specified, otherwise it creates one.
//
// The request is run against an IRMA server or library, as follows:
//   - irmaServer is used if not nil.
//   - If optionReuseServer is specified, irmaServer must be nil and the request is run
//     against an IRMA server which is expected to be already running.
//   - Otherwise, an IRMA server or library is created and used, depending on whether the config
//     parameter is of type func() *server.Configuration or func() *requestorserver.Configuration
func doSession(
	t *testing.T,
	request interface{},
	client *irmaclient.Client,
	irmaServer *IrmaServer,
	frontendOptionsHandler func(handler *TestHandler),
	pairingHandler func(handler *TestHandler),
	config interface{},
	options ...option,
) *requestorSessionResult {
	if client == nil {
		var handler *TestClientHandler
		client, handler = parseStorage(t, options...)
		defer test.ClearTestStorage(t, handler.storage)
	}

	opts := processOptions(options...)
	serv, conf, shouldStop := startServer(t, opts, irmaServer, config)
	if shouldStop {
		defer serv.Stop()
	}

	sesPkg := startSessionAtServer(t, serv, conf, request)
	sessionHandler, clientChan := createSessionHandler(t, opts, client, sesPkg, frontendOptionsHandler, pairingHandler)

	if frontendOptionsHandler != nil {
		frontendOptionsHandler(sessionHandler.(*TestHandler))
	}

	clientTransport, dismisser := startSessionAtClient(t, sesPkg, client, sessionHandler)

	if pairingHandler != nil {
		pairingHandler(sessionHandler.(*TestHandler))
	}

	clientResult := <-clientChan
	if !opts.enabled(optionIgnoreError) && clientResult != nil {
		require.NoError(t, clientResult.Err)
	}

	if opts.enabled(optionUnsatisfiableRequest) && !opts.enabled(optionWait) {
		require.NotNil(t, clientResult)
		return &requestorSessionResult{nil, nil, clientResult.Missing, dismisser}
	}

	serverResult := getSessionResult(t, sesPkg, serv, opts)
	require.Equal(t, sesPkg.Token, serverResult.Token)

	if opts.enabled(optionRetryPost) {
		var result string
		err := clientTransport.Post("proofs", &result, sessionHandler.(*TestHandler).result)
		require.NoError(t, err)
	}

	return &requestorSessionResult{serverResult, clientResult, nil, dismisser}
}
