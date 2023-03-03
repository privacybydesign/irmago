package sessiontest

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-errors/errors"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
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
		clientResult         *SessionResult
		clientResultExtended *server.SessionResultExtended
		Missing              [][]irmaclient.DisclosureCandidates
		Dismisser            irmaclient.SessionDismisser
	}
)

const (
	optionUnsatisfiableRequest option = 1 << iota
	optionRetryPost
	optionIgnoreError
	optionReuseServer // makes doSession assume a requestor server with authentication is used
	optionClientWait
	optionWait
	optionPrePairingClient
	optionPolling
	optionNoSchemeAssets
	optionGetResultExtended
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
		}
		if conf != nil {
			require.FailNow(t, "either specify irmaServer or conf, not both")
		}
		return irmaServer, nil, false
	}
	if opts.enabled(optionReuseServer) {
		if conf != nil {
			require.FailNow(t, "either specify optionReuseServer or conf, not both")
		}
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
		url := requestorServerURL
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
	waitSessionFinished(t, serv, sesPkg.Token, opts.enabled(optionWait))

	switch s := serv.(type) {
	case *IrmaServer:
		result, err := s.irma.GetSessionResult(sesPkg.Token)
		require.NoError(t, err)
		return result
	default:
		var res string
		err := irma.NewHTTPTransport(requestorServerURL+"/session/"+string(sesPkg.Token), false).Get("result-jwt", &res)
		require.NoError(t, err)

		bts, err := ioutil.ReadFile(jwtPrivkeyPath)
		require.NoError(t, err)
		sk, err := jwt.ParseRSAPrivateKeyFromPEM(bts)
		require.NoError(t, err)

		// Validate JWT
		claims := struct {
			jwt.RegisteredClaims
			*server.SessionResult
		}{}
		_, err = jwt.ParseWithClaims(res, &claims, func(_ *jwt.Token) (interface{}, error) {
			return &sk.PublicKey, nil
		})
		require.NoError(t, err)

		// Check default expiration time
		require.True(t, claims.IssuedAt.Add(irma.DefaultJwtValidity*time.Second).Equal(claims.ExpiresAt.Time))
		return claims.SessionResult
	}
}

// getSessionResult retrieves the session result from the IRMA server or library.
func getSessionResultExtended(t *testing.T, sesPkg *server.SessionPackage, serv stopper, opts option) *server.SessionResultExtended {
	waitSessionFinished(t, serv, sesPkg.Token, opts.enabled(optionWait))

	switch s := serv.(type) {
	case *IrmaServer:
		result, err := s.irma.GetSessionResultExtended(sesPkg.Token)
		require.NoError(t, err)
		return result
	default:
		var res string
		err := irma.NewHTTPTransport(requestorServerURL+"/session/"+string(sesPkg.Token), false).Get("result-extended", &res)
		require.NoError(t, err)

		clientResultExtended := &server.SessionResultExtended{}
		err = json.Unmarshal([]byte(res), clientResultExtended)
		require.NoError(t, err)

		return clientResultExtended
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

func waitSessionFinished(t *testing.T, serv interface{}, token irma.RequestorToken, longRunning bool) {
	if !longRunning {
		// wait a bit so that server can finish processing the session
		time.Sleep(100 * time.Millisecond)
		return
	}

	require.IsType(t, &IrmaServer{}, serv)
	irmaServer := serv.(*IrmaServer).irma
	for {
		res, err := irmaServer.GetSessionResult(token)
		require.NoError(t, err)
		if res.Status.Finished() {
			return
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
		defer test.ClearTestStorage(t, client, handler.storage)
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

	if opts.enabled(optionPolling) {
		// Some tests may want to enable polling. We reuse the waitSessionFinished() function for
		// this, which does its job by polling the GetSessionResult() function.
		go func() { waitSessionFinished(t, serv, sesPkg.Token, true) }()
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
		return &requestorSessionResult{nil, nil, nil, clientResult.Missing, dismisser}
	}

	serverResult := getSessionResult(t, sesPkg, serv, opts)
	require.Equal(t, sesPkg.Token, serverResult.Token)

	if opts.enabled(optionRetryPost) {
		var result string
		err := clientTransport.Post("proofs", &result, sessionHandler.(*TestHandler).result)
		require.NoError(t, err)
	}

	if opts.enabled(optionGetResultExtended) {
		clientResultExtended := getSessionResultExtended(t, sesPkg, serv, opts)
		return &requestorSessionResult{serverResult, clientResult, clientResultExtended, nil, dismisser}
	}

	return &requestorSessionResult{serverResult, clientResult, nil, nil, dismisser}
}

func doChainedSessions(
	t *testing.T, conf interface{}, id irma.AttributeTypeIdentifier, cred irma.CredentialTypeIdentifier, opts ...option,
) {
	client, handler := parseStorage(t, opts...)
	defer test.ClearTestStorage(t, client, handler.storage)

	require.IsType(t, IrmaServerConfiguration, conf)
	irmaServer := StartIrmaServer(t, conf.(func() *server.Configuration)())
	defer irmaServer.Stop()
	nextServer := StartNextRequestServer(t, irmaServer.conf, id, cred)
	defer func() {
		_ = nextServer.Close()
	}()

	var request irma.ServiceProviderRequest
	require.NoError(t, irma.NewHTTPTransport(nextSessionServerURL, false).Get("1", &request))

	// In case of chained sessions, the server's session store is queried twice in a single
	// HTTP handler (when processing the irmaclient's response). The mutexes involved have caused
	// deadlocks in the past when the frontend polls the session status, so we simulate polling in
	// this test.
	doSession(t, &request, client, irmaServer, nil, nil, nil, append(opts, optionPolling)...)

	// check that we have a new credential
	for _, cred := range client.CredentialInfoList() {
		if cred.SignedOn.After(irma.Timestamp(time.Now().Add(-1 * irma.ExpiryFactor * time.Second))) {
			return
		}
	}

	require.NoError(t, errors.New("newly issued credential not found in client"))
}
