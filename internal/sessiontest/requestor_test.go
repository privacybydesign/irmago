package sessiontest

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/privacybydesign/irmago/server/requestorserver"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

// TODO: restructure files:
// - all test helper code (doSession & friends) to one file
// - all configurable tests to one file
// - all normal tests to one file
// - decide where the rest of the infrastructure goes (server starting, configuration, the rest)

type (
	// TODO rename to option? (including constants)
	sessionOption int

	// TODO rename to stopper
	stoppable interface {
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
	sessionOptionUnsatisfiableRequest sessionOption = 1 << iota
	sessionOptionRetryPost
	sessionOptionIgnoreError
	sessionOptionReuseServer
	sessionOptionClientWait
	sessionOptionWait
	sessionOptionOldClient
)

func processOptions(options ...sessionOption) sessionOption {
	var opts sessionOption = 0
	for _, o := range options {
		opts |= o
	}
	return opts
}

func (o sessionOption) enabled(opt sessionOption) bool {
	return o&opt > 0
}

// startServer ensures that an IRMA server or library is running, if and when required, as specified
// by the parameters:
// - If irmaServer is not nil or sessionOptionReuseServer is enabled, this function does nothing.
// - Otherwise an IRMA server or library is started, depending on the type of conf.
func startServer(t *testing.T, opts sessionOption, irmaServer *IrmaServer, conf interface{}) (stoppable, interface{}, bool) {
	if irmaServer != nil {
		if opts.enabled(sessionOptionReuseServer) {
			require.FailNow(t, "either specify irmaServer or sessionOptionReuseServer")
			return nil, nil, false
		}
		if conf != nil {
			require.FailNow(t, "either specify irmaServer or conf")
			return nil, nil, false
		}
		return irmaServer, nil, false
	}
	if opts.enabled(sessionOptionReuseServer) {
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
		c := JwtServerConfiguration()
		rs := StartRequestorServer(t, c)
		return rs, c, true
	}
}

// startSession starts an IRMA session using the specified session request, against an IRMA server
// or library, as determined by the type of serv.
func startSession(t *testing.T, serv stoppable, conf interface{}, request interface{}) *server.SessionPackage {
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
		} else {
			err = irma.NewHTTPTransport(url, false).Post("session", &sesPkg, request)
		}
		require.NoError(t, err)
		return &sesPkg
	}
}

// getSessionResult retrieves the session result from the IRMA server or library.
func getSessionResult(t *testing.T, sesPkg *server.SessionPackage, serv stoppable, opts sessionOption) *server.SessionResult {
	if opts.enabled(sessionOptionWait) {
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
	opts sessionOption,
	client *irmaclient.Client,
	sesPkg *server.SessionPackage,
	frontendOptionsHandler func(handler *TestHandler),
	pairingHandler func(handler *TestHandler),
) (sessionHandler, chan *SessionResult) {
	clientChan := make(chan *SessionResult, 2)
	requestor := expectedRequestorInfo(t, client.Configuration)
	handler := TestHandler{t: t, c: clientChan, client: client, expectedServerName: requestor}
	if opts.enabled(sessionOptionUnsatisfiableRequest) {
		return &UnsatisfiableTestHandler{TestHandler: handler}, clientChan
	}

	if frontendOptionsHandler != nil || pairingHandler != nil {
		handler.pairingCodeChan = make(chan string)
		handler.frontendTransport = irma.NewHTTPTransport(sesPkg.SessionPtr.URL, false)
		handler.frontendTransport.SetHeader(irma.AuthorizationHeader, string(sesPkg.FrontendRequest.Authorization))
	}
	if opts.enabled(sessionOptionClientWait) {
		handler.wait = 2 * time.Second
	}
	return &handler, clientChan
}

// doSession performs an IRMA session using the specified session request.
//
// It uses the specified client if specified, otherwise it creates one.
//
// The request is run against an IRMA server or library, as follows:
//   - irmaServer is used if not nil.
//   - If sessionOptionReuseServer is specified, irmaServer must be nil and the request is run
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
	options ...sessionOption,
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

	sesPkg := startSession(t, serv, conf, request)
	sessionHandler, clientChan := createSessionHandler(t, opts, client, sesPkg, frontendOptionsHandler, pairingHandler)
	if frontendOptionsHandler != nil {
		frontendOptionsHandler(sessionHandler.(*TestHandler))
	}

	j, err := json.Marshal(sesPkg.SessionPtr)
	require.NoError(t, err)
	dismisser := client.NewSession(string(j), sessionHandler)
	clientTransport := extractClientTransport(dismisser)
	sessionHandler.SetClientTransport(clientTransport)

	if pairingHandler != nil {
		pairingHandler(sessionHandler.(*TestHandler))
	}

	clientResult := <-clientChan
	if !opts.enabled(sessionOptionIgnoreError) && clientResult != nil {
		require.NoError(t, clientResult.Err)
	}

	if opts.enabled(sessionOptionUnsatisfiableRequest) && !opts.enabled(sessionOptionWait) {
		require.NotNil(t, clientResult)
		return &requestorSessionResult{nil, nil, clientResult.Missing, dismisser}
	}

	serverResult := getSessionResult(t, sesPkg, serv, opts)
	require.Equal(t, sesPkg.Token, serverResult.Token)

	if opts.enabled(sessionOptionRetryPost) {
		var result string
		err := clientTransport.Post("proofs", &result, sessionHandler.(*TestHandler).result)
		require.NoError(t, err)
	}

	return &requestorSessionResult{serverResult, clientResult, nil, dismisser}
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

// Check that nonexistent IRMA identifiers in the session request fail the session
func TestInvalidRequest(t *testing.T) {
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()
	_, _, _, err := irmaServer.irma.StartSession(irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.foo.bar"),
		irma.NewAttributeTypeIdentifier("irma-demo.baz.qux.abc"),
	), nil)
	require.Error(t, err)
}

func TestDoubleGET(t *testing.T) {
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()
	qr, _, _, err := irmaServer.irma.StartSession(irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
	), nil)
	require.NoError(t, err)

	// Simulate the first GET by the client in the session protocol, twice
	var o interface{}
	transport := irma.NewHTTPTransport(qr.URL, false)
	transport.SetHeader(irma.MinVersionHeader, "2.5")
	transport.SetHeader(irma.MaxVersionHeader, "2.5")
	require.NoError(t, transport.Get("", &o))
	require.NoError(t, transport.Get("", &o))
}

func testSigningSession(t *testing.T, conf interface{}, opts ...sessionOption) {
	client, handler := parseStorage(t, opts...)
	defer test.ClearTestStorage(t, handler.storage)
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	var serverResult *requestorSessionResult
	for _, opt := range []sessionOption{0, sessionOptionRetryPost} {
		serverResult = doSession(t, getSigningRequest(id), client, nil, nil, nil, conf, append(opts, opt)...)

		require.Nil(t, serverResult.Err)
		require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)
		require.NotEmpty(t, serverResult.Disclosed)
		require.Equal(t, id, serverResult.Disclosed[0][0].Identifier)
		require.Equal(t, "456", serverResult.Disclosed[0][0].Value["en"])
	}

	// Load the updated scheme in which an attribute was added to the studentCard credential type
	scheme := client.Configuration.SchemeManagers[irma.NewSchemeManagerIdentifier("irma-demo")]
	scheme.URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	require.NoError(t, client.Configuration.UpdateScheme(scheme, nil))
	require.NoError(t, client.Configuration.ParseFolder())
	require.Contains(t, client.Configuration.AttributeTypes, irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute"))

	// Check that the just created credential is still valid after the new attribute has been added
	_, status, err := serverResult.Signature.Verify(client.Configuration, nil)
	require.NoError(t, err)
	require.Equal(t, irma.ProofStatusValid, status)
}

func testDisclosureSession(t *testing.T, conf interface{}, opts ...sessionOption) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)
	for _, opt := range []sessionOption{0, sessionOptionRetryPost} {
		serverResult := doSession(t, request, nil, nil, nil, nil, conf, append(opts, opt)...)
		require.Nil(t, serverResult.Err)
		require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)
		require.Len(t, serverResult.Disclosed, 1)
		require.Equal(t, id, serverResult.Disclosed[0][0].Identifier)
		require.Equal(t, "456", serverResult.Disclosed[0][0].Value["en"])
	}
}

func testDisclosureMultipleAttrs(t *testing.T, conf interface{}, opts ...sessionOption) {
	request := irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"),
	)

	serverResult := doSession(t, request, nil, nil, nil, nil, conf, opts...)
	require.Nil(t, serverResult.Err)
	require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)

	require.Len(t, serverResult.Disclosed, 2)
}

func testIssuanceSession(t *testing.T, conf interface{}, opts ...sessionOption) {
	doIssuanceSession(t, false, nil, conf, opts...)
}

func testCombinedSessionMultipleAttributes(t *testing.T, conf interface{}, opts ...sessionOption) {
	var ir irma.IssuanceRequest
	require.NoError(t, irma.UnmarshalValidate([]byte(`{
		"type":"issuing",
		"credentials": [
			{
				"credential":"irma-demo.MijnOverheid.singleton",
				"attributes" : {
					"BSN":"12345"
				}
			}
		],
		"disclose" : [
			{
				"label":"Initialen",
				"attributes":["irma-demo.RU.studentCard.studentCardNumber"]
			},
			{
				"label":"Achternaam",
				"attributes" : ["irma-demo.RU.studentCard.studentID"]
			},
			{
				"label":"Geboortedatum",
				"attributes":["irma-demo.RU.studentCard.university"]
			}
		]
	}`), &ir))

	require.Equal(t, irma.ServerStatusDone, doSession(t, &ir, nil, nil, nil, nil, conf, opts...).Status)
}

func doIssuanceSession(t *testing.T, keyshare bool, client *irmaclient.Client, conf interface{}, opts ...sessionOption) {
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		Attributes: map[string]string{
			"university":        "Radboud",
			"studentCardNumber": "31415927",
			"studentID":         "s1234567",
			"level":             "42",
		},
	}, {
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
		Attributes: map[string]string{
			"firstnames": "Johan Pieter",
			"firstname":  "Johan",
			"familyname": "Stuivezand",
		},
	}}, attrid)
	if keyshare {
		request.Credentials = append(request.Credentials, &irma.CredentialRequest{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes:       map[string]string{"email": "testusername"},
		})
	}

	result := doSession(t, request, client, nil, nil, nil, conf, opts...)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)
	require.Equal(t, attrid, result.Disclosed[0][0].Identifier)
	require.Equal(t, "456", result.Disclosed[0][0].Value["en"])
}

func testConDisCon(t *testing.T, conf interface{}, opts ...sessionOption) {
	client, handler := parseStorage(t, opts...)
	defer test.ClearTestStorage(t, handler.storage)
	ir := getMultipleIssuanceRequest()
	ir.Credentials = append(ir.Credentials, &irma.CredentialRequest{
		Validity:         ir.Credentials[0].Validity,
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
		Attributes: map[string]string{
			"firstnames": "Jan Hendrik",
			"firstname":  "Jan",
			"familyname": "Klaassen",
			"prefix":     "van",
		},
	})
	doSession(t, ir, client, nil, nil, nil, conf, opts...)

	dr := irma.NewDisclosureRequest()
	dr.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.root.BSN"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.studentID"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
			},
		},
	}

	doSession(t, dr, client, nil, nil, nil, conf, opts...)
}

func testOptionalDisclosure(t *testing.T, conf interface{}, opts ...sessionOption) {
	client, handler := parseStorage(t, opts...)
	defer test.ClearTestStorage(t, handler.storage)
	university := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university")
	studentid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	radboud := "Radboud"
	attrs1 := irma.AttributeConDisCon{
		irma.AttributeDisCon{ // Including one non-optional disjunction is required in disclosure and signature sessions
			irma.AttributeCon{irma.AttributeRequest{Type: university}},
		},
		irma.AttributeDisCon{
			irma.AttributeCon{},
			irma.AttributeCon{irma.AttributeRequest{Type: studentid}},
		},
	}
	disclosed1 := [][]*irma.DisclosedAttribute{
		{
			{
				RawValue:     &radboud,
				Value:        map[string]string{"": radboud, "en": radboud, "nl": radboud},
				Identifier:   irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"),
				Status:       irma.AttributeProofStatusPresent,
				IssuanceTime: irma.Timestamp(client.Attributes(university.CredentialTypeIdentifier(), 0).SigningDate()),
			},
		},
		{},
	}
	attrs2 := irma.AttributeConDisCon{ // In issuance sessions, it is allowed that all disjunctions are optional
		irma.AttributeDisCon{
			irma.AttributeCon{},
			irma.AttributeCon{irma.AttributeRequest{Type: studentid}},
		},
	}
	disclosed2 := [][]*irma.DisclosedAttribute{{}}

	tests := []struct {
		request   irma.SessionRequest
		attrs     irma.AttributeConDisCon
		disclosed [][]*irma.DisclosedAttribute
	}{
		{irma.NewDisclosureRequest(), attrs1, disclosed1},
		{irma.NewSignatureRequest("message"), attrs1, disclosed1},
		{getIssuanceRequest(true), attrs1, disclosed1},
		{getIssuanceRequest(true), attrs2, disclosed2},
	}

	for _, args := range tests {
		args.request.Disclosure().Disclose = args.attrs

		// TestHandler always prefers the first option when given any choice, so it will not disclose the optional attribute
		result := doSession(t, args.request, client, nil, nil, nil, conf, opts...)
		require.True(t, reflect.DeepEqual(args.disclosed, result.Disclosed))
	}
}

func TestClientDeveloperMode(t *testing.T) {
	common.ForceHTTPS = true
	defer func() { common.ForceHTTPS = false }()
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	// parseStorage returns a client with developer mode already enabled.
	// Do a session with our local testserver (without https)
	issuanceRequest := getNameIssuanceRequest()
	doSession(t, issuanceRequest, client, irmaServer, nil, nil, nil)
	require.True(t, issuanceRequest.DevelopmentMode) // set to true by server

	// RemoveStorage resets developer mode preference back to its default (disabled)
	require.NoError(t, client.RemoveStorage())
	require.False(t, client.Preferences.DeveloperMode)

	// Try to start another session with our non-https server
	issuanceRequest = getNameIssuanceRequest()
	qr, _, _, err := irmaServer.irma.StartSession(issuanceRequest, nil)
	require.NoError(t, err)
	c := make(chan *SessionResult, 1)
	j, err := json.Marshal(qr)
	require.NoError(t, err)
	client.NewSession(string(j), &TestHandler{t, c, client, nil, 0, "", nil, nil, nil})
	result := <-c

	// Check that it failed with an appropriate error message
	require.NotNil(t, result)
	require.Error(t, result.Err)
	serr, ok := result.Err.(*irma.SessionError)
	require.True(t, ok)
	require.NotNil(t, serr)
	require.Equal(t, string(irma.ErrorHTTPS), string(serr.ErrorType))
	require.Equal(t, "remote server does not use https", serr.Err.Error())
}

func TestParallelSessions(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	// Ensure we don't have the requested attribute at first
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})

	// Start disclosure session for an attribute we don't have.
	// sessionOptionWait makes this block until the IRMA server returns a result.
	disclosure := make(chan *requestorSessionResult)
	go func() {
		result := doSession(t,
			getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")),
			client,
			irmaServer,
			nil, nil, nil,
			sessionOptionUnsatisfiableRequest, sessionOptionWait,
		)
		require.Equal(t, result.Status, irma.ServerStatusDone)
		disclosure <- result
	}()

	// Wait for a bit then check that so far zero sessions have been done
	time.Sleep(100 * time.Millisecond)
	logs, err := client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Zero(t, len(logs))

	// Issue credential containing above attribute
	doSession(t, getIssuanceRequest(false), client, irmaServer, nil, nil, nil)

	// Running disclosure session should now finish using the new credential
	result := <-disclosure
	require.Nil(t, result.Err)
	require.NotEmpty(t, result.Disclosed)
	require.Equal(t, "s1234567", result.Disclosed[0][0].Value["en"])

	// Two sessions should now have been done
	time.Sleep(100 * time.Millisecond)
	logs, err = client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 2)
}

func expireKey(t *testing.T, conf *irma.Configuration) {
	pk, err := conf.PublicKey(irma.NewIssuerIdentifier("irma-demo.RU"), 2)
	require.NoError(t, err)
	pk.ExpiryDate = 1500000000
}

func TestIssueExpiredKey(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	// issuance sessions using valid, nonexpired public keys work
	result := doSession(t, getIssuanceRequest(true), client, irmaServer, nil, nil, nil)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)

	// client aborts issuance sessions in case of expired public keys
	expireKey(t, client.Configuration)
	result = doSession(t, getIssuanceRequest(true), client, irmaServer, nil, nil, nil, sessionOptionIgnoreError)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ServerStatusCancelled, result.Status)

	// server aborts issuance sessions in case of expired public keys
	expireKey(t, irmaServer.conf.IrmaConfiguration)
	_, _, _, err := irmaServer.irma.StartSession(getIssuanceRequest(true), nil)
	require.Error(t, err)
}
