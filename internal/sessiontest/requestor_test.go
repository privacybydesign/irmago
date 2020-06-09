package sessiontest

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/require"
)

type sessionOption int

const (
	sessionOptionUpdatedIrmaConfiguration sessionOption = 1 << iota
	sessionOptionUnsatisfiableRequest
	sessionOptionRetryPost
	sessionOptionIgnoreError
	sessionOptionReuseServer
	sessionOptionClientWait
	sessionOptionWait
)

type requestorSessionResult struct {
	*server.SessionResult
	clientResult *SessionResult
	Missing      [][]irmaclient.DisclosureCandidates
	Dismisser    irmaclient.SessionDismisser
}

func processOptions(options ...sessionOption) sessionOption {
	var opts sessionOption = 0
	for _, o := range options {
		opts |= o
	}
	return opts
}

func requestorSessionHelper(t *testing.T, request interface{}, client *irmaclient.Client, options ...sessionOption) *requestorSessionResult {
	if client == nil {
		var handler *TestClientHandler
		client, handler = parseStorage(t)
		defer test.ClearTestStorage(t, handler.storage)
	}

	opts := processOptions(options...)
	if opts&sessionOptionReuseServer == 0 {
		StartIrmaServer(t, opts&sessionOptionUpdatedIrmaConfiguration > 0, "")
		defer StopIrmaServer()
	}

	clientChan := make(chan *SessionResult, 2)
	serverChan := make(chan *server.SessionResult)

	qr, backendToken, _, err := irmaServer.StartSession(request, func(result *server.SessionResult) {
		serverChan <- result
	})
	require.NoError(t, err)

	var h irmaclient.Handler
	requestor := expectedRequestorInfo(t, client.Configuration)
	if opts&sessionOptionUnsatisfiableRequest > 0 {
		h = &UnsatisfiableTestHandler{TestHandler: TestHandler{t, clientChan, client, requestor, 0, "", nil}}
	} else {
		var wait time.Duration = 0
		if opts&sessionOptionClientWait > 0 {
			wait = 2 * time.Second
		}
		h = &TestHandler{t, clientChan, client, requestor, wait, "", nil}
	}

	clientToken, dismisser := client.NewQrSession(qr, h)
	clientResult := <-clientChan
	if opts&sessionOptionIgnoreError == 0 && clientResult != nil {
		require.NoError(t, clientResult.Err)
	}

	if opts&sessionOptionUnsatisfiableRequest > 0 && opts&sessionOptionWait == 0 {
		require.NotNil(t, clientResult)
		return &requestorSessionResult{nil, nil, clientResult.Missing, dismisser}
	}

	serverResult := <-serverChan
	require.Equal(t, backendToken, serverResult.Token)

	if opts&sessionOptionRetryPost > 0 {
		req, err := http.NewRequest(http.MethodPost,
			qr.URL+"/proofs",
			bytes.NewBuffer([]byte(h.(*TestHandler).result)),
		)
		require.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add(irma.AuthorizationHeader, clientToken)
		res, err := new(http.Client).Do(req)
		require.NoError(t, err)
		require.True(t, res.StatusCode < 300)
		_, err = ioutil.ReadAll(res.Body)
		require.NoError(t, err)
	}

	return &requestorSessionResult{serverResult, clientResult, nil, dismisser}
}

// Check that nonexistent IRMA identifiers in the session request fail the session
func TestRequestorInvalidRequest(t *testing.T) {
	StartIrmaServer(t, false, "")
	defer StopIrmaServer()
	_, _, _, err := irmaServer.StartSession(irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.foo.bar"),
		irma.NewAttributeTypeIdentifier("irma-demo.baz.qux.abc"),
	), nil)
	require.Error(t, err)
}

func TestRequestorDoubleGET(t *testing.T) {
	StartIrmaServer(t, false, "")
	defer StopIrmaServer()
	qr, _, _, err := irmaServer.StartSession(irma.NewDisclosureRequest(
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

func TestRequestorSignatureSession(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	var serverResult *requestorSessionResult
	for _, opt := range []sessionOption{0, sessionOptionRetryPost} {
		serverResult = requestorSessionHelper(t, irma.NewSignatureRequest("message", id), client, opt)

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

func TestRequestorDisclosureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := irma.NewDisclosureRequest(id)
	for _, opt := range []sessionOption{0, sessionOptionRetryPost} {
		serverResult := testRequestorDisclosure(t, request, opt)
		require.Len(t, serverResult.Disclosed, 1)
		require.Equal(t, id, serverResult.Disclosed[0][0].Identifier)
		require.Equal(t, "456", serverResult.Disclosed[0][0].Value["en"])
	}
}

func TestRequestorDisclosureMultipleAttrs(t *testing.T) {
	request := irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"),
	)
	serverResult := testRequestorDisclosure(t, request)
	require.Len(t, serverResult.Disclosed, 2)
}

func testRequestorDisclosure(t *testing.T, request *irma.DisclosureRequest, options ...sessionOption) *server.SessionResult {
	serverResult := requestorSessionHelper(t, request, nil, options...)
	require.Nil(t, serverResult.Err)
	require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)
	return serverResult.SessionResult
}

func TestRequestorIssuanceSession(t *testing.T) {
	testRequestorIssuance(t, false, nil)
}

func TestRequestorCombinedSessionMultipleAttributes(t *testing.T) {
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

	require.Equal(t, server.StatusDone, requestorSessionHelper(t, &ir, nil).Status)
}

func testRequestorIssuance(t *testing.T, keyshare bool, client *irmaclient.Client) {
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

	result := requestorSessionHelper(t, request, client)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)
	require.Equal(t, attrid, result.Disclosed[0][0].Identifier)
	require.Equal(t, "456", result.Disclosed[0][0].Value["en"])
}

func TestConDisCon(t *testing.T) {
	client, handler := parseStorage(t)
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
	requestorSessionHelper(t, ir, client)

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
		//irma.AttributeDisCon{
		//	irma.AttributeCon{
		//		irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstname"),
		//		irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
		//	},
		//},
	}

	requestorSessionHelper(t, dr, client)
}

func TestOptionalDisclosure(t *testing.T) {
	client, handler := parseStorage(t)
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
		result := requestorSessionHelper(t, args.request, client)
		require.True(t, reflect.DeepEqual(args.disclosed, result.Disclosed))
	}
}

func TestClientDeveloperMode(t *testing.T) {
	common.ForceHTTPS = true
	defer func() { common.ForceHTTPS = false }()
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	StartIrmaServer(t, false, "")
	defer StopIrmaServer()

	// parseStorage returns a client with developer mode already enabled.
	// Do a session with our local testserver (without https)
	issuanceRequest := getNameIssuanceRequest()
	requestorSessionHelper(t, issuanceRequest, client, sessionOptionReuseServer)
	require.True(t, issuanceRequest.DevelopmentMode) // set to true by server

	// RemoveStorage resets developer mode preference back to its default (disabled)
	require.NoError(t, client.RemoveStorage())
	require.False(t, client.Preferences.DeveloperMode)

	// Try to start another session with our non-https server
	issuanceRequest = getNameIssuanceRequest()
	qr, _, _, err := irmaServer.StartSession(issuanceRequest, nil)
	require.NoError(t, err)
	c := make(chan *SessionResult, 1)
	j, err := json.Marshal(qr)
	require.NoError(t, err)
	client.NewSession(string(j), &TestHandler{t, c, client, nil, 0, "", nil})
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
	StartIrmaServer(t, false, "")
	defer StopIrmaServer()

	// Ensure we don't have the requested attribute at first
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})

	// Start disclosure session for an attribute we don't have.
	// sessionOptionWait makes this block until the IRMA server returns a result.
	disclosure := make(chan *requestorSessionResult)
	go func() {
		disclosure <- requestorSessionHelper(t,
			getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")),
			client,
			sessionOptionUnsatisfiableRequest, sessionOptionReuseServer, sessionOptionWait,
		)
	}()

	// Wait for a bit then check that so far zero sessions have been done
	time.Sleep(100 * time.Millisecond)
	logs, err := client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Zero(t, len(logs))

	// Issue credential containing above attribute
	requestorSessionHelper(t, getIssuanceRequest(false), client, sessionOptionReuseServer)

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
	StartIrmaServer(t, false, "")
	defer StopIrmaServer()

	// issuance sessions using valid, nonexpired public keys work
	result := requestorSessionHelper(t, getIssuanceRequest(true), client, sessionOptionReuseServer)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)

	// client aborts issuance sessions in case of expired public keys
	expireKey(t, client.Configuration)
	result = requestorSessionHelper(t, getIssuanceRequest(true), client, sessionOptionReuseServer, sessionOptionIgnoreError)
	require.Nil(t, result.Err)
	require.Equal(t, server.StatusCancelled, result.Status)

	// server aborts issuance sessions in case of expired public keys
	expireKey(t, irmaServerConfiguration.IrmaConfiguration)
	_, _, _, err := irmaServer.StartSession(getIssuanceRequest(true), nil)
	require.Error(t, err)
}
