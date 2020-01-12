package sessiontest

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"testing"

	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/irmago"
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
	sessionOptionIgnoreClientError
)

type requestorSessionResult struct {
	*server.SessionResult
	Missing irmaclient.MissingAttributes
}

func requestorSessionHelper(t *testing.T, request irma.SessionRequest, client *irmaclient.Client, options ...sessionOption) *requestorSessionResult {
	if client == nil {
		client, _ = parseStorage(t)
		defer test.ClearTestStorage(t)
	}

	StartIrmaServer(t, len(options) == 1 && options[0] == sessionOptionUpdatedIrmaConfiguration)
	defer StopIrmaServer()

	clientChan := make(chan *SessionResult)
	serverChan := make(chan *server.SessionResult)

	qr, token, err := irmaServer.StartSession(request, func(result *server.SessionResult) {
		serverChan <- result
	})
	require.NoError(t, err)

	opts := 0
	for _, o := range options {
		opts |= int(o)
	}

	var h irmaclient.Handler
	if opts&int(sessionOptionUnsatisfiableRequest) > 0 {
		h = &UnsatisfiableTestHandler{TestHandler{t, clientChan, client, nil, ""}}
	} else {
		h = &TestHandler{t, clientChan, client, nil, ""}
	}

	j, err := json.Marshal(qr)
	require.NoError(t, err)
	client.NewSession(string(j), h)
	clientResult := <-clientChan
	if (len(options) == 0 || options[0] != sessionOptionIgnoreClientError) && clientResult != nil {
		require.NoError(t, clientResult.Err)
	}

	if opts&int(sessionOptionUnsatisfiableRequest) > 0 {
		require.NotNil(t, clientResult)
		return &requestorSessionResult{nil, clientResult.Missing}
	}

	serverResult := <-serverChan
	require.Equal(t, token, serverResult.Token)

	if opts&int(sessionOptionRetryPost) > 0 {
		req, err := http.NewRequest(http.MethodPost,
			qr.URL+"/proofs",
			bytes.NewBuffer([]byte(h.(*TestHandler).result)),
		)
		require.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		res, err := new(http.Client).Do(req)
		require.NoError(t, err)
		require.True(t, res.StatusCode < 300)
		_, err = ioutil.ReadAll(res.Body)
		require.NoError(t, err)
	}

	return &requestorSessionResult{serverResult, nil}
}

// Check that nonexistent IRMA identifiers in the session request fail the session
func TestRequestorInvalidRequest(t *testing.T) {
	StartIrmaServer(t, false)
	defer StopIrmaServer()
	_, _, err := irmaServer.StartSession(irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.foo.bar"),
		irma.NewAttributeTypeIdentifier("irma-demo.baz.qux.abc"),
	), nil)
	require.Error(t, err)
}

func TestRequestorDoubleGET(t *testing.T) {
	StartIrmaServer(t, false)
	defer StopIrmaServer()
	qr, _, err := irmaServer.StartSession(irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
	), nil)
	require.NoError(t, err)

	// Simulate the first GET by the client in the session protocol, twice
	var o interface{}
	transport := irma.NewHTTPTransport(qr.URL)
	transport.SetHeader(irma.MinVersionHeader, "2.5")
	transport.SetHeader(irma.MaxVersionHeader, "2.5")
	require.NoError(t, transport.Get("", &o))
	require.NoError(t, transport.Get("", &o))
}

func TestRequestorSignatureSession(t *testing.T) {
	client, _ := parseStorage(t)
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
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	require.NoError(t, client.Configuration.UpdateSchemeManager(schemeid, nil))
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
				"credential":"irma-demo.MijnOverheid.root",
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
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root"),
		Attributes: map[string]string{
			"BSN": "299792458",
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
	client, _ := parseStorage(t)
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
	client, _ := parseStorage(t)
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

func revocationRequest() irma.SessionRequest {
	attr := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	req := irma.NewDisclosureRequest(attr)
	req.Revocation = []irma.CredentialTypeIdentifier{attr.CredentialTypeIdentifier()}
	return req
}

func revocationSession(t *testing.T, client *irmaclient.Client, options ...sessionOption) *requestorSessionResult {
	result := requestorSessionHelper(t, revocationRequest(), client, options...)
	require.Nil(t, result.Err)
	return result
}

// revocationSetup sets up an irmaclient with a revocation-enabled credential, constants, and revocation key material.
func revocationSetup(t *testing.T) (*irmaclient.Client, irmaclient.ClientHandler) {
	StartRevocationServer(t)

	// issue a MijnOverheid.root instance with revocation enabled
	client, handler := parseStorage(t)
	result := requestorSessionHelper(t, revocationIssuanceRequest, client)
	require.Nil(t, result.Err)

	return client, handler
}

func revoke(t *testing.T, key string, conf *irma.RevocationStorage, cred irma.CredentialTypeIdentifier, acc *revocation.Accumulator) {
	sk, err := conf.Keys.PrivateKey(cred.IssuerIdentifier(), 2)
	require.NoError(t, err)
	witness, err := revocation.RandomWitness(sk, acc)
	require.NoError(t, err)
	require.NoError(t, conf.AddIssuanceRecord(&irma.IssuanceRecord{
		Key:        key,
		CredType:   cred,
		PKCounter:  2,
		Attr:       (*irma.RevocationAttribute)(witness.E),
		Issued:     time.Now().UnixNano(),
		ValidUntil: time.Now().Add(1 * time.Hour).UnixNano(),
	}))
	require.NoError(t, conf.Revoke(cred, key))
}

var revocationIssuanceRequest = irma.NewIssuanceRequest([]*irma.CredentialRequest{{
	RevocationKey:    "cred0", // once revocation is required for a credential type, this key is required
	CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root"),
	Attributes: map[string]string{
		"BSN": "299792458",
	},
}})

func TestRevocationOutdatedAccumulator(t *testing.T) {
	defer test.ClearTestStorage(t)
	attr := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	cred := attr.CredentialTypeIdentifier()
	client, _ := revocationSetup(t)

	// Prepare key material
	conf := revocationConfiguration.IrmaConfiguration.Revocation
	sk, err := conf.Keys.PrivateKey(cred.IssuerIdentifier(), 2)
	require.NoError(t, err)
	pk, err := conf.Keys.PublicKey(cred.IssuerIdentifier(), 2)
	require.NoError(t, err)
	update, err := revocation.NewAccumulator(sk)
	require.NoError(t, err)
	acc, err := update.SignedAccumulator.UnmarshalVerify(pk)
	require.NoError(t, err)

	// Prepare session request
	request := revocationRequest().(*irma.DisclosureRequest)
	require.NoError(t, revocationConfiguration.IrmaConfiguration.Revocation.SetRevocationUpdates(request.Base()))
	events := request.RevocationUpdates[cred][2].Events
	i := events[len(events)-1].Index

	// Construct disclosure proof with nonrevocation proof
	candidates, missing := client.CheckSatisfiability(request.Disclosure().Disclose)
	require.Empty(t, missing)
	disclosure, _, err := client.Proofs(&irma.DisclosureChoice{Attributes: [][]*irma.AttributeIdentifier{candidates[0][0]}}, request)
	require.NoError(t, err)

	// Revoke a bogus credential and update the session request,
	// indicated that we expect a nonrevocation proof wrt the just-updated accumulator
	revoke(t, "1", conf, cred, acc)
	request.RevocationUpdates = nil
	require.NoError(t, revocationConfiguration.IrmaConfiguration.Revocation.SetRevocationUpdates(request.Base()))
	events = request.RevocationUpdates[cred][2].Events
	require.True(t, events[len(events)-1].Index > i)

	// Try to verify against updated session request
	_, status, err := disclosure.Verify(client.Configuration, request)
	require.Error(t, err)
	require.Equal(t, irma.ProofStatusInvalid, status)
}

func TestRevocationClientUpdate(t *testing.T) {
	defer test.ClearTestStorage(t)
	attr := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	cred := attr.CredentialTypeIdentifier()
	client, _ := revocationSetup(t)

	conf := revocationConfiguration.IrmaConfiguration.Revocation

	sk, err := conf.Keys.PrivateKey(cred.IssuerIdentifier(), 2)
	require.NoError(t, err)
	pk, err := conf.Keys.PublicKey(cred.IssuerIdentifier(), 2)
	require.NoError(t, err)
	update, err := revocation.NewAccumulator(sk)
	require.NoError(t, err)
	acc, err := update.SignedAccumulator.UnmarshalVerify(pk)
	require.NoError(t, err)

	// Advance the accumulator by doing revocations so much that the client will need
	// to contact the RA to update its witness
	for i := 0; i < irma.RevocationDefaultEventCount+1; i++ {
		key := strconv.Itoa(i)
		revoke(t, key, conf, cred, acc)
	}

	result := revocationSession(t, client)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)
}

func TestRevocation(t *testing.T) {
	defer test.ClearTestStorage(t)
	attr := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	cred := attr.CredentialTypeIdentifier()
	client, handler := revocationSetup(t)

	// issue second credential which overwrites the first one, as our credtype is a singleton
	// this is ok, as we use cred0 only to revoke it, to see if cred1 keeps working
	revocationIssuanceRequest.Credentials[0].RevocationKey = "cred1"
	result := requestorSessionHelper(t, revocationIssuanceRequest, client)
	require.Nil(t, result.Err)

	// perform disclosure session (of cred1) with nonrevocation proof
	logger.Info("step 1")
	result = revocationSession(t, client)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)

	// revoke cred0
	logger.Info("step 2")
	require.NoError(t, revocationServer.Revoke(cred, "cred0"))

	// perform another disclosure session with nonrevocation proof to see that cred1 still works
	// client updates its witness to the new accumulator first
	logger.Info("step 3")
	result = revocationSession(t, client)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)

	// revoke cred1
	logger.Info("step 4")
	require.NoError(t, revocationServer.Revoke(cred, "cred1"))

	// try to perform session with revoked credential
	// client notices that his credential is revoked and aborts
	logger.Info("step 5")
	result = revocationSession(t, client, sessionOptionIgnoreClientError)
	require.Equal(t, server.StatusCancelled, result.Status)
	// client revocation callback was called
	require.NotNil(t, handler.(*TestClientHandler).revoked)
	require.Equal(t, cred, handler.(*TestClientHandler).revoked.Type)
	// credential is no longer suggested as candidate
	candidates, missing := client.Candidates(irma.AttributeDisCon{{{Type: attr}}})
	require.Empty(t, candidates)
	require.NotEmpty(t, missing)
}
