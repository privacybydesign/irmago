package irmaclient

// TODO +build integration

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/privacybydesign/irmago"
	"github.com/go-errors/errors"
	"github.com/stretchr/testify/require"
)

type TestHandler struct {
	t      *testing.T
	c      chan *irma.SessionError
	client *Client
}

func (th TestHandler) MissingKeyshareEnrollment(manager irma.SchemeManagerIdentifier) {
	th.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.Errorf("Missing keyshare server %s", manager.String())})
}

func (th TestHandler) StatusUpdate(action irma.Action, status irma.Status) {}
func (th TestHandler) Success(action irma.Action, result string) {
	th.c <- nil
}
func (th TestHandler) Cancelled(action irma.Action) {
	th.c <- &irma.SessionError{}
}
func (th TestHandler) Failure(action irma.Action, err *irma.SessionError) {
	select {
	case th.c <- err:
	default:
		th.t.Fatal(err)
	}
}
func (th TestHandler) UnsatisfiableRequest(action irma.Action, missing irma.AttributeDisjunctionList) {
	th.c <- &irma.SessionError{
		ErrorType: irma.ErrorType("UnsatisfiableRequest"),
	}
}
func (th TestHandler) RequestVerificationPermission(request irma.DisclosureRequest, ServerName string, callback PermissionHandler) {
	choice := &irma.DisclosureChoice{
		Attributes: []*irma.AttributeIdentifier{},
	}
	var candidates []*irma.AttributeIdentifier
	for _, disjunction := range request.Content {
		candidates = th.client.Candidates(disjunction)
		require.NotNil(th.t, candidates)
		require.NotEmpty(th.t, candidates, 1)
		choice.Attributes = append(choice.Attributes, candidates[0])
	}
	callback(true, choice)
}
func (th TestHandler) RequestIssuancePermission(request irma.IssuanceRequest, ServerName string, callback PermissionHandler) {
	dreq := irma.DisclosureRequest{
		SessionRequest: request.SessionRequest,
		Content:        request.Disclose,
	}
	th.RequestVerificationPermission(dreq, ServerName, callback)
}
func (th TestHandler) RequestSignaturePermission(request irma.SignatureRequest, ServerName string, callback PermissionHandler) {
	th.RequestVerificationPermission(request.DisclosureRequest, ServerName, callback)
}
func (th TestHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	callback(true)
}
func (th TestHandler) RequestPin(remainingAttempts int, callback PinHandler) {
	callback(true, "12345")
}

func getDisclosureJwt(name string, id irma.AttributeTypeIdentifier) interface{} {
	return irma.NewServiceProviderJwt(name, &irma.DisclosureRequest{
		Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{id},
		}}),
	})
}

func getSigningJwt(name string, id irma.AttributeTypeIdentifier) interface{} {
	return irma.NewSignatureRequestorJwt(name, &irma.SignatureRequest{
		Message:     "test",
		MessageType: "STRING",
		DisclosureRequest: irma.DisclosureRequest{
			Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
				Label:      "foo",
				Attributes: []irma.AttributeTypeIdentifier{id},
			}}),
		},
	})
}

func getIssuanceRequest() *irma.IssuanceRequest {
	expiry := irma.Timestamp(irma.NewMetadataAttribute().Expiry())
	credid1 := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	credid2 := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")

	return &irma.IssuanceRequest{
		Credentials: []*irma.CredentialRequest{
			{
				Validity:         &expiry,
				CredentialTypeID: &credid1,
				Attributes: map[string]string{
					"university":        "Radboud",
					"studentCardNumber": "3.1415926535897932384626433832811111111111111111111111111111111111111111",
					"studentID":         "s1234567",
					"level":             "42",
				},
			}, {
				Validity:         &expiry,
				CredentialTypeID: &credid2,
				Attributes: map[string]string{
					"BSN": "299792458",
				},
			},
		},
	}
}

func getIssuanceJwt(name string) interface{} {
	return irma.NewIdentityProviderJwt(name, getIssuanceRequest())
}

func getCombinedJwt(name string, id irma.AttributeTypeIdentifier) interface{} {
	isreq := getIssuanceRequest()
	isreq.Disclose = irma.AttributeDisjunctionList{
		&irma.AttributeDisjunction{Label: "foo", Attributes: []irma.AttributeTypeIdentifier{id}},
	}
	return irma.NewIdentityProviderJwt(name, isreq)
}

// StartSession starts an IRMA session by posting the request,
// and retrieving the QR contents from the specified url.
func StartSession(request interface{}, url string) (*irma.Qr, error) {
	server := irma.NewHTTPTransport(url)
	var response irma.Qr
	err := server.Post("", &response, request)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func TestSigningSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testsigclient"

	jwtcontents := getSigningJwt(name, id)
	sessionHelper(t, jwtcontents, "signature", nil)
}

func TestDisclosureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testsp"

	jwtcontents := getDisclosureJwt(name, id)
	sessionHelper(t, jwtcontents, "verification", nil)
}

func TestIssuanceSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testip"

	jwtcontents := getCombinedJwt(name, id)
	sessionHelper(t, jwtcontents, "issue", nil)
}

func TestLargeAttribute(t *testing.T) {
	client := parseStorage(t)
	require.NoError(t, client.RemoveAllCredentials())

	jwtcontents := getIssuanceJwt("testip")
	sessionHelper(t, jwtcontents, "issue", client)

	cred, err := client.credential(irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"), 0)
	require.NoError(t, err)
	require.True(t, cred.Signature.Verify(cred.Pk, cred.Attributes))

	jwtcontents = getDisclosureJwt("testsp", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"))
	sessionHelper(t, jwtcontents, "verification", client)

	teardown(t)
}

func sessionHelper(t *testing.T, jwtcontents interface{}, url string, client *Client) {
	init := client == nil
	if init {
		client = parseStorage(t)
	}

	url = "http://localhost:8088/irma_api_server/api/v2/" + url
	//url = "https://demo.irmacard.org/tomcat/irma_api_server/api/v2/" + url

	headerbytes, err := json.Marshal(&map[string]string{"alg": "none", "typ": "JWT"})
	require.NoError(t, err)
	bodybytes, err := json.Marshal(jwtcontents)
	require.NoError(t, err)

	jwt := base64.RawStdEncoding.EncodeToString(headerbytes) + "." + base64.RawStdEncoding.EncodeToString(bodybytes) + "."
	qr, transportErr := StartSession(jwt, url)
	if transportErr != nil {
		fmt.Printf("+%v\n", transportErr)
	}
	require.NoError(t, transportErr)
	qr.URL = url + "/" + qr.URL

	c := make(chan *irma.SessionError)
	client.NewSession(qr, TestHandler{t, c, client})

	if err := <-c; err != nil {
		t.Fatal(*err)
	}

	if init {
		teardown(t)
	}
}

func enrollKeyshareServer(t *testing.T, client *Client) {
	bytes := make([]byte, 8, 8)
	rand.Read(bytes)
	email := fmt.Sprintf("%s@example.com", hex.EncodeToString(bytes))
	require.NoError(t, client.keyshareEnrollWorker(irma.NewSchemeManagerIdentifier("test"), email, "12345"))
}

// Enroll at a keyshare server and do an issuance, disclosure,
// and issuance session, also using irma-demo credentials deserialized from Android storage
func TestKeyshareEnrollmentAndSessions(t *testing.T) {
	client := parseStorage(t)

	require.NoError(t, client.RemoveCredentialByHash(
		client.Attributes(irma.NewCredentialTypeIdentifier("test.test.mijnirma"), 0).Hash(),
	))
	require.NoError(t, client.KeyshareRemove(irma.NewSchemeManagerIdentifier("test")))
	enrollKeyshareServer(t, client)

	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	expiry := irma.Timestamp(irma.NewMetadataAttribute().Expiry())
	credid := irma.NewCredentialTypeIdentifier("test.test.mijnirma")
	jwt := getCombinedJwt("testip", id)
	jwt.(*irma.IdentityProviderJwt).Request.Request.Credentials = append(
		jwt.(*irma.IdentityProviderJwt).Request.Request.Credentials,
		&irma.CredentialRequest{
			Validity:         &expiry,
			CredentialTypeID: &credid,
			Attributes:       map[string]string{"email": "example@example.com"},
		},
	)
	sessionHelper(t, jwt, "issue", client)

	jwt = getDisclosureJwt("testsp", id)
	jwt.(*irma.ServiceProviderJwt).Request.Request.Content = append(
		jwt.(*irma.ServiceProviderJwt).Request.Request.Content,
		&irma.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "verification", client)

	jwt = getSigningJwt("testsigclient", id)
	jwt.(*irma.SignatureRequestorJwt).Request.Request.Content = append(
		jwt.(*irma.SignatureRequestorJwt).Request.Request.Content,
		&irma.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "signature", client)

	teardown(t)
}

// Use the existing keyshare enrollment and credentials deserialized from Android storage
// in a keyshare session of each session type.
// Use keyshareuser.sql to enroll the user at the keyshare server.
func TestKeyshareSessions(t *testing.T) {
	client := parseStorage(t)
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	expiry := irma.Timestamp(irma.NewMetadataAttribute().Expiry())
	credid := irma.NewCredentialTypeIdentifier("test.test.mijnirma")
	jwt := getCombinedJwt("testip", id)
	jwt.(*irma.IdentityProviderJwt).Request.Request.Credentials = append(
		jwt.(*irma.IdentityProviderJwt).Request.Request.Credentials,
		&irma.CredentialRequest{
			Validity:         &expiry,
			CredentialTypeID: &credid,
			Attributes:       map[string]string{"email": "example@example.com"},
		},
	)
	sessionHelper(t, jwt, "issue", client)

	jwt = getDisclosureJwt("testsp", id)
	jwt.(*irma.ServiceProviderJwt).Request.Request.Content = append(
		jwt.(*irma.ServiceProviderJwt).Request.Request.Content, //[]*AttributeDisjunction{},
		&irma.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "verification", client)

	jwt = getSigningJwt("testsigclient", id)
	jwt.(*irma.SignatureRequestorJwt).Request.Request.Content = append(
		jwt.(*irma.SignatureRequestorJwt).Request.Request.Content, //[]*AttributeDisjunction{},
		&irma.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "signature", client)

	teardown(t)
}
