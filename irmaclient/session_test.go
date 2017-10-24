package irmaclient

// TODO +build integration

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/credentials/irmago"
	"github.com/go-errors/errors"
	"github.com/stretchr/testify/require"
)

type TestHandler struct {
	t      *testing.T
	c      chan *irmago.SessionError
	client *Client
}

func (th TestHandler) MissingKeyshareEnrollment(manager irmago.SchemeManagerIdentifier) {
	th.Failure(irmago.ActionUnknown, &irmago.SessionError{Err: errors.Errorf("Missing keyshare server %s", manager.String())})
}

func (th TestHandler) StatusUpdate(action irmago.Action, status irmago.Status) {}
func (th TestHandler) Success(action irmago.Action) {
	th.c <- nil
}
func (th TestHandler) Cancelled(action irmago.Action) {
	th.c <- &irmago.SessionError{}
}
func (th TestHandler) Failure(action irmago.Action, err *irmago.SessionError) {
	select {
	case th.c <- err:
	default:
		th.t.Fatal(err)
	}
}
func (th TestHandler) UnsatisfiableRequest(action irmago.Action, missing irmago.AttributeDisjunctionList) {
	th.c <- &irmago.SessionError{
		ErrorType: irmago.ErrorType("UnsatisfiableRequest"),
	}
}
func (th TestHandler) RequestVerificationPermission(request irmago.DisclosureRequest, ServerName string, callback PermissionHandler) {
	choice := &irmago.DisclosureChoice{
		Attributes: []*irmago.AttributeIdentifier{},
	}
	var candidates []*irmago.AttributeIdentifier
	for _, disjunction := range request.Content {
		candidates = th.client.Candidates(disjunction)
		require.NotNil(th.t, candidates)
		require.NotEmpty(th.t, candidates, 1)
		choice.Attributes = append(choice.Attributes, candidates[0])
	}
	callback(true, choice)
}
func (th TestHandler) RequestIssuancePermission(request irmago.IssuanceRequest, ServerName string, callback PermissionHandler) {
	dreq := irmago.DisclosureRequest{
		SessionRequest: request.SessionRequest,
		Content:        request.Disclose,
	}
	th.RequestVerificationPermission(dreq, ServerName, callback)
}
func (th TestHandler) RequestSignaturePermission(request irmago.SignatureRequest, ServerName string, callback PermissionHandler) {
	th.RequestVerificationPermission(request.DisclosureRequest, ServerName, callback)
}
func (th TestHandler) RequestSchemeManagerPermission(manager *irmago.SchemeManager, callback func(proceed bool)) {
	callback(true)
}
func (th TestHandler) RequestPin(remainingAttempts int, callback PinHandler) {
	callback(true, "12345")
}

func getDisclosureJwt(name string, id irmago.AttributeTypeIdentifier) interface{} {
	return irmago.NewServiceProviderJwt(name, &irmago.DisclosureRequest{
		Content: irmago.AttributeDisjunctionList([]*irmago.AttributeDisjunction{{
			Label:      "foo",
			Attributes: []irmago.AttributeTypeIdentifier{id},
		}}),
	})
}

func getSigningJwt(name string, id irmago.AttributeTypeIdentifier) interface{} {
	return irmago.NewSignatureRequestorJwt(name, &irmago.SignatureRequest{
		Message:     "test",
		MessageType: "STRING",
		DisclosureRequest: irmago.DisclosureRequest{
			Content: irmago.AttributeDisjunctionList([]*irmago.AttributeDisjunction{{
				Label:      "foo",
				Attributes: []irmago.AttributeTypeIdentifier{id},
			}}),
		},
	})
}

func getIssuanceJwt(name string, id irmago.AttributeTypeIdentifier) interface{} {
	expiry := irmago.Timestamp(irmago.NewMetadataAttribute().Expiry())
	credid1 := irmago.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	credid2 := irmago.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")
	return irmago.NewIdentityProviderJwt(name, &irmago.IssuanceRequest{
		Credentials: []*irmago.CredentialRequest{
			{
				Validity:         &expiry,
				CredentialTypeID: &credid1,
				Attributes: map[string]string{
					"university":        "Radboud",
					"studentCardNumber": "3.14159265358979323846264338328",
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
		Disclose: irmago.AttributeDisjunctionList{
			&irmago.AttributeDisjunction{Label: "foo", Attributes: []irmago.AttributeTypeIdentifier{id}},
		},
	})
}

// StartSession starts an IRMA session by posting the request,
// and retrieving the QR contents from the specified url.
func StartSession(request interface{}, url string) (*irmago.Qr, error) {
	server := irmago.NewHTTPTransport(url)
	var response irmago.Qr
	err := server.Post("", &response, request)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func TestSigningSession(t *testing.T) {
	id := irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testsigclient"

	jwtcontents := getSigningJwt(name, id)
	sessionHelper(t, jwtcontents, "signature", nil)
}

func TestDisclosureSession(t *testing.T) {
	id := irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testsp"

	jwtcontents := getDisclosureJwt(name, id)
	sessionHelper(t, jwtcontents, "verification", nil)
}

func TestIssuanceSession(t *testing.T) {
	id := irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testip"

	jwtcontents := getIssuanceJwt(name, id)
	sessionHelper(t, jwtcontents, "issue", nil)
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

	c := make(chan *irmago.SessionError)
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
	require.NoError(t, client.keyshareEnrollWorker(irmago.NewSchemeManagerIdentifier("test"), email, "12345"))
}

// Enroll at a keyshare server and do an issuance, disclosure,
// and issuance session, also using irma-demo credentials deserialized from Android storage
func TestKeyshareEnrollmentAndSessions(t *testing.T) {
	client := parseStorage(t)

	client.credentials[irmago.NewCredentialTypeIdentifier("test.test.mijnirma")] = map[int]*credential{}
	test := irmago.NewSchemeManagerIdentifier("test")
	err := client.KeyshareRemove(test)
	require.NoError(t, err)
	enrollKeyshareServer(t, client)

	id := irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	expiry := irmago.Timestamp(irmago.NewMetadataAttribute().Expiry())
	credid := irmago.NewCredentialTypeIdentifier("test.test.mijnirma")
	jwt := getIssuanceJwt("testip", id)
	jwt.(*irmago.IdentityProviderJwt).Request.Request.Credentials = append(
		jwt.(*irmago.IdentityProviderJwt).Request.Request.Credentials,
		&irmago.CredentialRequest{
			Validity:         &expiry,
			CredentialTypeID: &credid,
			Attributes:       map[string]string{"email": "example@example.com"},
		},
	)
	sessionHelper(t, jwt, "issue", client)

	jwt = getDisclosureJwt("testsp", id)
	jwt.(*irmago.ServiceProviderJwt).Request.Request.Content = append(
		jwt.(*irmago.ServiceProviderJwt).Request.Request.Content,
		&irmago.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irmago.AttributeTypeIdentifier{irmago.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "verification", client)

	jwt = getSigningJwt("testsigclient", id)
	jwt.(*irmago.SignatureRequestorJwt).Request.Request.Content = append(
		jwt.(*irmago.SignatureRequestorJwt).Request.Request.Content,
		&irmago.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irmago.AttributeTypeIdentifier{irmago.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
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
	id := irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	expiry := irmago.Timestamp(irmago.NewMetadataAttribute().Expiry())
	credid := irmago.NewCredentialTypeIdentifier("test.test.mijnirma")
	jwt := getIssuanceJwt("testip", id)
	jwt.(*irmago.IdentityProviderJwt).Request.Request.Credentials = append(
		jwt.(*irmago.IdentityProviderJwt).Request.Request.Credentials,
		&irmago.CredentialRequest{
			Validity:         &expiry,
			CredentialTypeID: &credid,
			Attributes:       map[string]string{"email": "example@example.com"},
		},
	)
	sessionHelper(t, jwt, "issue", client)

	jwt = getDisclosureJwt("testsp", id)
	jwt.(*irmago.ServiceProviderJwt).Request.Request.Content = append(
		jwt.(*irmago.ServiceProviderJwt).Request.Request.Content, //[]*AttributeDisjunction{},
		&irmago.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irmago.AttributeTypeIdentifier{irmago.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "verification", client)

	jwt = getSigningJwt("testsigclient", id)
	jwt.(*irmago.SignatureRequestorJwt).Request.Request.Content = append(
		jwt.(*irmago.SignatureRequestorJwt).Request.Request.Content, //[]*AttributeDisjunction{},
		&irmago.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irmago.AttributeTypeIdentifier{irmago.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "signature", client)

	teardown(t)
}
