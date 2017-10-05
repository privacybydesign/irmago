package irmago

// TODO +build integration

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type TestHandler struct {
	t       *testing.T
	c       chan *SessionError
	manager *CredentialManager
}

func (th TestHandler) StatusUpdate(action Action, status Status) {}
func (th TestHandler) Success(action Action) {
	th.c <- nil
}
func (th TestHandler) Cancelled(action Action) {
	th.c <- &SessionError{}
}
func (th TestHandler) Failure(action Action, err *SessionError) {
	select {
	case th.c <- err:
	default:
		th.t.Fatal(err)
	}
}
func (th TestHandler) UnsatisfiableRequest(action Action, missing AttributeDisjunctionList) {
	th.c <- &SessionError{
		ErrorType: ErrorType("UnsatisfiableRequest"),
	}
}
func (th TestHandler) RequestVerificationPermission(request DisclosureRequest, ServerName string, callback PermissionHandler) {
	choice := &DisclosureChoice{
		Attributes: []*AttributeIdentifier{},
	}
	var candidates []*AttributeIdentifier
	for _, disjunction := range request.Content {
		candidates = th.manager.Candidates(disjunction)
		require.NotNil(th.t, candidates)
		require.NotEmpty(th.t, candidates, 1)
		choice.Attributes = append(choice.Attributes, candidates[0])
	}
	callback(true, choice)
}
func (th TestHandler) RequestIssuancePermission(request IssuanceRequest, ServerName string, callback PermissionHandler) {
	dreq := DisclosureRequest{
		SessionRequest: request.SessionRequest,
		Content:        request.Disclose,
	}
	th.RequestVerificationPermission(dreq, ServerName, callback)
}
func (th TestHandler) RequestSignaturePermission(request SignatureRequest, ServerName string, callback PermissionHandler) {
	th.RequestVerificationPermission(request.DisclosureRequest, ServerName, callback)
}
func (th TestHandler) RequestPin(remainingAttempts int, callback func(proceed bool, pin string)) {
	callback(true, "12345")
}

func getDisclosureJwt(name string, id AttributeTypeIdentifier) interface{} {
	return NewServiceProviderJwt(name, &DisclosureRequest{
		Content: AttributeDisjunctionList([]*AttributeDisjunction{{
			Label:      "foo",
			Attributes: []AttributeTypeIdentifier{id},
		}}),
	})
}

func getSigningJwt(name string, id AttributeTypeIdentifier) interface{} {
	return NewSignatureRequestorJwt(name, &SignatureRequest{
		Message:     "test",
		MessageType: "STRING",
		DisclosureRequest: DisclosureRequest{
			Content: AttributeDisjunctionList([]*AttributeDisjunction{{
				Label:      "foo",
				Attributes: []AttributeTypeIdentifier{id},
			}}),
		},
	})
}

func getIssuanceJwt(name string, id AttributeTypeIdentifier) interface{} {
	expiry := Timestamp(NewMetadataAttribute().Expiry())
	credid1 := NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	credid2 := NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")
	return NewIdentityProviderJwt(name, &IssuanceRequest{
		Credentials: []*CredentialRequest{
			{
				Validity:   &expiry,
				Credential: &credid1,
				Attributes: map[string]string{
					"university":        "Radboud",
					"studentCardNumber": "3.14159265358979323846264338328",
					"studentID":         "s1234567",
					"level":             "42",
				},
			}, {
				Validity:   &expiry,
				Credential: &credid2,
				Attributes: map[string]string{
					"BSN": "299792458",
				},
			},
		},
		Disclose: AttributeDisjunctionList{
			&AttributeDisjunction{Label: "foo", Attributes: []AttributeTypeIdentifier{id}},
		},
	})
}

// StartSession starts an IRMA session by posting the request,
// and retrieving the QR contents from the specified url.
func StartSession(request interface{}, url string) (*Qr, error) {
	server := NewHTTPTransport(url)
	var response Qr
	err := server.Post("", &response, request)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func TestSigningSession(t *testing.T) {
	id := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testsigclient"

	jwtcontents := getSigningJwt(name, id)
	sessionHelper(t, jwtcontents, "signature", nil)
}

func TestDisclosureSession(t *testing.T) {
	id := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testsp"

	jwtcontents := getDisclosureJwt(name, id)
	sessionHelper(t, jwtcontents, "verification", nil)
}

func TestIssuanceSession(t *testing.T) {
	id := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testip"

	jwtcontents := getIssuanceJwt(name, id)
	sessionHelper(t, jwtcontents, "issue", nil)
}

func sessionHelper(t *testing.T, jwtcontents interface{}, url string, manager *CredentialManager) {
	init := manager == nil
	if init {
		manager = parseStorage(t)
	}

	url = "http://localhost:8081/irma_api_server/api/v2/" + url
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

	c := make(chan *SessionError)
	manager.NewSession(qr, TestHandler{t, c, manager})

	if err := <-c; err != nil {
		t.Fatal(*err)
	}

	if init {
		teardown(t)
	}
}

func registerKeyshareServer(t *testing.T, manager *CredentialManager) {
	bytes := make([]byte, 8, 8)
	rand.Read(bytes)
	email := fmt.Sprintf("%s@example.com", hex.EncodeToString(bytes))
	require.NoError(t, manager.KeyshareEnroll(NewSchemeManagerIdentifier("test"), email, "12345"))
}

// Register a new account at the keyshare server and do an issuance, disclosure,
// and issuance session, also using irma-demo credentials deserialized from Android storage
func TestKeyshareRegistrationAndSessions(t *testing.T) {
	manager := parseStorage(t)

	manager.credentials[NewCredentialTypeIdentifier("test.test.mijnirma")] = map[int]*credential{}
	test := NewSchemeManagerIdentifier("test")
	err := manager.KeyshareRemove(test)
	require.NoError(t, err)
	registerKeyshareServer(t, manager)

	id := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	expiry := Timestamp(NewMetadataAttribute().Expiry())
	credid := NewCredentialTypeIdentifier("test.test.mijnirma")
	jwt := getIssuanceJwt("testip", id)
	jwt.(*IdentityProviderJwt).Request.Request.Credentials = append(
		jwt.(*IdentityProviderJwt).Request.Request.Credentials,
		&CredentialRequest{
			Validity:   &expiry,
			Credential: &credid,
			Attributes: map[string]string{"email": "example@example.com"},
		},
	)
	sessionHelper(t, jwt, "issue", manager)

	jwt = getDisclosureJwt("testsp", id)
	jwt.(*ServiceProviderJwt).Request.Request.Content = append(
		jwt.(*ServiceProviderJwt).Request.Request.Content,
		&AttributeDisjunction{
			Label:      "foo",
			Attributes: []AttributeTypeIdentifier{NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "verification", manager)

	jwt = getSigningJwt("testsigclient", id)
	jwt.(*SignatureRequestorJwt).Request.Request.Content = append(
		jwt.(*SignatureRequestorJwt).Request.Request.Content,
		&AttributeDisjunction{
			Label:      "foo",
			Attributes: []AttributeTypeIdentifier{NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "signature", manager)

	teardown(t)
}

// Use the existing keyshare registration and credentials deserialized from Android storage
// in a keyshare session of each session type.
// Use keyshareuser.sql to register the user at the keyshare server.
func TestKeyshareSessions(t *testing.T) {
	manager := parseStorage(t)
	id := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	expiry := Timestamp(NewMetadataAttribute().Expiry())
	credid := NewCredentialTypeIdentifier("test.test.mijnirma")
	jwt := getIssuanceJwt("testip", id)
	jwt.(*IdentityProviderJwt).Request.Request.Credentials = append(
		jwt.(*IdentityProviderJwt).Request.Request.Credentials,
		&CredentialRequest{
			Validity:   &expiry,
			Credential: &credid,
			Attributes: map[string]string{"email": "example@example.com"},
		},
	)
	sessionHelper(t, jwt, "issue", manager)

	jwt = getDisclosureJwt("testsp", id)
	jwt.(*ServiceProviderJwt).Request.Request.Content = append(
		jwt.(*ServiceProviderJwt).Request.Request.Content, //[]*AttributeDisjunction{},
		&AttributeDisjunction{
			Label:      "foo",
			Attributes: []AttributeTypeIdentifier{NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "verification", manager)

	jwt = getSigningJwt("testsigclient", id)
	jwt.(*SignatureRequestorJwt).Request.Request.Content = append(
		jwt.(*SignatureRequestorJwt).Request.Request.Content, //[]*AttributeDisjunction{},
		&AttributeDisjunction{
			Label:      "foo",
			Attributes: []AttributeTypeIdentifier{NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, jwt, "signature", manager)

	teardown(t)
}
