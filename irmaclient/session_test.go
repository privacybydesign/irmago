package irmaclient

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"math/big"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

type TestHandler struct {
	t      *testing.T
	c      chan *irma.SessionError
	client *Client
}

func (th TestHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	th.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.New("KeyshareEnrollmentIncomplete")})
}

func (th TestHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	th.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.New("KeyshareBlocked")})
}

func (th TestHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	th.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.Errorf("Missing keyshare server %s", manager.String())})
}

func (th TestHandler) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	th.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.Errorf("Keyshare enrollment deleted for %s", manager.String())})
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
func (th TestHandler) UnsatisfiableRequest(action irma.Action, serverName string, missing irma.AttributeDisjunctionList) {
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
		if len(candidates) == 0 {
			th.Failure(irma.ActionUnknown, &irma.SessionError{Err: errors.New("No disclosure candidates found")})
		}
		choice.Attributes = append(choice.Attributes, candidates[0])
	}
	callback(true, choice)
}
func (th TestHandler) RequestIssuancePermission(request irma.IssuanceRequest, ServerName string, callback PermissionHandler) {
	dreq := irma.DisclosureRequest{
		BaseRequest: request.BaseRequest,
		Content:     request.Disclose,
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
		Message: "test",
		DisclosureRequest: irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{
				Nonce:   big.NewInt(1),
				Context: big.NewInt(1),
			},
			Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
				Label:      "foo",
				Attributes: []irma.AttributeTypeIdentifier{id},
			}}),
		},
	})
}

func getIssuanceRequest(defaultValidity bool) *irma.IssuanceRequest {
	temp := irma.Timestamp(irma.FloorToEpochBoundary(time.Now().AddDate(1, 0, 0)))
	var expiry *irma.Timestamp
	credid1 := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	credid2 := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")

	if !defaultValidity {
		expiry = &temp
	}

	return &irma.IssuanceRequest{
		Credentials: []*irma.CredentialRequest{
			{
				Validity:         expiry,
				CredentialTypeID: &credid1,
				Attributes: map[string]string{
					"university":        "Radboud",
					"studentCardNumber": "31415927",
					"studentID":         "s1234567",
					"level":             "42",
				},
			}, {
				Validity:         expiry,
				CredentialTypeID: &credid2,
				Attributes: map[string]string{
					"BSN": "299792458",
				},
			},
		},
	}
}

func getNameIssuanceRequest() *irma.IssuanceRequest {
	expiry := irma.Timestamp(irma.NewMetadataAttribute(0).Expiry())
	credid := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName")

	req := &irma.IssuanceRequest{
		Credentials: []*irma.CredentialRequest{
			{
				Validity:         &expiry,
				CredentialTypeID: &credid,
				Attributes: map[string]string{
					"firstnames": "Johan Pieter",
					"firstname":  "Johan",
					"familyname": "Stuivezand",
				},
			},
		},
	}

	return req
}

func getIssuanceJwt(name string, defaultValidity bool, attribute string) interface{} {
	jwt := irma.NewIdentityProviderJwt(name, getIssuanceRequest(defaultValidity))
	if attribute != "" {
		jwt.Request.Request.Credentials[0].Attributes["studentCardNumber"] = attribute
	}
	return jwt

}

func getCombinedJwt(name string, id irma.AttributeTypeIdentifier) interface{} {
	isreq := getIssuanceRequest(false)
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

func TestNoAttributeDisclosureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard")
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

func TestDefaultCredentialValidity(t *testing.T) {
	client := parseStorage(t)
	jwtcontents := getIssuanceJwt("testip", true, "")
	sessionHelper(t, jwtcontents, "issue", client)
}

func TestIssuanceOptionalEmptyAttributes(t *testing.T) {
	req := getNameIssuanceRequest()
	jwt := irma.NewIdentityProviderJwt("testip", req)
	sessionHelper(t, jwt, "issue", nil)
}

func TestIssuanceOptionalZeroLengthAttributes(t *testing.T) {
	req := getNameIssuanceRequest()
	req.Credentials[0].Attributes["prefix"] = ""
	jwt := irma.NewIdentityProviderJwt("testip", req)
	sessionHelper(t, jwt, "issue", nil)
}

func TestIssuanceOptionalSetAttributes(t *testing.T) {
	req := getNameIssuanceRequest()
	req.Credentials[0].Attributes["prefix"] = "van"
	jwt := irma.NewIdentityProviderJwt("testip", req)
	sessionHelper(t, jwt, "issue", nil)
}

func TestLargeAttribute(t *testing.T) {
	client := parseStorage(t)
	require.NoError(t, client.RemoveAllCredentials())

	jwtcontents := getIssuanceJwt("testip", false, "1234567890123456789012345678901234567890") // 40 chars
	sessionHelper(t, jwtcontents, "issue", client)

	cred, err := client.credential(irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"), 0)
	require.NoError(t, err)
	require.True(t, cred.Signature.Verify(cred.Pk, cred.Attributes))

	jwtcontents = getDisclosureJwt("testsp", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"))
	sessionHelper(t, jwtcontents, "verification", client)

	test.ClearTestStorage(t)
}

func TestIssuanceSingletonCredential(t *testing.T) {
	client := parseStorage(t)
	jwtcontents := getIssuanceJwt("testip", true, "")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")

	require.Len(t, client.attrs(credid), 0)

	sessionHelper(t, jwtcontents, "issue", client)
	require.Len(t, client.attrs(credid), 1)

	sessionHelper(t, jwtcontents, "issue", client)
	require.Len(t, client.attrs(credid), 1)
}

/* There is an annoying difference between how Java and Go convert big integers to and from
byte arrays: in Java the sign of the integer is taken into account, but not in Go. This means
that in Java, when converting a bigint to or from a byte array, the most significant bit
indicates the sign of the integer. In Go this is not the case. This resulted in invalid
signatures being issued in the issuance protocol in two distinct ways, of which we test here
that they have been fixed. */
func TestAttributeByteEncoding(t *testing.T) {
	client := parseStorage(t)
	require.NoError(t, client.RemoveAllCredentials())

	/* After bitshifting the presence bit into the large attribute below, the most significant
	bit is 1. In the bigint->[]byte conversion that happens before hashing this attribute, in
	Java this results in an extra 0 byte being prepended in order to have a 0 instead as most
	significant (sign) bit. We test that the Java implementation correctly removes the extraneous
	0 byte. */
	jwtcontents := getIssuanceJwt("testip", false, "a23456789012345678901234567890")
	sessionHelper(t, jwtcontents, "issue", client)

	/* After converting the attribute below to bytes (using UTF8, on which Java and Go do agree),
	the most significant bit of the byte version of this attribute is 1. In the []byte->bigint
	conversion that happens at that point in the Java implementation (bitshifting is done
	afterwards), this results in a negative number in Java and a positive number in Go. We test
	here that the Java correctly prepends a 0 byte just before this conversion in order to get
	the same positive bigint. */
	jwtcontents = getIssuanceJwt("testip", false, "é")
	sessionHelper(t, jwtcontents, "issue", client)

	test.ClearTestStorage(t)
}

func sessionHelper(t *testing.T, jwtcontents interface{}, url string, client *Client) {
	sessionHandlerHelper(t, jwtcontents, url, client, nil)
}

func sessionHandlerHelper(t *testing.T, jwtcontents interface{}, url string, client *Client, h Handler) {
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
	if h == nil {
		h = TestHandler{t, c, client}
	}
	client.NewSession(qr, h)

	if err := <-c; err != nil {
		t.Fatal(*err)
	}

	if init {
		test.ClearTestStorage(t)
	}
}

func keyshareSessions(t *testing.T, client *Client) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	expiry := irma.Timestamp(irma.NewMetadataAttribute(0).Expiry())
	credid := irma.NewCredentialTypeIdentifier("test.test.mijnirma")
	jwt := getCombinedJwt("testip", id)
	jwt.(*irma.IdentityProviderJwt).Request.Request.Credentials = append(
		jwt.(*irma.IdentityProviderJwt).Request.Request.Credentials,
		&irma.CredentialRequest{
			Validity:         &expiry,
			CredentialTypeID: &credid,
			Attributes:       map[string]string{"email": "testusername"},
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
}

// Test pinchange interaction
func TestKeyshareChangePin(t *testing.T) {
	client := parseStorage(t)

	require.NoError(t, client.keyshareChangePinWorker(irma.NewSchemeManagerIdentifier("test"), "12345", "54321"))
	require.NoError(t, client.keyshareChangePinWorker(irma.NewSchemeManagerIdentifier("test"), "54321", "12345"))

	test.ClearTestStorage(t)
}

// Enroll at a keyshare server and do an issuance, disclosure,
// and issuance session, also using irma-demo credentials deserialized from Android storage
func TestKeyshareEnrollmentAndSessions(t *testing.T) {
	client := parseStorage(t)
	credtype := irma.NewCredentialTypeIdentifier("test.test.mijnirma")

	// Remove existing registration at test keyshare server
	require.NoError(t, client.RemoveCredentialByHash(
		client.Attributes(credtype, 0).Hash(),
	))
	require.NoError(t, client.KeyshareRemove(irma.NewSchemeManagerIdentifier("test")))

	// Do a new registration session
	c := make(chan error) // channel for TestClientHandler to inform us of result
	client.handler.(*TestClientHandler).c = c
	bytes := make([]byte, 8, 8)
	rand.Read(bytes)
	require.NoError(t, client.keyshareEnrollWorker(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en"))
	if err := <-c; err != nil {
		t.Fatal(err)
	}

	require.NotNil(t, client.Attributes(credtype, 0))

	keyshareSessions(t, client)

	test.ClearTestStorage(t)
}

// Use the existing keyshare enrollment and credentials deserialized from Android storage
// in a keyshare session of each session type.
// Use keyshareuser.sql to enroll the user at the keyshare server.
func TestKeyshareSessions(t *testing.T) {
	client := parseStorage(t)

	keyshareSessions(t, client)

	test.ClearTestStorage(t)
}
