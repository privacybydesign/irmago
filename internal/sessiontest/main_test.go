package sessiontest

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

func init() {
	irma.ForceHttps = false
}

func TestMain(m *testing.M) {
	// Create HTTP server for scheme managers
	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()

	test.CreateTestStorage(nil)
	defer test.ClearTestStorage(nil)

	os.Exit(m.Run())
}

func parseStorage(t *testing.T) *irmaclient.Client {
	test.SetupTestStorage(t)
	path := test.FindTestdataFolder(t)
	client, err := irmaclient.New(
		filepath.Join(path, "storage", "test"),
		filepath.Join(path, "irma_configuration"),
		"",
		&TestClientHandler{t: t},
	)
	require.NoError(t, err)
	return client
}

func getDisclosureRequest(id irma.AttributeTypeIdentifier) *irma.DisclosureRequest {
	return &irma.DisclosureRequest{
		BaseRequest: irma.BaseRequest{Type: irma.ActionDisclosing},
		Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{id},
		}}),
	}
}

func getSigningRequest(id irma.AttributeTypeIdentifier) *irma.SignatureRequest {
	return &irma.SignatureRequest{
		Message: "test",
		DisclosureRequest: irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{Type: irma.ActionSigning},
			Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
				Label:      "foo",
				Attributes: []irma.AttributeTypeIdentifier{id},
			}}),
		},
	}
}

func getIssuanceRequest(defaultValidity bool) *irma.IssuanceRequest {
	temp := irma.Timestamp(irma.FloorToEpochBoundary(time.Now().AddDate(1, 0, 0)))
	var expiry *irma.Timestamp

	if !defaultValidity {
		expiry = &temp
	}

	return &irma.IssuanceRequest{
		BaseRequest: irma.BaseRequest{Type: irma.ActionIssuing},
		Credentials: []*irma.CredentialRequest{
			{
				Validity:         expiry,
				CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
				Attributes: map[string]string{
					"university":        "Radboud",
					"studentCardNumber": "31415927",
					"studentID":         "s1234567",
					"level":             "42",
				},
			}, {
				Validity:         expiry,
				CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root"),
				Attributes: map[string]string{
					"BSN": "299792458",
				},
			},
		},
	}
}

func getNameIssuanceRequest() *irma.IssuanceRequest {
	expiry := irma.Timestamp(irma.NewMetadataAttribute(0).Expiry())

	req := &irma.IssuanceRequest{
		BaseRequest: irma.BaseRequest{Type: irma.ActionIssuing},
		Credentials: []*irma.CredentialRequest{
			{
				Validity:         &expiry,
				CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
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

func getSpecialIssuanceRequest(defaultValidity bool, attribute string) *irma.IssuanceRequest {
	request := getIssuanceRequest(defaultValidity)
	request.Credentials[0].Attributes["studentCardNumber"] = attribute
	return request
}

func getCombinedIssuanceRequest(id irma.AttributeTypeIdentifier) *irma.IssuanceRequest {
	request := getIssuanceRequest(false)
	request.Disclose = irma.AttributeDisjunctionList{
		&irma.AttributeDisjunction{Label: "foo", Attributes: []irma.AttributeTypeIdentifier{id}},
	}
	return request
}

var TestType = "irmaserver-jwt"

func startSession(t *testing.T, request irma.SessionRequest, sessiontype string) *irma.Qr {
	var qr irma.Qr
	var err error

	switch TestType {
	case "apiserver":
		url := "http://localhost:8088/irma_api_server/api/v2/" + sessiontype
		err = irma.NewHTTPTransport(url).Post("", &qr, getJwt(t, request, sessiontype, jwt.SigningMethodNone))
		qr.URL = url + "/" + qr.URL
	case "irmaserver-jwt":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url).Post("session", &qr, getJwt(t, request, sessiontype, jwt.SigningMethodRS256))
	case "irmaserver-hmac-jwt":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url).Post("session", &qr, getJwt(t, request, sessiontype, jwt.SigningMethodHS256))
	case "irmaserver":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url).Post("session", &qr, request)
	default:
		t.Fatal("Invalid TestType")
	}

	require.NoError(t, err)
	return &qr
}

func getJwt(t *testing.T, request irma.SessionRequest, sessiontype string, alg jwt.SigningMethod) string {
	var jwtcontents irma.RequestorJwt
	var kid string
	switch sessiontype {
	case "issue":
		kid = "testip"
		jwtcontents = irma.NewIdentityProviderJwt("testip", request.(*irma.IssuanceRequest))
	case "verification":
		kid = "testsp"
		jwtcontents = irma.NewServiceProviderJwt("testsp", request.(*irma.DisclosureRequest))
	case "signature":
		kid = "testsigclient"
		jwtcontents = irma.NewSignatureRequestorJwt("testsigclient", request.(*irma.SignatureRequest))
	}

	var j string
	var err error

	switch alg {
	case jwt.SigningMethodRS256:
		skbts, err := ioutil.ReadFile(filepath.Join(test.FindTestdataFolder(t), "jwtkeys", "requestor1-sk.pem"))
		require.NoError(t, err)
		sk, err := jwt.ParseRSAPrivateKeyFromPEM(skbts)
		require.NoError(t, err)
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtcontents)
		tok.Header["kid"] = "requestor1"
		j, err = tok.SignedString(sk)
	case jwt.SigningMethodHS256:
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtcontents)
		tok.Header["kid"] = "requestor3"
		bts, err := base64.StdEncoding.DecodeString(JwtServerConfiguration.Requestors["requestor3"].AuthenticationKey)
		require.NoError(t, err)
		j, err = tok.SignedString(bts)
	case jwt.SigningMethodNone:
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwtcontents)
		tok.Header["kid"] = kid
		j, err = tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	}
	require.NoError(t, err)

	return j
}

func sessionHelper(t *testing.T, request irma.SessionRequest, sessiontype string, client *irmaclient.Client) {
	if client == nil {
		client = parseStorage(t)
		defer test.ClearTestStorage(t)
	}

	if TestType == "irmaserver" || TestType == "irmaserver-jwt" || TestType == "irmaserver-hmac-jwt" {
		StartRequestorServer(JwtServerConfiguration)
		defer StopRequestorServer()
	}

	qr := startSession(t, request, sessiontype)

	c := make(chan *SessionResult)
	h := TestHandler{t, c, client}
	qrjson, err := json.Marshal(qr)
	require.NoError(t, err)
	client.NewSession(string(qrjson), h)

	if result := <-c; result != nil {
		require.NoError(t, result.Err)
	}
}

func keyshareSessions(t *testing.T, client *irmaclient.Client) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	expiry := irma.Timestamp(irma.NewMetadataAttribute(0).Expiry())
	issuanceRequest := getCombinedIssuanceRequest(id)
	issuanceRequest.Credentials = append(issuanceRequest.Credentials,
		&irma.CredentialRequest{
			Validity:         &expiry,
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes:       map[string]string{"email": "testusername"},
		},
	)
	sessionHelper(t, issuanceRequest, "issue", client)

	disclosureRequest := getDisclosureRequest(id)
	disclosureRequest.Content = append(disclosureRequest.Content,
		&irma.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, disclosureRequest, "verification", client)

	sigRequest := getSigningRequest(id)
	sigRequest.Content = append(sigRequest.Content,
		&irma.AttributeDisjunction{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		},
	)
	sessionHelper(t, sigRequest, "signature", client)
}
