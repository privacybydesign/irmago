package sessiontest

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func init() {
	irma.ForceHttps = false
	irma.Logger.SetLevel(logrus.WarnLevel)
}

func TestMain(m *testing.M) {
	// Create HTTP server for scheme managers
	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()

	test.CreateTestStorage(nil)
	defer test.ClearTestStorage(nil)

	os.Exit(m.Run())
}

func parseStorage(t *testing.T) (*irmaclient.Client, *TestClientHandler) {
	test.SetupTestStorage(t)
	return parseExistingStorage(t)
}

func parseExistingStorage(t *testing.T) (*irmaclient.Client, *TestClientHandler) {
	handler := &TestClientHandler{t: t, c: make(chan error)}
	path := test.FindTestdataFolder(t)
	client, err := irmaclient.New(
		filepath.Join(path, "tmp", "client"),
		filepath.Join(path, "irma_configuration"),
		handler,
	)
	require.NoError(t, err)
	return client, handler
}

func getDisclosureRequest(id irma.AttributeTypeIdentifier) *irma.DisclosureRequest {
	return irma.NewDisclosureRequest(id)
}

func getSigningRequest(id irma.AttributeTypeIdentifier) *irma.SignatureRequest {
	return irma.NewSignatureRequest("test", id)
}

func getIssuanceRequest(defaultValidity bool) *irma.IssuanceRequest {
	temp := irma.Timestamp(irma.FloorToEpochBoundary(time.Now().AddDate(1, 0, 0)))
	var expiry *irma.Timestamp
	if !defaultValidity {
		expiry = &temp
	}
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			Validity:         expiry,
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "Radboud",
				"studentCardNumber": "31415927",
				"studentID":         "s1234567",
				"level":             "42",
			},
		},
	})
}

func getNameIssuanceRequest() *irma.IssuanceRequest {
	expiry := irma.Timestamp(irma.NewMetadataAttribute(0).Expiry())
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			Validity:         &expiry,
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
			Attributes: map[string]string{
				"firstnames": "Johan Pieter",
				"firstname":  "Johan",
				"familyname": "Stuivezand",
			},
		},
	})

}

func getSpecialIssuanceRequest(defaultValidity bool, attribute string) *irma.IssuanceRequest {
	request := getIssuanceRequest(defaultValidity)
	request.Credentials[0].Attributes["studentCardNumber"] = attribute
	return request
}

func getCombinedIssuanceRequest(id irma.AttributeTypeIdentifier) *irma.IssuanceRequest {
	request := getIssuanceRequest(false)
	request.AddSingle(id, nil, nil)
	return request
}

func getMultipleIssuanceRequest() *irma.IssuanceRequest {
	request := getIssuanceRequest(false)
	request.Credentials = append(request.Credentials, &irma.CredentialRequest{
		Validity:         request.Credentials[0].Validity,
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root"),
		Attributes: map[string]string{
			"BSN": "299792458",
		},
	})
	return request
}

var TestType = "irmaserver-jwt"

func startSession(t *testing.T, request irma.SessionRequest, sessiontype string) *irma.Qr {
	var (
		qr     *irma.Qr = new(irma.Qr)
		sesPkg server.SessionPackage
		err    error
	)

	switch TestType {
	case "apiserver":
		url := "http://localhost:8088/irma_api_server/api/v2/" + sessiontype
		err = irma.NewHTTPTransport(url).Post("", qr, getJwt(t, request, sessiontype, jwt.SigningMethodNone))
		qr.URL = url + "/" + qr.URL
	case "irmaserver-jwt":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url).Post("session", &sesPkg, getJwt(t, request, sessiontype, jwt.SigningMethodRS256))
		qr = sesPkg.SessionPtr
	case "irmaserver-hmac-jwt":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url).Post("session", &sesPkg, getJwt(t, request, sessiontype, jwt.SigningMethodHS256))
		qr = sesPkg.SessionPtr
	case "irmaserver":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url).Post("session", &sesPkg, request)
		qr = sesPkg.SessionPtr
	default:
		t.Fatal("Invalid TestType")
	}

	require.NoError(t, err)
	return qr
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
		require.NoError(t, err)
	case jwt.SigningMethodHS256:
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtcontents)
		tok.Header["kid"] = "requestor3"
		bts, err := base64.StdEncoding.DecodeString(JwtServerConfiguration.Requestors["requestor3"].AuthenticationKey)
		require.NoError(t, err)
		j, err = tok.SignedString(bts)
		require.NoError(t, err)
	case jwt.SigningMethodNone:
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwtcontents)
		tok.Header["kid"] = kid
		j, err = tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)
	}

	return j
}

func sessionHelper(t *testing.T, request irma.SessionRequest, sessiontype string, client *irmaclient.Client) {
	if client == nil {
		client, _ = parseStorage(t)
		defer test.ClearTestStorage(t)
	}

	if TestType == "irmaserver" || TestType == "irmaserver-jwt" || TestType == "irmaserver-hmac-jwt" {
		StartRequestorServer(JwtServerConfiguration)
		defer StopRequestorServer()
	}

	qr := startSession(t, request, sessiontype)

	c := make(chan *SessionResult)
	h := &TestHandler{t: t, c: c, client: client, expectedServerName: expectedServerName(t, request, client.Configuration)}
	qrjson, err := json.Marshal(qr)
	require.NoError(t, err)
	client.NewSession(string(qrjson), h)

	if result := <-c; result != nil {
		require.NoError(t, result.Err)
	}
}

func expectedServerName(t *testing.T, request irma.SessionRequest, conf *irma.Configuration) irma.TranslatedString {
	localhost := "localhost"
	host := irma.NewTranslatedString(&localhost)

	ir, ok := request.(*irma.IssuanceRequest)
	if !ok {
		return host
	}

	// In issuance sessions, the server name is expected to be:
	// - the name of the issuer, if there is just one issuer
	// - the hostname as usual otherwise

	var name irma.TranslatedString
	for _, credreq := range ir.Credentials {
		n := conf.Issuers[credreq.CredentialTypeID.IssuerIdentifier()].Name
		if !reflect.DeepEqual(name, n) {
			if len(name) != 0 {
				return host
			}
			name = n
		}
	}

	return name
}
