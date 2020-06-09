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
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Create HTTP server for scheme managers
	test.StartSchemeManagerHttpServer()

	retval := m.Run()

	test.StopSchemeManagerHttpServer()
	test.ClearAllTestStorage()

	os.Exit(retval)
}

func parseStorage(t *testing.T) (*irmaclient.Client, *TestClientHandler) {
	storage := test.SetupTestStorage(t)
	return parseExistingStorage(t, storage)
}

func parseExistingStorage(t *testing.T, storage string) (*irmaclient.Client, *TestClientHandler) {
	handler := &TestClientHandler{t: t, c: make(chan error), storage: storage}
	path := test.FindTestdataFolder(t)
	client, err := irmaclient.New(
		filepath.Join(storage, "client"),
		filepath.Join(path, "irma_configuration"),
		handler,
	)
	require.NoError(t, err)
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
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
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
		Attributes: map[string]string{
			"firstnames": "Johan Pieter",
			"firstname":  "Johan",
			"familyname": "Stuivezand",
		},
	})
	return request
}

var TestType = "irmaserver-jwt"

func startSession(t *testing.T, request irma.SessionRequest, sessiontype string) (*server.SessionPackage, irma.FrontendToken) {
	var (
		sesPkg server.SessionPackage
		err    error
	)

	switch TestType {
	case "irmaserver-jwt":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url, false).Post("session", &sesPkg, getJwt(t, request, sessiontype, jwt.SigningMethodRS256))
	case "irmaserver-hmac-jwt":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url, false).Post("session", &sesPkg, getJwt(t, request, sessiontype, jwt.SigningMethodHS256))
	case "irmaserver":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url, false).Post("session", &sesPkg, request)
	default:
		t.Fatal("Invalid TestType")
	}

	require.NoError(t, err)
	return &sesPkg, sesPkg.FrontendToken
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

func sessionHelper(t *testing.T, request irma.SessionRequest, sessiontype string, client *irmaclient.Client) string {
	if client == nil {
		var handler *TestClientHandler
		client, handler = parseStorage(t)
		defer test.ClearTestStorage(t, handler.storage)
	}

	if TestType == "irmaserver" || TestType == "irmaserver-jwt" || TestType == "irmaserver-hmac-jwt" {
		StartRequestorServer(JwtServerConfiguration)
		defer StopRequestorServer()
	}

	sesPkg, _ := startSession(t, request, sessiontype)

	c := make(chan *SessionResult)
	h := &TestHandler{t: t, c: c, client: client, expectedServerName: expectedRequestorInfo(t, client.Configuration)}
	qrjson, err := json.Marshal(sesPkg.SessionPtr)
	require.NoError(t, err)
	client.NewSession(string(qrjson), h)

	if result := <-c; result != nil {
		require.NoError(t, result.Err)
	}

	var resJwt string
	err = irma.NewHTTPTransport("http://localhost:48682/session/"+sesPkg.Token, false).Get("result-jwt", &resJwt)
	require.NoError(t, err)

	return resJwt
}

func sessionHelperWithBinding(t *testing.T, request irma.SessionRequest, sessiontype string, client *irmaclient.Client,
	bindingCheck func(t *testing.T, transport *irma.HTTPTransport)) {
	if client == nil {
		var handler *TestClientHandler
		client, handler = parseStorage(t)
		defer test.ClearTestStorage(t, handler.storage)
	}

	if TestType == "irmaserver" || TestType == "irmaserver-jwt" || TestType == "irmaserver-hmac-jwt" {
		StartRequestorServer(JwtServerConfiguration)
		defer StopRequestorServer()
	}

	sesPkg, frontendToken := startSession(t, request, sessiontype)
	optionsRequest := irma.NewOptionsRequest()
	optionsRequest.EnableBinding = true
	options := &server.SessionOptions{}
	transport := irma.NewHTTPTransport(sesPkg.SessionPtr.URL, false)
	transport.SetHeader(irma.AuthorizationHeader, frontendToken)
	err := transport.Post("options", options, optionsRequest)
	require.NoError(t, err)
	require.Equal(t, true, options.BindingEnabled)
	require.Equal(t, false, options.BindingCompleted)

	c := make(chan *SessionResult)
	cBindingCode := make(chan string)
	h := &TestHandler{
		t:                  t,
		c:                  c,
		client:             client,
		expectedServerName: expectedRequestorInfo(t, client.Configuration),
		bindingCodeChan:    cBindingCode,
	}

	qrjson, err := json.Marshal(sesPkg.SessionPtr)
	require.NoError(t, err)
	client.NewSession(string(qrjson), h)

	// Binding can only be done from protocol version 2.7
	if _, max := client.GetSupportedVersions(); max.Above(2, 6) {
		bindingCode := <-cBindingCode
		bindingCheck(t, transport)
		require.Equal(t, options.BindingCode, bindingCode)
		optionsRequest = irma.NewOptionsRequest()
		optionsRequest.BindingCompleted = true
		options = &server.SessionOptions{}
		err = transport.Post("options", options, optionsRequest)
		require.NoError(t, err)
		require.Equal(t, true, options.BindingEnabled)
		require.Equal(t, true, options.BindingCompleted)
	}

	if result := <-c; result != nil {
		require.NoError(t, result.Err)
	}
}

func expectedRequestorInfo(t *testing.T, conf *irma.Configuration) *irma.RequestorInfo {
	if common.ForceHTTPS {
		return irma.NewRequestorInfo("localhost")
	}
	require.Contains(t, conf.Requestors, "localhost")
	return conf.Requestors["localhost"]
}
