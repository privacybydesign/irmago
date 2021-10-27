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
	"unsafe"

	"github.com/privacybydesign/irmago/server/requestorserver"

	jwt "github.com/dgrijalva/jwt-go"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/require"
)

// Defines the maximum protocol version of an irmaclient in tests
var maxClientVersion = &irma.ProtocolVersion{Major: 2, Minor: 8}

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

	// Set max version we want to test on
	version := extractClientMaxVersion(client)
	version.Major = maxClientVersion.Major
	version.Minor = maxClientVersion.Minor

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

func startSession(t *testing.T, request irma.SessionRequest, useJWTs bool) (*server.SessionPackage, *irma.FrontendSessionRequest) {
	var (
		sesPkg server.SessionPackage
		err    error
	)

	url := "http://localhost:48682"
	if useJWTs {
		err = irma.NewHTTPTransport(url, false).Post("session", &sesPkg, getJwt(t, request, jwt.SigningMethodRS256))
	} else {
		err = irma.NewHTTPTransport(url, false).Post("session", &sesPkg, request)
	}

	require.NoError(t, err)
	return &sesPkg, sesPkg.FrontendRequest
}

func getJwt(t *testing.T, request irma.SessionRequest, alg jwt.SigningMethod) string {
	var jwtcontents irma.RequestorJwt
	var kid string
	switch request.Action() {
	case irma.ActionIssuing:
		kid = "testip"
		jwtcontents = irma.NewIdentityProviderJwt("testip", request.(*irma.IssuanceRequest))
	case irma.ActionDisclosing:
		kid = "testsp"
		jwtcontents = irma.NewServiceProviderJwt("testsp", request.(*irma.DisclosureRequest))
	case irma.ActionSigning:
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
		bts, err := base64.StdEncoding.DecodeString(JwtServerConfiguration().Requestors["requestor3"].AuthenticationKey)
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

func sessionHelperWithFrontendOptions(
	t *testing.T,
	request irma.SessionRequest,
	sessiontype string,
	client *irmaclient.Client,
	frontendOptionsHandler func(handler *TestHandler),
	pairingHandler func(handler *TestHandler),
) {
	sessionHelperWithFrontendOptionsAndConfig(t, request, client, frontendOptionsHandler, pairingHandler, JwtServerConfiguration())
}

func sessionHelperWithFrontendOptionsAndConfig(
	t *testing.T,
	request irma.SessionRequest,
	client *irmaclient.Client,
	frontendOptionsHandler func(handler *TestHandler),
	pairingHandler func(handler *TestHandler),
	config *requestorserver.Configuration,
) string {
	if client == nil {
		var handler *TestClientHandler
		client, handler = parseStorage(t)
		defer test.ClearTestStorage(t, handler.storage)
	}

	if config != nil {
		rs := StartRequestorServer(t, config)
		defer rs.Stop()
	}

	sesPkg, frontendRequest := startSession(t, request, config != nil && !config.DisableRequestorAuthentication)

	c := make(chan *SessionResult)
	h := &TestHandler{
		t:                  t,
		c:                  c,
		client:             client,
		expectedServerName: expectedRequestorInfo(t, client.Configuration),
	}

	if frontendOptionsHandler != nil || pairingHandler != nil {
		h.pairingCodeChan = make(chan string)
		h.frontendTransport = irma.NewHTTPTransport(sesPkg.SessionPtr.URL, false)
		h.frontendTransport.SetHeader(irma.AuthorizationHeader, string(frontendRequest.Authorization))
	}
	if frontendOptionsHandler != nil {
		frontendOptionsHandler(h)
	}

	qrjson, err := json.Marshal(sesPkg.SessionPtr)
	require.NoError(t, err)
	h.dismisser = client.NewSession(string(qrjson), h)

	if pairingHandler != nil {
		pairingHandler(h)
	}

	if result := <-c; result != nil {
		require.NoError(t, result.Err)
	}

	var res string
	err = irma.NewHTTPTransport("http://localhost:48682/session/"+string(sesPkg.Token), false).Get("result-jwt", &res)
	require.NoError(t, err)

	return res
}

func sessionHelper(t *testing.T, request irma.SessionRequest, sessiontype string, client *irmaclient.Client) {
	sessionHelperWithFrontendOptions(t, request, sessiontype, client, nil, nil)
}

func extractClientTransport(dismisser irmaclient.SessionDismisser) *irma.HTTPTransport {
	return extractPrivateField(dismisser, "transport").(*irma.HTTPTransport)
}

func extractClientMaxVersion(client *irmaclient.Client) *irma.ProtocolVersion {
	return extractPrivateField(client, "maxVersion").(*irma.ProtocolVersion)
}

func extractPrivateField(i interface{}, field string) interface{} {
	rct := reflect.ValueOf(i).Elem().FieldByName(field)
	return reflect.NewAt(rct.Type(), unsafe.Pointer(rct.UnsafeAddr())).Elem().Interface()
}

func setPairingMethod(method irma.PairingMethod, handler *TestHandler) string {
	optionsRequest := irma.NewFrontendOptionsRequest()
	optionsRequest.PairingMethod = method
	options := &irma.SessionOptions{}
	err := handler.frontendTransport.Post("frontend/options", options, optionsRequest)
	require.NoError(handler.t, err)
	return options.PairingCode
}

func expectedRequestorInfo(t *testing.T, conf *irma.Configuration) *irma.RequestorInfo {
	if common.ForceHTTPS {
		return irma.NewRequestorInfo("localhost")
	}
	require.Contains(t, conf.Requestors, "localhost")
	return conf.Requestors["localhost"]
}
