package sessiontest

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

func init() {
	irma.ForceHttps = false
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

func startSession(t *testing.T, request irma.SessionRequest, sessiontype string) (*irma.Qr, string) {
	var qr irma.Qr
	var err error
	var token string

	switch TestType {
	case "apiserver":
		url := "http://localhost:8088/irma_api_server/api/v2/" + sessiontype
		err = irma.NewHTTPTransport(url).Post("", &qr, getJwt(t, request, sessiontype, jwt.SigningMethodNone))
		token = qr.URL
		qr.URL = url + "/" + qr.URL
	case "irmaserver-jwt":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url).Post("session", &qr, getJwt(t, request, sessiontype, jwt.SigningMethodRS256))
		token = tokenFromURL(qr.URL)
	case "irmaserver-hmac-jwt":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url).Post("session", &qr, getJwt(t, request, sessiontype, jwt.SigningMethodHS256))
		token = tokenFromURL(qr.URL)
	case "irmaserver":
		url := "http://localhost:48682"
		err = irma.NewHTTPTransport(url).Post("session", &qr, request)
		token = tokenFromURL(qr.URL)
	default:
		t.Fatal("Invalid TestType")
	}

	require.NoError(t, err)
	return &qr, token
}

func tokenFromURL(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
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
		StartIrmaServer(JwtServerConfiguration)
		defer StopIrmaServer()
	}

	qr, _ := startSession(t, request, sessiontype)

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

func TestSigningSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getSigningRequest(id)
	sessionHelper(t, request, "signature", nil)
}

func TestDisclosureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)
	sessionHelper(t, request, "verification", nil)
}

func TestNoAttributeDisclosureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard")
	request := getDisclosureRequest(id)
	sessionHelper(t, request, "verification", nil)
}

func TestIssuanceSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getCombinedIssuanceRequest(id)
	sessionHelper(t, request, "issue", nil)
}

func TestDefaultCredentialValidity(t *testing.T) {
	client := parseStorage(t)
	request := getIssuanceRequest(true)
	sessionHelper(t, request, "issue", client)
}

func TestIssuanceOptionalEmptyAttributes(t *testing.T) {
	req := getNameIssuanceRequest()
	sessionHelper(t, req, "issue", nil)
}

func TestIssuanceOptionalZeroLengthAttributes(t *testing.T) {
	req := getNameIssuanceRequest()
	req.Credentials[0].Attributes["prefix"] = ""
	sessionHelper(t, req, "issue", nil)
}

func TestIssuanceOptionalSetAttributes(t *testing.T) {
	req := getNameIssuanceRequest()
	req.Credentials[0].Attributes["prefix"] = "van"
	sessionHelper(t, req, "issue", nil)
}

func TestLargeAttribute(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	require.NoError(t, client.RemoveAllCredentials())

	issuanceRequest := getSpecialIssuanceRequest(false, "1234567890123456789012345678901234567890") // 40 chars
	sessionHelper(t, issuanceRequest, "issue", client)

	disclosureRequest := getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"))
	sessionHelper(t, disclosureRequest, "verification", client)
}

func TestIssuanceSingletonCredential(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	request := getIssuanceRequest(true)
	credid := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")

	require.Nil(t, client.Attributes(credid, 0))

	sessionHelper(t, request, "issue", client)
	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))

	sessionHelper(t, request, "issue", client)
	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))
}

/* There is an annoying difference between how Java and Go convert big integers to and from
byte arrays: in Java the sign of the integer is taken into account, but not in Go. This means
that in Java, when converting a bigint to or from a byte array, the most significant bit
indicates the sign of the integer. In Go this is not the case. This resulted in invalid
signatures being issued in the issuance protocol in two distinct ways, of which we test here
that they have been fixed. */
func TestAttributeByteEncoding(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)
	require.NoError(t, client.RemoveAllCredentials())

	/* After bitshifting the presence bit into the large attribute below, the most significant
	bit is 1. In the bigint->[]byte conversion that happens before hashing this attribute, in
	Java this results in an extra 0 byte being prepended in order to have a 0 instead as most
	significant (sign) bit. We test that the Java implementation correctly removes the extraneous
	0 byte. */
	request := getSpecialIssuanceRequest(false, "a23456789012345678901234567890")
	sessionHelper(t, request, "issue", client)

	/* After converting the attribute below to bytes (using UTF8, on which Java and Go do agree),
	the most significant bit of the byte version of this attribute is 1. In the []byte->bigint
	conversion that happens at that point in the Java implementation (bitshifting is done
	afterwards), this results in a negative number in Java and a positive number in Go. We test
	here that the Java correctly prepends a 0 byte just before this conversion in order to get
	the same positive bigint. */
	request = getSpecialIssuanceRequest(false, "é")
	sessionHelper(t, request, "issue", client)
}

// Use the existing keyshare enrollment and credentials
// in a keyshare session of each session type.
// Use keyshareuser.sql to enroll the user at the keyshare server.
func TestKeyshareSessions(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	keyshareSessions(t, client)
}

func TestDisclosureNewAttributeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.False(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	disclosureRequest := irma.DisclosureRequest{
		Content: irma.AttributeDisjunctionList{
			&irma.AttributeDisjunction{
				Label: "foo",
				Attributes: []irma.AttributeTypeIdentifier{
					attrid,
				},
			},
		},
	}

	client.Configuration.Download(&disclosureRequest)
	require.True(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))
}

func TestIssueNewAttributeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.False(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	issuanceRequest.Credentials[0].Attributes["newAttribute"] = "foobar"
	client.Configuration.Download(issuanceRequest)
	require.True(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))
}

func TestIssueOptionalAttributeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")
	require.False(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid).IsOptional())

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	delete(issuanceRequest.Credentials[0].Attributes, "level")
	client.Configuration.Download(issuanceRequest)
	require.True(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid).IsOptional())
}

func TestIssueNewCredTypeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")

	delete(client.Configuration.CredentialTypes, credid)
	require.NotContains(t, client.Configuration.CredentialTypes, credid)

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	request := getIssuanceRequest(true)
	client.Configuration.Download(request)

	require.Contains(t, client.Configuration.CredentialTypes, credid)

	test.ClearTestStorage(t)
}

func TestDisclosureNewCredTypeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")

	delete(client.Configuration.CredentialTypes, credid)
	require.NotContains(t, client.Configuration.CredentialTypes, credid)

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	request := &irma.DisclosureRequest{
		Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{attrid},
		}}),
	}
	client.Configuration.Download(request)

	require.Contains(t, client.Configuration.CredentialTypes, credid)

	test.ClearTestStorage(t)
}

// Test installing a new scheme manager from a qr, and do a(n issuance) session
// within this manager to test the autmatic downloading of credential definitions,
// issuers, and public keys.
func TestDownloadSchemeManager(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	// Remove irma-demo scheme manager as we need to test adding it
	irmademo := irma.NewSchemeManagerIdentifier("irma-demo")
	require.Contains(t, client.Configuration.SchemeManagers, irmademo)
	require.NoError(t, client.Configuration.RemoveSchemeManager(irmademo, true))
	require.NotContains(t, client.Configuration.SchemeManagers, irmademo)

	// Do an add-scheme-manager-session
	c := make(chan *SessionResult)
	qr, err := json.Marshal(&irma.SchemeManagerRequest{
		Type: irma.ActionSchemeManager,
		URL:  "http://localhost:48681/irma_configuration/irma-demo",
	})
	require.NoError(t, err)
	client.NewSession(string(qr), TestHandler{t, c, client})
	if result := <-c; result != nil {
		require.NoError(t, result.Err)
	}
	require.Contains(t, client.Configuration.SchemeManagers, irmademo)

	// Do a session to test downloading of cred types, issuers and keys
	request := getCombinedIssuanceRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	sessionHelper(t, request, "issue", client)

	require.Contains(t, client.Configuration.SchemeManagers, irmademo)
	require.Contains(t, client.Configuration.Issuers, irma.NewIssuerIdentifier("irma-demo.RU"))
	require.Contains(t, client.Configuration.CredentialTypes, irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"))

	basepath := test.FindTestdataFolder(t) + "/storage/test/irma_configuration/irma-demo"
	exists, err := fs.PathExists(basepath + "/description.xml")
	require.NoError(t, err)
	require.True(t, exists)
	exists, err = fs.PathExists(basepath + "/RU/description.xml")
	require.NoError(t, err)
	require.True(t, exists)
	exists, err = fs.PathExists(basepath + "/RU/Issues/studentCard/description.xml")
	require.NoError(t, err)
	require.True(t, exists)
}
