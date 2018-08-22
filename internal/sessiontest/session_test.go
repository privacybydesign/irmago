package sessiontest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

func init() {
	irma.ForceHttps = false
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

	if !defaultValidity {
		expiry = &temp
	}

	return &irma.IssuanceRequest{
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

// startSession starts an IRMA session by posting the request,
// and retrieving the QR contents from the specified url.
func startSession(request interface{}, url string) (*irma.Qr, error) {
	server := irma.NewHTTPTransport(url)
	var response irma.Qr
	err := server.Post("", &response, request)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func sessionHelper(t *testing.T, jwtcontents interface{}, url string, client *irmaclient.Client) {
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
	qr, transportErr := startSession(jwt, url)
	if transportErr != nil {
		fmt.Printf("+%v\n", transportErr)
	}
	require.NoError(t, transportErr)
	qr.URL = url + "/" + qr.URL

	c := make(chan *SessionResult)
	h := TestHandler{t, c, client}
	j, err := json.Marshal(qr)
	require.NoError(t, err)
	client.NewSession(string(j), h)

	if result := <-c; result != nil {
		require.NoError(t, result.Err)
	}

	if init {
		test.ClearTestStorage(t)
	}
}

func keyshareSessions(t *testing.T, client *irmaclient.Client) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	expiry := irma.Timestamp(irma.NewMetadataAttribute(0).Expiry())
	jwt := getCombinedJwt("testip", id)
	jwt.(*irma.IdentityProviderJwt).Request.Request.Credentials = append(
		jwt.(*irma.IdentityProviderJwt).Request.Request.Credentials,
		&irma.CredentialRequest{
			Validity:         &expiry,
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
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

	jwtcontents = getDisclosureJwt("testsp", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"))
	sessionHelper(t, jwtcontents, "verification", client)

	test.ClearTestStorage(t)
}

func TestIssuanceSingletonCredential(t *testing.T) {
	client := parseStorage(t)
	jwtcontents := getIssuanceJwt("testip", true, "")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")

	require.Nil(t, client.Attributes(credid, 0))

	sessionHelper(t, jwtcontents, "issue", client)
	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))

	sessionHelper(t, jwtcontents, "issue", client)
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

// Use the existing keyshare enrollment and credentials
// in a keyshare session of each session type.
// Use keyshareuser.sql to enroll the user at the keyshare server.
func TestKeyshareSessions(t *testing.T) {
	client := parseStorage(t)

	keyshareSessions(t, client)

	test.ClearTestStorage(t)
}

func TestDisclosureNewAttributeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)

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

	test.ClearTestStorage(t)
}

func TestIssueNewAttributeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.False(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	issuanceRequest.Credentials[0].Attributes["newAttribute"] = "foobar"
	client.Configuration.Download(issuanceRequest)
	require.True(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	test.ClearTestStorage(t)
}

func TestIssueOptionalAttributeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")
	require.False(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid).IsOptional())

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	delete(issuanceRequest.Credentials[0].Attributes, "level")
	client.Configuration.Download(issuanceRequest)
	require.True(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid).IsOptional())

	test.ClearTestStorage(t)
}

// Test installing a new scheme manager from a qr, and do a(n issuance) session
// within this manager to test the autmatic downloading of credential definitions,
// issuers, and public keys.
func TestDownloadSchemeManager(t *testing.T) {
	client := parseStorage(t)

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
	jwt := getCombinedJwt("testip", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	sessionHelper(t, jwt, "issue", client)

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

	test.ClearTestStorage(t)
}
