package sessiontest

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

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

func TestMultipleIssuanceSession(t *testing.T) {
	request := getMultipleIssuanceRequest()
	sessionHelper(t, request, "issue", nil)
}

func TestDefaultCredentialValidity(t *testing.T) {
	client, _ := parseStorage(t)
	request := getIssuanceRequest(true)
	sessionHelper(t, request, "issue", client)
}

func TestIssuanceDisclosureEmptyAttributes(t *testing.T) {
	client, _ := parseStorage(t)
	defer test.ClearTestStorage(t)

	req := getNameIssuanceRequest()
	sessionHelper(t, req, "issue", client)

	// Test disclosing our null attribute
	req2 := getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.fullName.prefix"))
	res := requestorSessionHelper(t, req2, client)
	require.Nil(t, res.Err)
	require.Nil(t, res.Disclosed[0][0].RawValue)
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
	client, _ := parseStorage(t)
	defer test.ClearTestStorage(t)

	require.NoError(t, client.RemoveAllCredentials())

	issuanceRequest := getSpecialIssuanceRequest(false, "1234567890123456789012345678901234567890") // 40 chars
	sessionHelper(t, issuanceRequest, "issue", client)

	disclosureRequest := getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"))
	sessionHelper(t, disclosureRequest, "verification", client)
}

func TestIssuanceSingletonCredential(t *testing.T) {
	client, _ := parseStorage(t)
	defer test.ClearTestStorage(t)

	request := getMultipleIssuanceRequest()
	credid := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")

	require.Nil(t, client.Attributes(credid, 0))

	sessionHelper(t, request, "issue", client)
	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))

	sessionHelper(t, request, "issue", client)
	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))
}

func TestUnsatisfiableDisclosureSession(t *testing.T) {
	client, _ := parseStorage(t)
	defer test.ClearTestStorage(t)

	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.root.BSN"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.mijnirma.email"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
		},
	}

	missing := irmaclient.MissingAttributes{}
	require.NoError(t, json.Unmarshal([]byte(`{
		"0": {
			"0": {
				"0": {"type": "irma-demo.MijnOverheid.root.BSN"}
			},
			"1": {
				"1": {"type": "irma-demo.MijnOverheid.fullName.firstname"},
				"2": {"type": "irma-demo.MijnOverheid.fullName.familyname"}
			}
		}
	}`), &missing))
	require.True(t, reflect.DeepEqual(
		missing,
		requestorSessionHelper(t, request, client, sessionOptionUnsatisfiableRequest).Missing),
	)
}

/* There is an annoying difference between how Java and Go convert big integers to and from
byte arrays: in Java the sign of the integer is taken into account, but not in Go. This means
that in Java, when converting a bigint to or from a byte array, the most significant bit
indicates the sign of the integer. In Go this is not the case. This resulted in invalid
signatures being issued in the issuance protocol in two distinct ways, of which we test here
that they have been fixed. */
func TestAttributeByteEncoding(t *testing.T) {
	client, _ := parseStorage(t)
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

func TestOutdatedClientIrmaConfiguration(t *testing.T) {
	client, _ := parseStorage(t)
	defer test.ClearTestStorage(t)

	// Remove old studentCard credential from before support for optional attributes, and issue a new one
	require.NoError(t, client.RemoveAllCredentials())
	require.Nil(t, requestorSessionHelper(t, getIssuanceRequest(true), client).Err)

	// client does not have updated irma_configuration with new attribute irma-demo.RU.studentCard.newAttribute,
	// and the server does. Disclose an attribute from this credential. The client implicitly discloses value 0
	// for the new attribute, and the server accepts.
	req := getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"))
	require.Nil(t, requestorSessionHelper(t, req, client, sessionOptionUpdatedIrmaConfiguration).Err)
}

func TestDisclosureNewAttributeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	defer test.ClearTestStorage(t)

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.False(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	// Remove old studentCard credential from before support for optional attributes, and issue a new one
	require.NoError(t, client.RemoveAllCredentials())
	require.Nil(t, requestorSessionHelper(t, getIssuanceRequest(true), client).Err)

	// Trigger downloading the updated irma_configuration using a disclosure request containing the
	// new attribute, and inform the client
	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	newAttrRequest := irma.NewDisclosureRequest(attrid)
	downloaded, err := client.Configuration.Download(newAttrRequest)
	require.NoError(t, err)
	require.NoError(t, client.ConfigurationUpdated(downloaded))

	// Our new attribute now exists in the configuration
	require.True(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	// Disclose an old attribute (i.e. not newAttribute) to a server with an old configuration
	// Since our client has a new configuration it hides the new attribute that is not yet in the
	// server's configuration. All proofs are however valid as they should be and the server accepts.
	levelRequest := getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"))
	require.Nil(t, requestorSessionHelper(t, levelRequest, client).Err)

	// Disclose newAttribute to a server with a new configuration. This attribute was added
	// after we received a credential without it, so its value in this credential is 0.
	res := requestorSessionHelper(t, newAttrRequest, client, sessionOptionUpdatedIrmaConfiguration)
	require.Nil(t, res.Err)
	require.Nil(t, res.Disclosed[0][0].RawValue)
}

func TestIssueNewAttributeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	defer test.ClearTestStorage(t)

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.False(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	issuanceRequest.Credentials[0].Attributes["newAttribute"] = "foobar"
	_, err := client.Configuration.Download(issuanceRequest)
	require.NoError(t, err)
	require.True(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))
}

func TestIssueOptionalAttributeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	defer test.ClearTestStorage(t)

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")
	require.False(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid).IsOptional())

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	delete(issuanceRequest.Credentials[0].Attributes, "level")
	_, err := client.Configuration.Download(issuanceRequest)
	require.NoError(t, err)
	require.True(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid).IsOptional())
}

func TestIssueNewCredTypeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")

	delete(client.Configuration.CredentialTypes, credid)
	require.NotContains(t, client.Configuration.CredentialTypes, credid)

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	request := getIssuanceRequest(true)
	_, err := client.Configuration.Download(request)
	require.NoError(t, err)

	require.Contains(t, client.Configuration.CredentialTypes, credid)

	test.ClearTestStorage(t)
}

func TestDisclosureNewCredTypeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")

	delete(client.Configuration.CredentialTypes, credid)
	require.NotContains(t, client.Configuration.CredentialTypes, credid)

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	request := irma.NewDisclosureRequest(attrid)
	_, err := client.Configuration.Download(request)
	require.NoError(t, err)
	require.Contains(t, client.Configuration.CredentialTypes, credid)

	test.ClearTestStorage(t)
}

func TestDisclosureNonexistingCredTypeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	request := irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.foo.bar"),
		irma.NewAttributeTypeIdentifier("irma-demo.baz.qux.abc"),
	)
	_, err := client.Configuration.Download(request)
	require.Error(t, err)

	expectedErr := &irma.UnknownIdentifierError{
		ErrorType: irma.ErrorUnknownIdentifier,
		Missing: &irma.IrmaIdentifierSet{
			SchemeManagers: map[irma.SchemeManagerIdentifier]struct{}{},
			PublicKeys:     map[irma.IssuerIdentifier][]int{},
			Issuers: map[irma.IssuerIdentifier]struct{}{
				irma.NewIssuerIdentifier("irma-demo.baz"): struct{}{},
			},
			CredentialTypes: map[irma.CredentialTypeIdentifier]struct{}{
				irma.NewCredentialTypeIdentifier("irma-demo.RU.foo"):  struct{}{},
				irma.NewCredentialTypeIdentifier("irma-demo.baz.qux"): struct{}{},
			},
		},
	}
	require.True(t, reflect.DeepEqual(expectedErr, err), "Download() returned incorrect missing identifier set")
}

// Test installing a new scheme manager from a qr, and do a(n issuance) session
// within this manager to test the autmatic downloading of credential definitions,
// issuers, and public keys.
func TestDownloadSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
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
	client.NewSession(string(qr), TestHandler{t, c, client, nil})
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
