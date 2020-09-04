package sessiontest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"

	"github.com/dgrijalva/jwt-go"
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
	responseString := sessionHelper(t, request, "verification", nil)

	// Validate JWT
	claims := struct {
		jwt.StandardClaims
		*server.SessionResult
	}{}
	_, err := jwt.ParseWithClaims(responseString, &claims, func(token *jwt.Token) (interface{}, error) {
		return &JwtServerConfiguration.JwtRSAPrivateKey.PublicKey, nil
	})
	require.NoError(t, err)

	// Check default expiration time
	require.True(t, claims.IssuedAt+irma.DefaultJwtValidity == claims.ExpiresAt)
}

func TestNoAttributeDisclosureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard")
	request := getDisclosureRequest(id)
	sessionHelper(t, request, "verification", nil)
}

func TestEmptyDisclosure(t *testing.T) {
	// Disclosure request asking for an attribute value that the client doesn't have,
	// and an empty conjunction as first option, which is always chosen by the test session handler
	val := "client doesn't have this attr"
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{},
			irma.AttributeCon{{Type: irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"), Value: &val}},
		},
	}

	res := requestorSessionHelper(t, request, nil)
	require.Nil(t, res.Err)
	require.NotNil(t, res.SessionResult)
	require.NotEmpty(t, res.SessionResult.Disclosed) // The outer conjunction was satisfied
	require.Empty(t, res.SessionResult.Disclosed[0]) // by the empty set, so we get no attributes
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
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	request := getIssuanceRequest(true)
	sessionHelper(t, request, "issue", client)
}

func TestIssuanceDisclosureEmptyAttributes(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

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

func TestIssuanceSameAttributesNotSingleton(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	prevLen := len(client.CredentialInfoList())

	req := getIssuanceRequest(true)
	sessionHelper(t, req, "issue", client)

	req = getIssuanceRequest(false)
	sessionHelper(t, req, "issue", client)
	require.Equal(t, prevLen+1, len(client.CredentialInfoList()))

	// Also check whether this is actually stored
	require.NoError(t, client.Close())
	client, handler = parseExistingStorage(t, handler.storage)
	require.Equal(t, prevLen+1, len(client.CredentialInfoList()))
}

func TestIssuanceBinding(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getCombinedIssuanceRequest(id)

	var bindingCode string
	frontendOptionsHandler := func(handler *TestHandler) {
		bindingCode = setBindingMethod(irma.BindingMethodPin, handler)
	}
	bindingHandler := func(handler *TestHandler) {
		if extractClientMaxVersion(handler.client).Above(2, 6) {
			require.Equal(t, bindingCode, <-handler.bindingCodeChan)

			// Check whether access to request endpoint is denied as long as binding is not finished
			clientTransport := extractClientTransport(handler.dismisser)
			err := clientTransport.Get("request", struct{}{})
			require.Error(t, err)
			require.Equal(t, 403, err.(*irma.SessionError).RemoteStatus)

			// Check whether binding cannot be disabled again after client is connected.
			request := irma.NewOptionsRequest()
			result := &irma.SessionOptions{}
			err = handler.frontendTransport.Post("frontend/options", result, request)
			require.Error(t, err)

			err = handler.frontendTransport.Post("frontend/bindingcompleted", nil, nil)
			require.NoError(handler.t, err)
		}
	}
	sessionHelperWithFrontendOptions(t, request, "issue", nil, frontendOptionsHandler, bindingHandler)
}

func TestLargeAttribute(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})

	issuanceRequest := getSpecialIssuanceRequest(false, "1234567890123456789012345678901234567890") // 40 chars
	sessionHelper(t, issuanceRequest, "issue", client)

	disclosureRequest := getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"))
	sessionHelper(t, disclosureRequest, "verification", client)
}

func TestIssuanceSingletonCredential(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	credid := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.singleton")
	request := getIssuanceRequest(false)
	request.Credentials = append(request.Credentials, &irma.CredentialRequest{
		Validity:         request.Credentials[0].Validity,
		CredentialTypeID: credid,
		Attributes: map[string]string{
			"BSN": "299792458",
		},
	})

	require.Nil(t, client.Attributes(credid, 0))

	sessionHelper(t, request, "issue", client)
	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))

	sessionHelper(t, request, "issue", client)
	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))

	// Also check whether this is actually stored
	require.NoError(t, client.Close())
	client, handler = parseExistingStorage(t, handler.storage)
	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))
}

func TestUnsatisfiableDisclosureSession(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

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

	missing := [][]irmaclient.DisclosureCandidates{}
	require.NoError(t, json.Unmarshal([]byte(`[[[{"Type":"irma-demo.MijnOverheid.root.BSN","CredentialHash":"","Expired":false,"Revoked":false,"NotRevokable":false},{"Type":"irma-demo.RU.studentCard.level","CredentialHash":"5ac19c13941eb3b3687511a526adc1fdfa7a8c1bc976634e202671c2ba38c9fa","Expired":false,"Revoked":false,"NotRevokable":false}],[{"Type":"irma-demo.MijnOverheid.root.BSN","CredentialHash":"","Expired":false,"Revoked":false,"NotRevokable":false},{"Type":"irma-demo.RU.studentCard.level","CredentialHash":"","Expired":false,"Revoked":false,"NotRevokable":false}],[{"Type":"test.test.mijnirma.email","CredentialHash":"dc8d5f252ae0e87db6136ba74598682158bfe8d0d2e2fc4ee61dbf24aa2746d4","Expired":false,"Revoked":false,"NotRevokable":false},{"Type":"irma-demo.MijnOverheid.fullName.firstname","CredentialHash":"","Expired":false,"Revoked":false,"NotRevokable":false},{"Type":"irma-demo.MijnOverheid.fullName.familyname","CredentialHash":"","Expired":false,"Revoked":false,"NotRevokable":false}]],[[{"Type":"irma-demo.RU.studentCard.level","CredentialHash":"5ac19c13941eb3b3687511a526adc1fdfa7a8c1bc976634e202671c2ba38c9fa","Expired":false,"Revoked":false,"NotRevokable":false}],[{"Type":"irma-demo.RU.studentCard.level","CredentialHash":"","Expired":false,"Revoked":false,"NotRevokable":false}]]]`), &missing))
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
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})

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
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	// Remove old studentCard credential from before support for optional attributes, and issue a new one
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
	require.Nil(t, requestorSessionHelper(t, getIssuanceRequest(true), client).Err)

	// client does not have updated irma_configuration with new attribute irma-demo.RU.studentCard.newAttribute,
	// and the server does. Disclose an attribute from this credential. The client implicitly discloses value 0
	// for the new attribute, and the server accepts.
	req := getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"))
	require.Nil(t, requestorSessionHelper(t, req, client, sessionOptionUpdatedIrmaConfiguration).Err)
}

func TestDisclosureNewAttributeUpdateSchemeManager(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.False(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	// Remove old studentCard credential from before support for optional attributes, and issue a new one
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
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
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

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

func TestIrmaServerPrivateKeysFolder(t *testing.T) {
	storage, err := ioutil.TempDir("", "servertest")
	require.NoError(t, err)
	defer func() { require.NoError(t, os.RemoveAll(storage)) }()
	StartIrmaServer(t, false, storage)
	defer StopIrmaServer()

	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	conf := irmaServerConfiguration.IrmaConfiguration
	sk, err := conf.PrivateKeys.Latest(credid.IssuerIdentifier())
	require.NoError(t, err)
	require.NotNil(t, sk)

	issuanceRequest := getIssuanceRequest(true)
	delete(issuanceRequest.Credentials[0].Attributes, "level")

	conf.SchemeManagers[credid.IssuerIdentifier().SchemeManagerIdentifier()].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	downloaded, err := conf.Download(issuanceRequest)
	require.NoError(t, err)
	require.Equal(t, &irma.IrmaIdentifierSet{
		SchemeManagers: map[irma.SchemeManagerIdentifier]struct{}{},
		Issuers:        map[irma.IssuerIdentifier]struct{}{},
		CredentialTypes: map[irma.CredentialTypeIdentifier]struct{}{
			irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"):  {},
			irma.NewCredentialTypeIdentifier("irma-demo.stemmen.stempas"): {},
		},
		PublicKeys:       map[irma.IssuerIdentifier][]uint{},
		AttributeTypes:   map[irma.AttributeTypeIdentifier]struct{}{},
		RequestorSchemes: map[irma.RequestorSchemeIdentifier]struct{}{},
	}, downloaded)

	sk, err = conf.PrivateKeys.Latest(credid.IssuerIdentifier())
	require.NoError(t, err)
	require.NotNil(t, sk)
}

func TestIssueOptionalAttributeUpdateSchemeManager(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")
	require.False(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid).IsOptional())
	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	delete(issuanceRequest.Credentials[0].Attributes, "level")

	serverChan := make(chan *server.SessionResult)

	StartIrmaServer(t, false, "") // Run a server with old configuration (level is non-optional)
	_, _, _, err := irmaServer.StartSession(issuanceRequest, func(result *server.SessionResult) {
		serverChan <- result
	})
	expectedError := &irma.RequiredAttributeMissingError{
		ErrorType: irma.ErrorRequiredAttributeMissing,
		Missing: &irma.IrmaIdentifierSet{
			SchemeManagers:   map[irma.SchemeManagerIdentifier]struct{}{},
			RequestorSchemes: map[irma.RequestorSchemeIdentifier]struct{}{},
			Issuers:          map[irma.IssuerIdentifier]struct{}{},
			CredentialTypes:  map[irma.CredentialTypeIdentifier]struct{}{},
			PublicKeys:       map[irma.IssuerIdentifier][]uint{},
			AttributeTypes: map[irma.AttributeTypeIdentifier]struct{}{
				irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"): struct{}{},
			},
		},
	}
	require.True(t, reflect.DeepEqual(err, expectedError), "Incorrect missing identifierset")
	StopIrmaServer()

	StartIrmaServer(t, true, "") // Run a server with updated configuration (level is optional)
	_, err = client.Configuration.Download(issuanceRequest)
	require.NoError(t, err)
	require.True(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid).IsOptional())
	_, _, _, err = irmaServer.StartSession(issuanceRequest, func(result *server.SessionResult) {
		serverChan <- result
	})
	require.NoError(t, err)
	StopIrmaServer()
}

func TestIssueNewCredTypeUpdateSchemeManager(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")

	delete(client.Configuration.CredentialTypes, credid)
	require.NotContains(t, client.Configuration.CredentialTypes, credid)

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	request := getIssuanceRequest(true)
	_, err := client.Configuration.Download(request)
	require.NoError(t, err)

	require.Contains(t, client.Configuration.CredentialTypes, credid)
}

func TestDisclosureNewCredTypeUpdateSchemeManager(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
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
}

func TestDisclosureNonexistingCredTypeUpdateSchemeManager(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	request := irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.baz.qux.abc"),        // non-existing issuer
		irma.NewAttributeTypeIdentifier("irma-demo.RU.foo.bar"),         // non-existing credential
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.xyz"), // non-existing attribute
	)
	_, err := client.Configuration.Download(request)
	require.Error(t, err)

	expectedErr := &irma.UnknownIdentifierError{
		ErrorType: irma.ErrorUnknownIdentifier,
		Missing: &irma.IrmaIdentifierSet{
			SchemeManagers:   map[irma.SchemeManagerIdentifier]struct{}{},
			RequestorSchemes: map[irma.RequestorSchemeIdentifier]struct{}{},
			PublicKeys:       map[irma.IssuerIdentifier][]uint{},
			Issuers: map[irma.IssuerIdentifier]struct{}{
				irma.NewIssuerIdentifier("irma-demo.baz"): struct{}{},
			},
			CredentialTypes: map[irma.CredentialTypeIdentifier]struct{}{
				irma.NewCredentialTypeIdentifier("irma-demo.RU.foo"):  struct{}{},
				irma.NewCredentialTypeIdentifier("irma-demo.baz.qux"): struct{}{},
			},
			AttributeTypes: map[irma.AttributeTypeIdentifier]struct{}{
				irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.xyz"): struct{}{},
			},
		},
	}
	require.True(t, reflect.DeepEqual(expectedErr, err), "Download() returned incorrect missing identifier set")
}

func TestStaticQRSession(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	StartRequestorServer(JwtServerConfiguration)
	defer StopRequestorServer()

	// start server to receive session result callback after the session
	var received bool
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		received = true
	})
	s := &http.Server{Addr: "localhost:48685", Handler: mux}
	go func() { _ = s.ListenAndServe() }()

	// setup static QR and other variables
	qr := &irma.Qr{
		Type: irma.ActionRedirect,
		URL:  "http://localhost:48682/irma/session/staticsession",
	}
	bts, err := json.Marshal(qr)
	require.NoError(t, err)
	requestor := expectedRequestorInfo(t, client.Configuration)
	c := make(chan *SessionResult)

	// Perform session
	client.NewSession(string(bts), &TestHandler{t, c, client, requestor, 0, "", nil, nil, nil})
	if result := <-c; result != nil {
		require.NoError(t, result.Err)
	}

	// give irma server time to post session result to the server started above, and check the call was received
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, s.Shutdown(context.Background()))
	require.True(t, received)
}

func TestIssuedCredentialIsStored(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	issuanceRequest := getNameIssuanceRequest()
	sessionHelper(t, issuanceRequest, "issue", client)
	require.NoError(t, client.Close())

	client, handler = parseExistingStorage(t, handler.storage)
	id := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.fullName.familyname")
	sessionHelper(t, getDisclosureRequest(id), "verification", client)
}

func TestBlindIssuanceSession(t *testing.T) {
	credID := irma.NewCredentialTypeIdentifier("irma-demo.stemmen.stempas")
	attrID1 := irma.NewAttributeTypeIdentifier("irma-demo.stemmen.stempas.election")
	attrID2 := irma.NewAttributeTypeIdentifier("irma-demo.stemmen.stempas.votingnumber")

	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	require.Truef(t, client.Configuration.ContainsCredentialType(credID), "CredentialType %s not found", credID)
	require.Truef(t, client.Configuration.ContainsAttributeType(attrID1), "AttributeType %s not found", attrID1)
	require.Truef(t, client.Configuration.ContainsAttributeType(attrID2), "AttributeType %s not found", attrID2)
	require.True(t, client.Configuration.AttributeTypes[attrID2].RandomBlind, "AttributeType votingnumber is not of type random blind")

	// this request should give an error by the server that the random blind attribute should not be in the credentialrequest
	request := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: credID,
			Attributes: map[string]string{
				"election":     "plantsoen",
				"votingnumber": "blabla",
			},
		},
	})

	StartIrmaServer(t, false, "")
	defer StopIrmaServer()
	_, _, _, err := irmaServer.StartSession(request, nil)
	require.EqualError(t, err, "Error type: randomblind\nDescription: randomblind attribute cannot be set in credential request\nStatus code: 0")

	// Make the request valid
	delete(request.Credentials[0].Attributes, "votingnumber")

	sessionHelper(t, request, "issue", client)
	attrList := client.Attributes(credID, 0)

	// Since attrList.Ints does not include the secret key,
	// we should have {metadata attribute, election, votingnumber}.
	require.Equal(t, 3, len(attrList.Ints), "number of attributes in credential should be 3")
	require.NotNil(t, attrList.Ints[2], "randomblind attribute should not be nil")
	require.NotEqual(t, 0, attrList.Ints[2].Cmp(big.NewInt(0)), "random blind attribute should not equal zero")
	require.NoError(t, client.Close())
}

// Tests whether the client correctly detects a mismatch in the randomblind attributes between client and server.
// In this test we simulate a scenario where the client has an out-of-date configuration compared to the server.
// The server has updated configuration in which two randomblind attributes are present.
// The client has only one. The client should notice and and abort the session.
func TestBlindIssuanceSessionDifferentAmountOfRandomBlinds(t *testing.T) {
	credID := irma.NewCredentialTypeIdentifier("irma-demo.stemmen.stempas")
	attrID1 := irma.NewAttributeTypeIdentifier("irma-demo.stemmen.stempas.election")
	attrID2 := irma.NewAttributeTypeIdentifier("irma-demo.stemmen.stempas.votingnumber")

	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	require.Truef(t, client.Configuration.ContainsCredentialType(credID), "CredentialType %s not found", credID)
	require.Truef(t, client.Configuration.ContainsAttributeType(attrID1), "AttributeType %s not found", attrID1)
	require.Truef(t, client.Configuration.ContainsAttributeType(attrID2), "AttributeType %s not found", attrID2)
	require.True(t, client.Configuration.AttributeTypes[attrID2].RandomBlind, "AttributeType votingnumber is not of type random blind")

	request := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: credID,
			Attributes: map[string]string{
				"election": "plantsoen",
			},
		},
	})

	res := requestorSessionHelper(t, request, client, sessionOptionUpdatedIrmaConfiguration, sessionOptionIgnoreError)
	require.EqualError(t, res.clientResult.Err, "Error type: randomblind\nDescription: mismatch in randomblind attributes between server/client\nStatus code: 0")
}

func TestPOSTSizeLimit(t *testing.T) {
	StartRequestorServer(IrmaServerConfiguration)
	defer StopRequestorServer()

	req, err := http.NewRequest(
		http.MethodPost,
		"http://localhost:48682/session/",
		bytes.NewReader(make([]byte, server.PostSizeLimit+1, server.PostSizeLimit+1)),
	)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Timeout = 30 * time.Second
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	bts, err := ioutil.ReadAll(res.Body)
	require.NoError(t, err)

	var rerr irma.RemoteError
	require.NoError(t, json.Unmarshal(bts, &rerr))
	require.Equal(t, "http: request body too large", rerr.Message)
}

func TestChainedSessions(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	StartNextRequestServer(t)
	defer StopNextRequestServer()

	var request irma.ServiceProviderRequest
	require.NoError(t, irma.NewHTTPTransport("http://localhost:48686", false).Get("1", &request))
	requestorSessionHelper(t, &request, client)

	// check that our credential instance is new
	id := request.SessionRequest().Disclosure().Disclose[0][0][0].Type.CredentialTypeIdentifier()

	for _, cred := range client.CredentialInfoList() {
		if id.String() == fmt.Sprintf("%s.%s.%s", cred.SchemeManagerID, cred.IssuerID, cred.ID) &&
			cred.SignedOn.After(irma.Timestamp(time.Now().Add(-1*irma.ExpiryFactor*time.Second))) {
			return
		}
	}

	require.NoError(t, errors.New("newly issued credential not found in client"))
}

func TestDisableBinding(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getCombinedIssuanceRequest(id)

	frontendOptionsHandler := func(handler *TestHandler) {
		_ = setBindingMethod(irma.BindingMethodPin, handler)
		_ = setBindingMethod(irma.BindingMethodNone, handler)
	}
	sessionHelperWithFrontendOptions(t, request, "issue", nil, frontendOptionsHandler, nil)
}
