package sessiontest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	sseclient "github.com/sietseringers/go-sse"
	"github.com/stretchr/testify/require"
)

// This file contains integration test functions that can be invoked against differing kinds of
// servers (i.e. IRMA server vs. IRMA library) with differing configurations (e.g. Redis enabled, or
// clients without pairing support), as follows.
// - Each function has the following signature:
//   *testing.T, interface{}, ...option
//   Here the second parameter must be, when not-nil, of one of the following types:
//   - func() *requestorserver.Configuration
//   - func() *server.Configuration
//   In the function, these parameters can be passed to doSession() which will, depending on the
//   session options, start and stop a server of the appropriate type (server or library), as
//   determined by the type of the configuration function.
// - Each function may be converted to one suitable for Go testing, i.e. having signature
//   *testing.T, using the apply() function.

func TestRequestorServer(t *testing.T) {
	t.Run("ChainedSessions", apply(testRequestorChainedSessions, RequestorServerAuthConfiguration))
	t.Run("UnauthorizedChainedSession", apply(testUnauthorizedRequestorChainedSession, RequestorServerPermissionsConfiguration))
	t.Run("DisclosureSession", apply(testDisclosureSession, RequestorServerConfiguration))
	t.Run("NoAttributeDisclosureSession", apply(testNoAttributeDisclosureSession, RequestorServerConfiguration))
	t.Run("EmptyDisclosure", apply(testEmptyDisclosure, RequestorServerConfiguration))
	t.Run("SigningSession", apply(testSigningSession, RequestorServerConfiguration))
	t.Run("IssuanceSession", apply(testIssuanceSession, RequestorServerConfiguration))
	t.Run("MultipleIssuanceSession", apply(testMultipleIssuanceSession, RequestorServerConfiguration))
	t.Run("DefaultCredentialValidity", apply(testDefaultCredentialValidity, RequestorServerConfiguration))
	t.Run("IssuanceDisclosureEmptyAttributes", apply(testIssuanceDisclosureEmptyAttributes, RequestorServerConfiguration))
	t.Run("IssuanceOptionalZeroLengthAttributes", apply(testIssuanceOptionalZeroLengthAttributes, RequestorServerConfiguration))
	t.Run("IssuanceOptionalSetAttributes", apply(testIssuanceOptionalSetAttributes, RequestorServerConfiguration))
	t.Run("IssuanceSameAttributesNotSingleton", apply(testIssuanceSameAttributesNotSingleton, RequestorServerConfiguration))
	t.Run("IssuancePairing", apply(testIssuancePairing, RequestorServerConfiguration))
	t.Run("PairingRejected", apply(testPairingRejected, RequestorServerConfiguration))
	t.Run("LargeAttribute", apply(testLargeAttribute, RequestorServerConfiguration))
	t.Run("IssuanceSingletonCredential", apply(testIssuanceSingletonCredential, RequestorServerConfiguration))
	t.Run("UnsatisfiableDisclosureSession", apply(testUnsatisfiableDisclosureSession, RequestorServerConfiguration))
	t.Run("AttributeByteEncoding", apply(testAttributeByteEncoding, RequestorServerConfiguration))
	t.Run("IssuedCredentialIsStored", apply(testIssuedCredentialIsStored, RequestorServerConfiguration))
	t.Run("BlindIssuanceSession", apply(testBlindIssuanceSession, RequestorServerConfiguration))
	t.Run("DisablePairing", apply(testDisablePairing, RequestorServerConfiguration))
	t.Run("DisclosureMultipleAttrs", apply(testDisclosureMultipleAttrs, RequestorServerConfiguration))
	t.Run("CombinedSessionMultipleAttributes", apply(testCombinedSessionMultipleAttributes, RequestorServerConfiguration))
	t.Run("ConDisCon", apply(testConDisCon, RequestorServerConfiguration))
	t.Run("OptionalDisclosure", apply(testOptionalDisclosure, RequestorServerConfiguration))
}

func TestIrmaServer(t *testing.T) {
	// Tests supporting only the IRMA server (library)
	t.Run("UnknownRequestorToken", apply(testUnknownRequestorToken, IrmaServerConfiguration))
	t.Run("DisclosureNewAttributeUpdateSchemeManager", apply(testDisclosureNewAttributeUpdateSchemeManager, IrmaServerConfiguration))
	t.Run("BlindIssuanceSessionDifferentAmountOfRandomBlinds", apply(testBlindIssuanceSessionDifferentAmountOfRandomBlinds, IrmaServerConfiguration))
	t.Run("OutdatedClientIrmaConfiguration", apply(testOutdatedClientIrmaConfiguration, IrmaServerConfiguration))

	// Tests also run against the requestor server
	t.Run("DisclosureSession", apply(testDisclosureSession, IrmaServerConfiguration))
	t.Run("NoAttributeDisclosureSession", apply(testNoAttributeDisclosureSession, IrmaServerConfiguration))
	t.Run("EmptyDisclosure", apply(testEmptyDisclosure, IrmaServerConfiguration))
	t.Run("SigningSession", apply(testSigningSession, IrmaServerConfiguration))
	t.Run("IssuanceSession", apply(testIssuanceSession, IrmaServerConfiguration))

	t.Run("MultipleIssuanceSession", apply(testMultipleIssuanceSession, IrmaServerConfiguration))
	t.Run("IssuancePairing", apply(testIssuancePairing, IrmaServerConfiguration))
	t.Run("PairingRejected", apply(testPairingRejected, IrmaServerConfiguration))
	t.Run("DisablePairing", apply(testDisablePairing, IrmaServerConfiguration))
	t.Run("UnsatisfiableDisclosureSession", apply(testUnsatisfiableDisclosureSession, IrmaServerConfiguration))

	t.Run("StaticQRSession", apply(testStaticQRSession, nil)) // has its own configuration
}

func testNoAttributeDisclosureSession(t *testing.T, conf interface{}, opts ...option) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard")
	request := getDisclosureRequest(id)
	doSession(t, request, nil, nil, nil, nil, nil, conf, opts...)
}

func testEmptyDisclosure(t *testing.T, conf interface{}, opts ...option) {
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

	res := doSession(t, request, nil, nil, nil, nil, nil, conf, opts...)
	require.Nil(t, res.Err)
	require.NotNil(t, res.SessionResult)
	require.NotEmpty(t, res.SessionResult.Disclosed) // The outer conjunction was satisfied
	require.Empty(t, res.SessionResult.Disclosed[0]) // by the empty set, so we get no attributes
}

func testMultipleIssuanceSession(t *testing.T, conf interface{}, opts ...option) {
	request := getMultipleIssuanceRequest()
	doSession(t, request, nil, nil, nil, nil, nil, conf, opts...)
}

func testDefaultCredentialValidity(t *testing.T, conf interface{}, opts ...option) {
	client, _ := parseStorage(t, opts...)
	defer client.Close()
	request := getIssuanceRequest(true)
	doSession(t, request, client, nil, nil, nil, nil, conf, opts...)
}

func testIssuanceDisclosureEmptyAttributes(t *testing.T, conf interface{}, opts ...option) {
	client, _ := parseStorage(t, opts...)
	defer client.Close()

	req := getNameIssuanceRequest()
	doSession(t, req, client, nil, nil, nil, nil, conf, opts...)

	// Test disclosing our null attribute
	req2 := getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.fullName.prefix"))
	res := doSession(t, req2, client, nil, nil, nil, nil, conf, opts...)
	require.Nil(t, res.Err)
	require.Nil(t, res.Disclosed[0][0].RawValue)
}

func testIssuanceOptionalZeroLengthAttributes(t *testing.T, conf interface{}, opts ...option) {
	req := getNameIssuanceRequest()
	req.Credentials[0].Attributes["prefix"] = ""
	doSession(t, req, nil, nil, nil, nil, nil, conf, opts...)
}

func testIssuanceOptionalSetAttributes(t *testing.T, conf interface{}, opts ...option) {
	req := getNameIssuanceRequest()
	req.Credentials[0].Attributes["prefix"] = "van"
	doSession(t, req, nil, nil, nil, nil, nil, conf, opts...)
}

func testIssuanceSameAttributesNotSingleton(t *testing.T, conf interface{}, opts ...option) {
	client, handler := parseStorage(t, opts...)
	defer client.Close()

	prevLen := len(client.CredentialInfoList())

	req := getIssuanceRequest(true)
	doSession(t, req, client, nil, nil, nil, nil, conf, opts...)

	req = getIssuanceRequest(false)
	doSession(t, req, client, nil, nil, nil, nil, conf, opts...)
	require.Equal(t, prevLen+1, len(client.CredentialInfoList()))

	// Also check whether this is actually stored
	require.NoError(t, client.Close())
	client, _ = parseExistingStorage(t, handler.storage)
	defer client.Close()

	require.Equal(t, prevLen+1, len(client.CredentialInfoList()))
}

func testIssuancePairing(t *testing.T, conf interface{}, opts ...option) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getCombinedIssuanceRequest(id)

	var pairingCode string
	frontendOptionsHandler := func(handler *TestHandler) {
		pairingCode = setPairingMethod(irma.PairingMethodPin, handler)
	}
	pairingHandler := func(handler *TestHandler) {
		// Below protocol version 2.8 pairing is not supported, so then the pairing stage is expected to be skipped.
		if extractClientMaxVersion(handler.client).Below(2, 8) {
			return
		}

		require.Equal(t, pairingCode, <-handler.pairingCodeChan)

		// Check whether access to request endpoint is denied as long as pairing is not finished
		err := handler.clientTransport.Get("request", struct{}{})
		require.Error(t, err)
		sessionErr := err.(*irma.SessionError)
		require.Equal(t, irma.ErrorApi, sessionErr.ErrorType)
		require.Equal(t, server.ErrorPairingRequired.Status, sessionErr.RemoteError.Status)
		require.Equal(t, string(server.ErrorPairingRequired.Type), sessionErr.RemoteError.ErrorName)

		// Check whether pairing cannot be disabled again after client is connected.
		request := irma.NewFrontendOptionsRequest()
		result := &irma.SessionOptions{}
		err = handler.frontendTransport.Post("frontend/options", result, request)
		require.Error(t, err)
		sessionErr = err.(*irma.SessionError)
		require.Equal(t, irma.ErrorApi, sessionErr.ErrorType)
		require.Equal(t, server.ErrorUnexpectedRequest.Status, sessionErr.RemoteError.Status)
		require.Equal(t, string(server.ErrorUnexpectedRequest.Type), sessionErr.RemoteError.ErrorName)

		err = handler.frontendTransport.Post("frontend/pairingcompleted", nil, nil)
		require.NoError(t, err)
	}
	doSession(t, request, nil, nil, nil, frontendOptionsHandler, pairingHandler, conf, opts...)
}

func testPairingRejected(t *testing.T, conf interface{}, opts ...option) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getCombinedIssuanceRequest(id)

	var pairingCode string
	frontendOptionsHandler := func(handler *TestHandler) {
		pairingCode = setPairingMethod(irma.PairingMethodPin, handler)
	}
	pairingHandler := func(handler *TestHandler) {
		require.Equal(t, pairingCode, <-handler.pairingCodeChan)
		err := handler.frontendTransport.Delete()
		require.NoError(t, err)
	}
	sessionOpts := append(opts, optionIgnoreError)
	result := doSession(t, request, nil, nil, nil, frontendOptionsHandler, pairingHandler, conf, sessionOpts...)
	err, ok := result.clientResult.Err.(*irma.SessionError)
	require.True(t, ok)
	require.Equal(t, irma.ErrorPairingRejected, err.ErrorType)
	// No error should be wrapped, because this is an alternative flow.
	require.Equal(t, err.WrappedError(), "")
}

func testLargeAttribute(t *testing.T, conf interface{}, opts ...option) {
	client, _ := parseStorage(t, opts...)
	defer client.Close()

	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})

	issuanceRequest := getSpecialIssuanceRequest(false, "1234567890123456789012345678901234567890") // 40 chars
	doSession(t, issuanceRequest, client, nil, nil, nil, nil, conf, opts...)

	disclosureRequest := getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"))
	doSession(t, disclosureRequest, client, nil, nil, nil, nil, conf, opts...)
}

func testIssuanceSingletonCredential(t *testing.T, conf interface{}, opts ...option) {
	client, handler := parseStorage(t, opts...)
	defer client.Close()

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

	doSession(t, request, client, nil, nil, nil, nil, conf, opts...)
	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))

	doSession(t, request, client, nil, nil, nil, nil, conf, opts...)
	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))

	// Also check whether this is actually stored
	require.NoError(t, client.Close())
	client, _ = parseExistingStorage(t, handler.storage)
	defer client.Close()

	require.NotNil(t, client.Attributes(credid, 0))
	require.Nil(t, client.Attributes(credid, 1))
}

func testUnsatisfiableDisclosureSession(t *testing.T, conf interface{}, opts ...option) {
	client, _ := parseStorage(t, opts...)
	defer client.Close()

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
		doSession(t, request, client, nil, nil, nil, nil, nil, append(opts, optionUnsatisfiableRequest)...).Missing),
	)

}

/*
There is an annoying difference between how Java and Go convert big integers to and from
byte arrays: in Java the sign of the integer is taken into account, but not in Go. This means
that in Java, when converting a bigint to or from a byte array, the most significant bit
indicates the sign of the integer. In Go this is not the case. This resulted in invalid
signatures being issued in the issuance protocol in two distinct ways, of which we test here
that they have been fixed.
*/
func testAttributeByteEncoding(t *testing.T, conf interface{}, opts ...option) {
	client, _ := parseStorage(t, opts...)
	defer client.Close()
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})

	/* After bitshifting the presence bit into the large attribute below, the most significant
	bit is 1. In the bigint->[]byte conversion that happens before hashing this attribute, in
	Java this results in an extra 0 byte being prepended in order to have a 0 instead as most
	significant (sign) bit. We test that the Java implementation correctly removes the extraneous
	0 byte. */
	request := getSpecialIssuanceRequest(false, "a23456789012345678901234567890")
	doSession(t, request, client, nil, nil, nil, nil, conf, opts...)

	/* After converting the attribute below to bytes (using UTF8, on which Java and Go do agree),
	the most significant bit of the byte version of this attribute is 1. In the []byte->bigint
	conversion that happens at that point in the Java implementation (bitshifting is done
	afterwards), this results in a negative number in Java and a positive number in Go. We test
	here that the Java correctly prepends a 0 byte just before this conversion in order to get
	the same positive bigint. */
	request = getSpecialIssuanceRequest(false, "é")
	doSession(t, request, client, nil, nil, nil, nil, conf, opts...)
}

func testOutdatedClientIrmaConfiguration(t *testing.T, conf interface{}, opts ...option) {
	require.IsType(t, IrmaServerConfiguration, conf)
	irmaServerConf := updatedSchemeConfigDecorator(conf.(func() *server.Configuration))

	client, _ := parseStorage(t, opts...)
	defer client.Close()

	// Remove old studentCard credential from before support for optional attributes, and issue a new one
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
	require.Nil(t, doSession(t, getIssuanceRequest(true), client, nil, nil, nil, nil, conf, opts...).Err)

	// client does not have updated irma_configuration with new attribute irma-demo.RU.studentCard.newAttribute,
	// and the server does. Disclose an attribute from this credential. The client implicitly discloses value 0
	// for the new attribute, and the server accepts.
	req := getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"))
	require.Nil(t, doSession(t, req, client, nil, nil, nil, nil, irmaServerConf, opts...).Err)
}

func testDisclosureNewAttributeUpdateSchemeManager(t *testing.T, conf interface{}, opts ...option) {
	require.IsType(t, IrmaServerConfiguration, conf)
	irmaServerConf := updatedSchemeConfigDecorator(conf.(func() *server.Configuration))

	client, _ := parseStorage(t, opts...)
	defer client.Close()

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.False(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	// Remove old studentCard credential from before support for optional attributes, and issue a new one
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
	require.Nil(t, doSession(t, getIssuanceRequest(true), client, nil, nil, nil, nil, conf, opts...).Err)

	// Trigger downloading the updated irma_configuration using a disclosure request containing the
	// new attribute, and inform the client
	client.Configuration.SchemeManagers[schemeid].URL = schemeServerURL + "/irma_configuration_updated/irma-demo"
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
	require.Nil(t, doSession(t, levelRequest, client, nil, nil, nil, nil, conf, opts...).Err)

	// Disclose newAttribute to a server with a new configuration. This attribute was added
	// after we received a credential without it, so its value in this credential is 0.
	res := doSession(t, newAttrRequest, client, nil, nil, nil, nil, irmaServerConf, opts...)
	require.Nil(t, res.Err)
	require.Nil(t, res.Disclosed[0][0].RawValue)
}

func testStaticQRSession(t *testing.T, _ interface{}, opts ...option) {
	client, _ := parseStorage(t, opts...)
	defer client.Close()
	rs := StartRequestorServer(t, RequestorServerAuthConfiguration())
	defer rs.Stop()

	// start server to receive session result callback after the session
	var received bool
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		received = true
	})
	s := &http.Server{Addr: fmt.Sprintf("localhost:%d", staticSessionServerPort), Handler: mux}
	go func() { _ = s.ListenAndServe() }()

	// setup static QR and other variables
	qr := &irma.Qr{
		Type: irma.ActionRedirect,
		URL:  requestorServerURL + "/irma/session/staticsession",
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

func testIssuedCredentialIsStored(t *testing.T, conf interface{}, opts ...option) {
	client, handler := parseStorage(t, opts...)
	defer client.Close()

	issuanceRequest := getNameIssuanceRequest()
	doSession(t, issuanceRequest, client, nil, nil, nil, nil, conf, opts...)
	require.NoError(t, client.Close())

	client, _ = parseExistingStorage(t, handler.storage)
	defer client.Close()

	id := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.fullName.familyname")
	doSession(t, getDisclosureRequest(id), client, nil, nil, nil, nil, conf, opts...)
}

func testBlindIssuanceSession(t *testing.T, conf interface{}, opts ...option) {
	credID := irma.NewCredentialTypeIdentifier("irma-demo.stemmen.stempas")
	attrID1 := irma.NewAttributeTypeIdentifier("irma-demo.stemmen.stempas.election")
	attrID2 := irma.NewAttributeTypeIdentifier("irma-demo.stemmen.stempas.votingnumber")

	client, _ := parseStorage(t, opts...)
	defer client.Close()

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

	irmaServer := StartIrmaServer(t, nil)
	_, _, _, err := irmaServer.irma.StartSession(request, nil, "")
	irmaServer.Stop()
	require.EqualError(t, err, "Error type: randomblind\nDescription: randomblind attribute cannot be set in credential request\nStatus code: 0")

	// Make the request valid
	delete(request.Credentials[0].Attributes, "votingnumber")

	doSession(t, request, client, nil, nil, nil, nil, conf, opts...)
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
func testBlindIssuanceSessionDifferentAmountOfRandomBlinds(t *testing.T, conf interface{}, opts ...option) {
	require.IsType(t, IrmaServerConfiguration, conf)
	irmaServerConf := updatedSchemeConfigDecorator(conf.(func() *server.Configuration))

	credID := irma.NewCredentialTypeIdentifier("irma-demo.stemmen.stempas")
	attrID1 := irma.NewAttributeTypeIdentifier("irma-demo.stemmen.stempas.election")
	attrID2 := irma.NewAttributeTypeIdentifier("irma-demo.stemmen.stempas.votingnumber")

	client, _ := parseStorage(t, opts...)
	defer client.Close()

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

	res := doSession(t, request, client, nil, nil, nil, nil, irmaServerConf, append(opts, optionIgnoreError)...)
	require.NotNil(t, res.clientResult)
	require.EqualError(t, res.clientResult.Err, "Error type: randomblind\nDescription: mismatch in randomblind attributes between server/client\nStatus code: 0")
}

func testNonRequestorChainedSessions(t *testing.T, conf interface{}, opts ...option) {
	doNonRequestorChainedSessions(t, conf,
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
		irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		append(opts, optionIgnoreError)...,
	)
}

func testRequestorChainedSessions(t *testing.T, conf interface{}, opts ...option) {
	doChainedSessions(t, conf,
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
		irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		opts...,
	)
}

func testUnauthorizedRequestorChainedSession(t *testing.T, conf interface{}, opts ...option) {
	doUnauthorizedChainedSession(t, conf,
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
		irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		append(opts, optionIgnoreError)...,
	)
}

// Test to check whether session stores (like Redis) correctly handle non-existing sessions
func testUnknownRequestorToken(t *testing.T, conf interface{}, opts ...option) {
	require.IsType(t, IrmaServerConfiguration, conf)
	irmaServer := StartIrmaServer(t, conf.(func() *server.Configuration)())
	defer irmaServer.Stop()

	result, err := irmaServer.irma.GetSessionResult("12345")

	require.Error(t, err)
	require.Equal(t, err.Error(), "session result requested of unknown session 12345")
	require.Nil(t, result)
}

func testDisablePairing(t *testing.T, conf interface{}, opts ...option) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getCombinedIssuanceRequest(id)

	frontendOptionsHandler := func(handler *TestHandler) {
		_ = setPairingMethod(irma.PairingMethodPin, handler)
		_ = setPairingMethod(irma.PairingMethodNone, handler)
	}
	doSession(t, request, nil, nil, nil, frontendOptionsHandler, nil, conf, opts...)
}

func updatedSchemeConfigDecorator(fn func() *server.Configuration) func() *server.Configuration {
	return func() *server.Configuration {
		c := fn()
		c.SchemesPath = filepath.Join(testdataFolder, "irma_configuration_updated")
		return c
	}
}

func testSigningSession(t *testing.T, conf interface{}, opts ...option) {
	client, _ := parseStorage(t, opts...)
	defer client.Close()
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	var serverResult *requestorSessionResult
	for _, opt := range []option{0, optionRetryPost} {
		serverResult = doSession(t, getSigningRequest(id), client, nil, nil, nil, nil, conf, append(opts, opt)...)

		require.Nil(t, serverResult.Err)
		require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)
		require.NotEmpty(t, serverResult.Disclosed)
		require.Equal(t, id, serverResult.Disclosed[0][0].Identifier)
		require.Equal(t, "456", serverResult.Disclosed[0][0].Value["en"])
	}

	// Load the updated scheme in which an attribute was added to the studentCard credential type
	scheme := client.Configuration.SchemeManagers[irma.NewSchemeManagerIdentifier("irma-demo")]
	scheme.URL = schemeServerURL + "/irma_configuration_updated/irma-demo"
	require.NoError(t, client.Configuration.UpdateScheme(scheme, nil))
	require.NoError(t, client.Configuration.ParseFolder())
	require.Contains(t, client.Configuration.AttributeTypes, irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute"))

	// Check that the just created credential is still valid after the new attribute has been added
	_, status, err := serverResult.Signature.Verify(client.Configuration, nil)
	require.NoError(t, err)
	require.Equal(t, irma.ProofStatusValid, status)
}

func testDisclosureSession(t *testing.T, conf interface{}, opts ...option) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)
	for _, opt := range []option{0, optionRetryPost} {
		serverResult := doSession(t, request, nil, nil, nil, nil, nil, conf, append(opts, opt)...)
		require.Nil(t, serverResult.Err)
		require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)
		require.Len(t, serverResult.Disclosed, 1)
		require.Equal(t, id, serverResult.Disclosed[0][0].Identifier)
		require.Equal(t, "456", serverResult.Disclosed[0][0].Value["en"])
	}
}

func testDisclosureMultipleAttrs(t *testing.T, conf interface{}, opts ...option) {
	request := irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"),
	)

	serverResult := doSession(t, request, nil, nil, nil, nil, nil, conf, opts...)
	require.Nil(t, serverResult.Err)
	require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)

	require.Len(t, serverResult.Disclosed, 2)
}

func testIssuanceSession(t *testing.T, conf interface{}, opts ...option) {
	doIssuanceSession(t, false, nil, conf, opts...)
}

func testCombinedSessionMultipleAttributes(t *testing.T, conf interface{}, opts ...option) {
	var ir irma.IssuanceRequest
	require.NoError(t, irma.UnmarshalValidate([]byte(`{
		"type":"issuing",
		"credentials": [
			{
				"credential":"irma-demo.MijnOverheid.singleton",
				"attributes" : {
					"BSN":"12345"
				}
			}
		],
		"disclose" : [
			{
				"label":"Initialen",
				"attributes":["irma-demo.RU.studentCard.studentCardNumber"]
			},
			{
				"label":"Achternaam",
				"attributes" : ["irma-demo.RU.studentCard.studentID"]
			},
			{
				"label":"Geboortedatum",
				"attributes":["irma-demo.RU.studentCard.university"]
			}
		]
	}`), &ir))

	require.Equal(t, irma.ServerStatusDone, doSession(t, &ir, nil, nil, nil, nil, nil, conf, opts...).Status)
}

func doIssuanceSession(t *testing.T, keyshare bool, client *irmaclient.IrmaClient, conf interface{}, options ...option) {
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		Attributes: map[string]string{
			"university":        "Radboud",
			"studentCardNumber": "31415927",
			"studentID":         "s1234567",
			"level":             "42",
		},
	}, {
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
		Attributes: map[string]string{
			"firstnames": "Johan Pieter",
			"firstname":  "Johan",
			"familyname": "Stuivezand",
		},
	}}, attrid)
	if keyshare {
		request.Credentials = append(request.Credentials, &irma.CredentialRequest{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes:       map[string]string{"email": "testusername"},
		})
	}

	result := doSession(t, request, client, nil, nil, nil, nil, conf, options...)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)
	require.Equal(t, attrid, result.Disclosed[0][0].Identifier)
	require.Equal(t, "456", result.Disclosed[0][0].Value["en"])

}

func testConDisCon(t *testing.T, conf interface{}, opts ...option) {
	client, _ := parseStorage(t, opts...)
	defer client.Close()
	ir := getMultipleIssuanceRequest()
	ir.Credentials = append(ir.Credentials, &irma.CredentialRequest{
		Validity:         ir.Credentials[0].Validity,
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
		Attributes: map[string]string{
			"firstnames": "Jan Hendrik",
			"firstname":  "Jan",
			"familyname": "Klaassen",
			"prefix":     "van",
		},
	})
	doSession(t, ir, client, nil, nil, nil, nil, conf, opts...)

	dr := irma.NewDisclosureRequest()
	dr.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.root.BSN"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.studentID"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
			},
		},
	}

	doSession(t, dr, client, nil, nil, nil, nil, conf, opts...)
}

func testOptionalDisclosure(t *testing.T, conf interface{}, opts ...option) {
	client, _ := parseStorage(t, opts...)
	defer client.Close()
	university := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university")
	studentid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	radboud := "Radboud"
	attrs1 := irma.AttributeConDisCon{
		irma.AttributeDisCon{ // Including one non-optional disjunction is required in disclosure and signature sessions
			irma.AttributeCon{irma.AttributeRequest{Type: university}},
		},
		irma.AttributeDisCon{
			irma.AttributeCon{},
			irma.AttributeCon{irma.AttributeRequest{Type: studentid}},
		},
	}
	disclosed1 := [][]*irma.DisclosedAttribute{
		{
			{
				RawValue:     &radboud,
				Value:        map[string]string{"": radboud, "en": radboud, "nl": radboud},
				Identifier:   irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"),
				Status:       irma.AttributeProofStatusPresent,
				IssuanceTime: irma.Timestamp(client.Attributes(university.CredentialTypeIdentifier(), 0).SigningDate()),
			},
		},
		{},
	}
	attrs2 := irma.AttributeConDisCon{ // In issuance sessions, it is allowed that all disjunctions are optional
		irma.AttributeDisCon{
			irma.AttributeCon{},
			irma.AttributeCon{irma.AttributeRequest{Type: studentid}},
		},
	}
	disclosed2 := [][]*irma.DisclosedAttribute{{}}

	tests := []struct {
		request   irma.SessionRequest
		attrs     irma.AttributeConDisCon
		disclosed [][]*irma.DisclosedAttribute
	}{
		{irma.NewDisclosureRequest(), attrs1, disclosed1},
		{irma.NewSignatureRequest("message"), attrs1, disclosed1},
		{getIssuanceRequest(true), attrs1, disclosed1},
		{getIssuanceRequest(true), attrs2, disclosed2},
	}

	for _, args := range tests {
		args.request.Disclosure().Disclose = args.attrs

		// TestHandler always prefers the first option when given any choice, so it will not disclose the optional attribute
		result := doSession(t, args.request, client, nil, nil, nil, nil, conf, opts...)
		require.True(t, reflect.DeepEqual(args.disclosed, result.Disclosed))
	}
}

// The following tests are currently not reused with different server/configuration types.

func TestIssueNewAttributeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.False(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	client.Configuration.SchemeManagers[schemeid].URL = schemeServerURL + "/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	issuanceRequest.Credentials[0].Attributes["newAttribute"] = "foobar"
	_, err := client.Configuration.Download(issuanceRequest)
	require.NoError(t, err)
	require.True(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))
}

func TestIrmaServerPrivateKeysFolder(t *testing.T) {
	storage, err := os.MkdirTemp("", "servertest")
	require.NoError(t, err)
	defer func() { require.NoError(t, os.RemoveAll(storage)) }()

	conf := IrmaServerConfiguration()
	conf.SchemesAssetsPath = filepath.Join(testdataFolder, "irma_configuration")
	conf.SchemesPath = storage

	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	irmaConf := irmaServer.conf.IrmaConfiguration
	sk, err := irmaConf.PrivateKeys.Latest(credid.IssuerIdentifier())
	require.NoError(t, err)
	require.NotNil(t, sk)

	issuanceRequest := getIssuanceRequest(true)
	delete(issuanceRequest.Credentials[0].Attributes, "level")

	irmaConf.SchemeManagers[credid.IssuerIdentifier().SchemeManagerIdentifier()].URL = schemeServerURL + "/irma_configuration_updated/irma-demo"
	downloaded, err := irmaConf.Download(issuanceRequest)
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

	sk, err = irmaConf.PrivateKeys.Latest(credid.IssuerIdentifier())
	require.NoError(t, err)
	require.NotNil(t, sk)
}

func TestIssueOptionalAttributeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")
	require.False(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid).IsOptional())
	client.Configuration.SchemeManagers[schemeid].URL = schemeServerURL + "/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	delete(issuanceRequest.Credentials[0].Attributes, "level")

	irmaServer := StartIrmaServer(t, nil) // Run a server with old configuration (level is non-optional)
	_, _, _, err := irmaServer.irma.StartSession(issuanceRequest, nil, "")
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
	irmaServer.Stop()

	// Run a server with updated configuration (level is optional)
	conf := IrmaServerConfiguration()
	conf.SchemesPath = filepath.Join(testdataFolder, "irma_configuration_updated")
	irmaServer = StartIrmaServer(t, conf)
	_, err = client.Configuration.Download(issuanceRequest)
	require.NoError(t, err)
	require.True(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid).IsOptional())
	_, _, _, err = irmaServer.irma.StartSession(issuanceRequest, nil, "")
	require.NoError(t, err)
	irmaServer.Stop()
}

func TestIssueNewCredTypeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")

	delete(client.Configuration.CredentialTypes, credid)
	require.NotContains(t, client.Configuration.CredentialTypes, credid)

	client.Configuration.SchemeManagers[schemeid].URL = schemeServerURL + "/irma_configuration_updated/irma-demo"
	request := getIssuanceRequest(true)
	_, err := client.Configuration.Download(request)
	require.NoError(t, err)

	require.Contains(t, client.Configuration.CredentialTypes, credid)
}

func TestDisclosureNewCredTypeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")

	delete(client.Configuration.CredentialTypes, credid)
	require.NotContains(t, client.Configuration.CredentialTypes, credid)

	client.Configuration.SchemeManagers[schemeid].URL = schemeServerURL + "/irma_configuration_updated/irma-demo"
	request := irma.NewDisclosureRequest(attrid)
	_, err := client.Configuration.Download(request)
	require.NoError(t, err)
	require.Contains(t, client.Configuration.CredentialTypes, credid)
}

func TestDisclosureNonexistingCredTypeUpdateSchemeManager(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()
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

func TestPOSTSizeLimit(t *testing.T) {
	rs := StartRequestorServer(t, RequestorServerConfiguration())
	defer rs.Stop()

	server.PostSizeLimit = 1 << 10
	defer func() {
		server.PostSizeLimit = 10 << 20
	}()

	req, err := http.NewRequest(
		http.MethodPost,
		requestorServerURL+"/session/",
		bytes.NewReader(make([]byte, server.PostSizeLimit+1)),
	)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	http.DefaultClient.Timeout = 30 * time.Second
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	bts, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	var rerr irma.RemoteError
	require.NoError(t, json.Unmarshal(bts, &rerr))
	require.Equal(t, "http: request body too large", rerr.Message)
}

func TestStatusEventsSSE(t *testing.T) {
	// Start a server with SSE enabled
	conf := RequestorServerConfiguration()
	conf.EnableSSE = true
	rs := StartRequestorServer(t, conf)
	defer rs.Stop()

	// Start a session at the server
	request := irma.NewDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	useJWTs := !conf.DisableRequestorAuthentication
	sesPkg := startSessionAtServer(t, rs, useJWTs, request)

	// Start SSE connections to the SSE endpoints
	url := fmt.Sprintf("http://localhost:%d/session/%s/statusevents", conf.Port, sesPkg.Token)
	requestorStatuschan, requestorCancel := listenStatusEventsSSE(t, url)
	frontendStatuschan, frontendCancel := listenStatusEventsSSE(t, sesPkg.SessionPtr.URL+"/statusevents")

	// Wait for the session to start and the SSE HTTP connections to be made
	time.Sleep(100 * time.Millisecond)

	// Make a client, and let it perform the session
	client, _ := parseStorage(t)
	defer client.Close()
	h := &TestHandler{
		t:                  t,
		c:                  make(chan *SessionResult),
		client:             client,
		expectedServerName: expectedRequestorInfo(t, client.Configuration),
	}
	qrjson, err := json.Marshal(sesPkg.SessionPtr)
	require.NoError(t, err)
	client.NewSession(string(qrjson), h)

	// Both channels should now receive "CONNECTED" and "DONE" in quick succession as the client
	// connects and then finishes the session.
	done := make(chan struct{})
	go func() {
		require.Equal(t, irma.ServerStatusConnected, <-requestorStatuschan)
		require.Equal(t, irma.ServerStatusConnected, <-frontendStatuschan)
		require.Equal(t, irma.ServerStatusDone, <-requestorStatuschan)
		require.Equal(t, irma.ServerStatusDone, <-frontendStatuschan)
		done <- struct{}{}
	}()

	// Stop waiting for events to arrive if it takes too long
	select {
	case <-done: // all ok, do nothing
	case <-time.After(5 * time.Second):
		// Cancel SSE requests, to ensure the goroutine above finishes so the test ends
		requestorCancel()
		frontendCancel()
		t.Fatal("SSE events took too long to arrive")
	}
}

// listenStatusEventsSSE is a helper function that connects to a SSE statusevents endpoint, and emits events
// received on it to the returned channel. Partially copied from subscribeSSE() in wait_status.go.
func listenStatusEventsSSE(t *testing.T, url string) (chan irma.ServerStatus, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	statuschan := make(chan irma.ServerStatus)
	events := make(chan *sseclient.Event)

	// Start reading SSE events from the channel to which sseclient.Notify() will write
	go func() {
		for {
			e := <-events
			if e == nil || e.Type == "open" {
				continue
			}
			status := irma.ServerStatus(strings.Trim(string(e.Data), `"`))
			statuschan <- status
			if status.Finished() {
				cancel()
				return
			}
		}
	}()

	// Open SSE HTTP connection (in a goroutine since it is long-lived)
	go func() {
		defer close(statuschan)
		err := sseclient.Notify(ctx, url, true, events)
		if err != nil && strings.HasSuffix(err.Error(), context.Canceled.Error()) {
			// this error is expected: we trigger it ourselves with cancel() above
			return
		}
		require.NoError(t, err)
	}()

	return statuschan, cancel
}

// Check that nonexistent IRMA identifiers in the session request fail the session
func TestInvalidRequest(t *testing.T) {
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()
	_, _, _, err := irmaServer.irma.StartSession(irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.foo.bar"),
		irma.NewAttributeTypeIdentifier("irma-demo.baz.qux.abc"),
	), nil, "")
	require.Error(t, err)
}

func TestDoubleGET(t *testing.T) {
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()
	qr, _, _, err := irmaServer.irma.StartSession(irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
	), nil, "")
	require.NoError(t, err)

	// Simulate the first GET by the client in the session protocol, twice
	var o interface{}
	transport := irma.NewHTTPTransport(qr.URL, false)
	transport.SetHeader(irma.MinVersionHeader, "2.8")
	transport.SetHeader(irma.MaxVersionHeader, "2.8")
	transport.SetHeader(irma.AuthorizationHeader, "testauthtoken")
	require.NoError(t, transport.Get("", &o))
	require.NoError(t, transport.Get("", &o))
}

func TestInsecureProtocolVersion(t *testing.T) {
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	// Test whether the server accepts a request with an insecure protocol version
	request := irma.NewDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))

	qr, _, _, err := irmaServer.irma.StartSession(request, func(result *server.SessionResult) {}, "")
	require.NoError(t, err)

	var o interface{}
	transport := irma.NewHTTPTransport(qr.URL, false)
	transport.SetHeader(irma.MinVersionHeader, "2.7")
	transport.SetHeader(irma.MaxVersionHeader, "2.7")
	transport.SetHeader(irma.AuthorizationHeader, "testauthtoken")
	err = transport.Get("", &o)
	require.Error(t, err)
	serr, ok := err.(*irma.SessionError)
	require.True(t, ok)
	require.Equal(t, server.ErrorProtocolVersion.Status, serr.RemoteStatus)
	require.Equal(t, string(server.ErrorProtocolVersion.Type), serr.RemoteError.ErrorName)
}

func TestClientDeveloperMode(t *testing.T) {
	common.ForceHTTPS = true
	defer func() { common.ForceHTTPS = false }()
	client, _ := parseStorage(t)
	defer client.Close()
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	// parseStorage returns a client with developer mode already enabled.
	// Do a session with our local testserver (without https)
	issuanceRequest := getNameIssuanceRequest()
	doSession(t, issuanceRequest, client, irmaServer, nil, nil, nil, nil)
	require.True(t, issuanceRequest.DevelopmentMode) // set to true by server

	// RemoveStorage resets developer mode preference back to its default (disabled)
	require.NoError(t, client.RemoveStorage())
	require.False(t, client.Preferences.DeveloperMode)

	// Try to start another session with our non-https server
	issuanceRequest = getNameIssuanceRequest()
	qr, _, _, err := irmaServer.irma.StartSession(issuanceRequest, nil, "")
	require.NoError(t, err)
	c := make(chan *SessionResult, 1)
	j, err := json.Marshal(qr)
	require.NoError(t, err)
	client.NewSession(string(j), &TestHandler{t, c, client, nil, 0, "", nil, nil, nil})
	result := <-c

	// Check that it failed with an appropriate error message
	require.NotNil(t, result)
	require.Error(t, result.Err)
	serr, ok := result.Err.(*irma.SessionError)
	require.True(t, ok)
	require.NotNil(t, serr)
	require.Equal(t, string(irma.ErrorHTTPS), string(serr.ErrorType))
	require.Equal(t, "remote server does not use https", serr.Err.Error())
}

func TestParallelSessions(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	// Ensure we don't have the requested attribute at first
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})

	// Start disclosure session for an attribute we don't have.
	// optionWait makes this block until the IRMA server returns a result.
	disclosure := make(chan *requestorSessionResult)
	go func() {
		result := doSession(t,
			getDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")),
			client,
			irmaServer,
			nil, nil, nil, nil,
			optionUnsatisfiableRequest, optionWait,
		)
		require.Equal(t, result.Status, irma.ServerStatusDone)
		disclosure <- result
	}()

	// Wait for a bit then check that so far zero sessions have been done
	time.Sleep(100 * time.Millisecond)
	logs, err := client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Zero(t, len(logs))

	// Issue credential containing above attribute
	doSession(t, getIssuanceRequest(false), client, irmaServer, nil, nil, nil, nil)

	// Running disclosure session should now finish using the new credential
	result := <-disclosure
	require.Nil(t, result.Err)
	require.NotEmpty(t, result.Disclosed)
	require.Equal(t, "s1234567", result.Disclosed[0][0].Value["en"])

	// Two sessions should now have been done
	time.Sleep(100 * time.Millisecond)
	logs, err = client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 2)
}

func TestParallelSessionsWithPairing(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getCombinedIssuanceRequest(id)

	frontendOptionsHandler := func(handler *TestHandler) {
		_ = setPairingMethod(irma.PairingMethodPin, handler)
	}

	pairingHandler := func(handler *TestHandler) {
		<-handler.pairingCodeChan

		// Do a second session while the first session is pairing.
		doSession(t, request, client, irmaServer, nil, nil, nil, nil)

		// After the second session has been completed, we complete pairing of the first session.
		err := handler.frontendTransport.Post("frontend/pairingcompleted", nil, nil)
		require.NoError(t, err)
	}

	// Initiate the first session with pairing being enabled.
	doSession(t, request, client, irmaServer, nil, frontendOptionsHandler, pairingHandler, nil)
}

func expireKey(t *testing.T, conf *irma.Configuration) {
	pk, err := conf.PublicKey(irma.NewIssuerIdentifier("irma-demo.RU"), 2)
	require.NoError(t, err)
	pk.ExpiryDate = 1500000000
}

func TestIssueExpiredKey(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	// issuance sessions using valid, nonexpired public keys work
	result := doSession(t, getIssuanceRequest(true), client, irmaServer, nil, nil, nil, nil)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)

	// client aborts issuance sessions in case of expired public keys
	expireKey(t, client.Configuration)
	result = doSession(t, getIssuanceRequest(true), client, irmaServer, nil, nil, nil, nil, optionIgnoreError)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ServerStatusCancelled, result.Status)

	// server aborts issuance sessions in case of expired public keys
	expireKey(t, irmaServer.conf.IrmaConfiguration)
	_, _, _, err := irmaServer.irma.StartSession(getIssuanceRequest(true), nil, "")
	require.Error(t, err)
}

func TestExpiredCredential(t *testing.T) {
	irmaserver.AllowIssuingExpiredCredentials = true
	defer func() {
		irmaserver.AllowIssuingExpiredCredentials = false
	}()

	client, _ := parseStorage(t)
	defer client.Close()

	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	// Issue an expired credential
	invalidValidity := irma.Timestamp(time.Now())
	value := "13371337"
	issuanceRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			Validity:         &invalidValidity,
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "Radboud",
				"studentCardNumber": value,
				"studentID":         "s1234567",
				"level":             "42",
			},
		},
	})
	doSession(t, issuanceRequest, client, irmaServer, nil, nil, nil, nil)

	// Try to disclose it and check that it fails.
	disclosureRequest := irma.NewDisclosureRequest()
	disclosureRequest.AddSingle(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentCardNumber"), &value, nil)
	doSession(t, disclosureRequest, client, irmaServer, nil, nil, nil, nil, optionUnsatisfiableRequest)

	// Try to disclose it when allowing expired credentials and check that it succeeds.
	disclosureRequest.SkipExpiryCheck = []irma.CredentialTypeIdentifier{issuanceRequest.Credentials[0].CredentialTypeID}
	doSession(t, disclosureRequest, client, irmaServer, nil, nil, nil, nil)
}

func TestRequestorHostPermissions(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()
	rs := StartRequestorServer(t, RequestorServerAuthConfiguration())
	defer rs.Stop()

	// Check that a requestor can use a host that is allowed.
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)
	sesPkg := &server.SessionPackage{}

	// Check that a requestor can't use a host that is not allowed.
	request.Base().Host = "127.0.0.1:48682"
	err := irma.NewHTTPTransport(requestorServerURL, false).Post("session", &server.SessionPackage{}, signSessionRequest(t, request))
	require.Error(t, err)
	require.Contains(t, err.Error(), "requestor not allowed to use the requested host")

	// Start a new session using the allowed host.
	request.Base().Host = "localhost:48682"
	err = irma.NewHTTPTransport(requestorServerURL, false).Post("session", sesPkg, signSessionRequest(t, request))
	require.NoError(t, err)
	realURL := sesPkg.SessionPtr.URL

	// Check that a client can't use another host than the requestor wanted.
	sesPkg.SessionPtr.URL = strings.Replace(sesPkg.SessionPtr.URL, "localhost", "127.0.0.1", 1)
	sessionHandler, resultChan := createSessionHandler(t, optionIgnoreError, client, sesPkg, nil, nil)
	startSessionAtClient(t, sesPkg, client, sessionHandler)
	result := <-resultChan
	require.Error(t, result.Err)
	require.Contains(t, result.Err.Error(), "Host mismatch")

	// Check that a client can use the host the requestor wanted.
	sesPkg.SessionPtr.URL = realURL
	sessionHandler, resultChan = createSessionHandler(t, 0, client, sesPkg, nil, nil)
	startSessionAtClient(t, sesPkg, client, sessionHandler)
	result = <-resultChan
	require.Nil(t, result)
}

func signSessionRequest(t *testing.T, req irma.SessionRequest) string {
	skbts, err := os.ReadFile(filepath.Join(testdataFolder, "jwtkeys", "requestor1-sk.pem"))
	require.NoError(t, err)
	sk, err := jwt.ParseRSAPrivateKeyFromPEM(skbts)
	require.NoError(t, err)
	j, err := irma.SignSessionRequest(req, jwt.SigningMethodRS256, sk, "requestor1")
	require.NoError(t, err)
	return j
}
