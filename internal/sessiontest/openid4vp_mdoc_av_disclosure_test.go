package sessiontest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

// avDocType is the EU Age Verification profile's docType. Five dot-separated
// parts where a Yivi scheme identifier has three, which is what makes the
// relying party's authorized-set matching worth exercising against a real
// certificate rather than only in unit tests.
const avDocType = "eu.europa.ec.av.1"

// testSessionHandlerForOpenID4VPWithMdocAv covers an mso_mdoc age-verification
// presentation end to end against the EU reference verifier container.
//
// This is the only place the mdoc disclosure path runs against a real verifier:
// the wallet matches the DCQL query, signs a DeviceResponse with the credential's
// device key, and the verifier accepts it. The relying party certificate the
// container presents is testdata/eudi/verifier/verifier.crt, whose scheme
// extension authorizes eu.europa.ec.av.1 — so the authorization stage runs for
// real and passes because the certificate genuinely permits the query.
func testSessionHandlerForOpenID4VPWithMdocAv(t *testing.T) {
	runEudiSessionTest(t,
		"age verification mdoc is disclosed to the verifier",
		testOpenID4VP_MdocAv_Disclosure,
	)

	runEudiSessionTest(t,
		"an unauthorized mdoc doctype is refused",
		testOpenID4VP_MdocAv_UnauthorizedDocType,
	)
}

// testOpenID4VP_MdocAv_UnauthorizedDocType asks for a docType the verifier's
// certificate does not authorize, and is the check that keeps the test above
// honest: it proves the authorization stage really runs against the certificate's
// scheme extension, so the passing case passes because eu.europa.ec.av.1 was
// added to that authorized set and not because the check was skipped.
//
// The refusal happens before any credential matching, so no credential needs to
// be seeded for this one.
func testOpenID4VP_MdocAv_UnauthorizedDocType(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	dcql := `{
		"credentials": [
		  {
			"id": "age",
			"format": "mso_mdoc",
			"meta": { "doctype_value": "eu.europa.ec.av.2" },
			"claims": [
			  { "path": ["eu.europa.ec.av.2", "age_over_21"] }
			]
		  }
		]
	}`

	testSession := startOpenID4VPSession(t, c, 1, sessionHandler, dcql)
	session := testSession.ClientSession

	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_Error, session.Status)
	require.NotNil(t, session.Error)
	require.Contains(t, session.Error.WrappedError,
		"credential eu.europa.ec.av.2 is not in the authorized set")
}

func testOpenID4VP_MdocAv_Disclosure(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issuer := seedAvMdoc(t, c)

	testSession := startOpenID4VPSessionWithAuthRequest(t, c, 1, sessionHandler,
		createMdocAvAuthRequestRequest(t, issuer))

	session := testSession.ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)

	// No display metadata was stored with the credential (the AV profile does not
	// specify any), so the credential name falls back to the raw docType and the
	// claim has no label. The claim path is the two-component
	// [namespace, elementIdentifier] form mdoc matching requires.
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{{
					CredentialId: avDocType,
					Name:         avDocType,
					IssuerName:   "",
					Attributes: []expectedAttr{
						{
							Path:  []any{avDocType, "age_over_18"},
							Value: boolVal(true),
						},
					},
				}},
			},
		},
	})

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 1, makeDisclosureChoice(choice))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireMdocVerifierResult(t, testSession.VerifierSession, "age", avDocType, "age_over_18", true)
}

// seedAvMdoc issues a real mso_mdoc age credential and stores it the way
// issuance does, returning the issuer so its IACA can be handed to the verifier
// as a trust anchor.
//
// The credential is genuinely signed rather than faked: stdmdoc.NewIssuer builds
// the two-tier IACA/document-signer PKI the AV Blueprint expects, so the stored
// bytes are a credential a verifier can actually check. The device key is stored
// as a holder binding key on the instance, which is what lets the wallet produce
// a DeviceSigned at presentation time — PrepareDisclosure refuses an instance
// without one.
func seedAvMdoc(t *testing.T, c *client.Client) *stdmdoc.Issuer {
	t.Helper()

	issuer, err := stdmdoc.NewIssuer()
	require.NoError(t, err)

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issued, err := issuer.Issue(avDocType, avDocType, map[string]any{"age_over_18": true}, &deviceKey.PublicKey)
	require.NoError(t, err)

	rawCredential, err := cbor.Marshal(issued)
	require.NoError(t, err)

	devicePrivKey, err := x509.MarshalPKCS8PrivateKey(deviceKey)
	require.NoError(t, err)

	// The credential store rejects a holder binding key that carries neither a
	// thumbprint nor a DID, so derive the thumbprint exactly as
	// HolderBindingKeyService does at issuance: hex of the JWK's SHA-256
	// thumbprint over the public key.
	jwkPrivKey, err := jwk.Import(deviceKey)
	require.NoError(t, err)
	jwkPubKey, err := jwkPrivKey.PublicKey()
	require.NoError(t, err)
	require.NoError(t, jwkPubKey.Set(jwk.KeyUsageKey, jwk.ForSignature))
	thumbprintBytes, err := jwkPubKey.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	thumbprint := hex.EncodeToString(thumbprintBytes)

	// The namespace -> elementIdentifier -> value shape mdoc_dcql reads, which is
	// what the mso_mdoc format parser caches at issuance.
	resolvedClaims, err := json.Marshal(map[string]map[string]any{
		avDocType: {"age_over_18": true},
	})
	require.NoError(t, err)

	now := time.Now()
	batch := &models.CredentialBatch{
		IssuerURL:                "https://av-issuer.example.com",
		CredentialIssuer:         "https://av-issuer.example.com",
		VerifiableCredentialType: avDocType,
		Format:                   models.CredentialFormatMsoMdoc,
		Hash:                     "av-integration-batch-hash",
		ProcessedSdJwtPayload:    datatypes.JSON(resolvedClaims),
		IssuedAt:                 datatypes.NullTime{V: now.Add(-time.Hour), Valid: true},
		ExpiresAt:                datatypes.NullTime{V: now.Add(24 * time.Hour), Valid: true},
		BatchSize:                1,
		RemainingCount:           1,
		Instances: []models.IssuedCredentialInstance{
			{
				RawCredential: rawCredential,
				HolderBindingKey: &models.HolderBindingKey{
					Algorithm:           models.KeyAlgorithmECDSA,
					PrivateKey:          devicePrivKey,
					PublicKeyThumbprint: datatypes.NullString{V: thumbprint, Valid: true},
					ECDSA: &models.ECDSAKeyMetadata{
						CurveName: deviceKey.Curve.Params().Name,
					},
				},
			},
		},
	}

	credStore := db.NewCredentialStore(c.EudiStorageForTesting().Db())
	require.NoError(t, credStore.StoreBatch(batch))

	return issuer
}

// createMdocAvAuthRequestRequest builds the verifier's session-creation request
// for the age query.
//
// Unlike createAuthRequestRequestWithDcql this passes the freshly generated IACA
// as issuer_chain rather than a fixture certificate: the credential is signed by
// a per-run PKI, so the verifier can only validate its issuer signature if it is
// told about that run's trust anchor. The body is marshalled rather than
// formatted into a template because a PEM block carries newlines, which have to
// be escaped to survive as a JSON string value.
func createMdocAvAuthRequestRequest(t *testing.T, issuer *stdmdoc.Issuer) string {
	t.Helper()

	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.IACACert().Raw})

	request := map[string]any{
		"type": "vp_token",
		"dcql_query": map[string]any{
			"credentials": []map[string]any{
				{
					"id":     "age",
					"format": string(clientmodels.Format_MsoMdoc),
					"meta":   map[string]any{"doctype_value": avDocType},
					"claims": []map[string]any{
						{"path": []string{avDocType, "age_over_18"}},
					},
				},
			},
		},
		"nonce":              "nonce",
		"jar_mode":           "by_reference",
		"request_uri_method": "post",
		"issuer_chain":       string(chain),
	}

	body, err := json.Marshal(request)
	require.NoError(t, err)
	return string(body)
}

// requireMdocVerifierResult fetches the wallet response from the verifier and
// checks that the vp_token holds a DeviceResponse disclosing exactly the
// requested element.
//
// An mso_mdoc vp_token entry is base64url-encoded CBOR rather than the compact
// JWS the SD-JWT helpers expect, so this cannot reuse requireVerifierResult:
// the value has to be decoded into a DeviceResponse and its issuerSigned items
// unwrapped from their Tag-24 envelopes to read the disclosed claim back.
func requireMdocVerifierResult(
	t *testing.T,
	verifierSession irmaclient.EudiVerifierSession,
	queryId string,
	expectedDocType string,
	expectedElement string,
	expectedValue any,
) {
	t.Helper()

	result, err := irmaclient.GetWalletResponseFromEudiVerifier(verifierSession)
	require.NoError(t, err)
	require.Nil(t, result["error"], "verifier returned error: %v", result["error_description"])

	vpToken, ok := result["vp_token"].(map[string]any)
	require.True(t, ok, "vp_token should be a JSON object, got %T", result["vp_token"])

	entry, ok := vpToken[queryId]
	require.True(t, ok, "vp_token should carry query id %q, got keys %v", queryId, vpToken)

	// The token is either the encoded DeviceResponse itself or a single-element
	// array of them, depending on how the verifier reports one presentation.
	encoded, ok := entry.(string)
	if !ok {
		list, isList := entry.([]any)
		require.True(t, isList, "vp_token[%q] should be a string or array, got %T", queryId, entry)
		require.Len(t, list, 1, "expected exactly one presentation for query %q", queryId)
		encoded, ok = list[0].(string)
		require.True(t, ok, "vp_token[%q][0] should be a string, got %T", queryId, list[0])
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(encoded)
	}
	require.NoError(t, err, "vp_token entry should be base64-encoded CBOR")

	var response stdmdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(raw, &response), "vp_token entry should decode as a DeviceResponse")

	require.Equal(t, uint64(0), response.Status, "DeviceResponse status should be OK")
	require.Len(t, response.Documents, 1)

	document := response.Documents[0]
	require.Equal(t, expectedDocType, document.DocType)
	require.NotNil(t, document.DeviceSigned, "the presented document must carry a DeviceSigned")

	items, ok := document.IssuerSigned.NameSpaces[expectedDocType]
	require.True(t, ok, "namespace %q should be disclosed, got %v", expectedDocType,
		namespaceKeys(document.IssuerSigned.NameSpaces))
	require.Len(t, items, 1, "exactly the requested element should be disclosed")

	disclosed := decodeIssuerSignedItem(t, items[0])
	require.Equal(t, expectedElement, disclosed.ElementIdentifier)
	require.Equal(t, expectedValue, disclosed.ElementValue)
}

// decodeIssuerSignedItem unwraps one Tag-24 wrapped issuerSigned item. The outer
// Tag-24 has to be peeled before the inner byte string decodes as an item; the
// bytes are treated as read-only here since re-encoding them would break the
// digest they were hashed under.
func decodeIssuerSignedItem(t *testing.T, item stdmdoc.Tag24Item) stdmdoc.IssuerSignedItem {
	t.Helper()

	var rawTag cbor.RawTag
	require.NoError(t, cbor.Unmarshal(item.EncodedItem, &rawTag))
	require.Equal(t, uint64(24), rawTag.Number, "issuerSigned items are Tag-24 wrapped")

	var inner []byte
	require.NoError(t, cbor.Unmarshal(rawTag.Content, &inner))

	var decoded stdmdoc.IssuerSignedItem
	require.NoError(t, cbor.Unmarshal(inner, &decoded))
	return decoded
}

func namespaceKeys(namespaces map[string][]stdmdoc.Tag24Item) []string {
	keys := make([]string, 0, len(namespaces))
	for key := range namespaces {
		keys = append(keys, key)
	}
	return keys
}
