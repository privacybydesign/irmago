package sessiontest

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
)

// These tests cover an mso_mdoc presented over the W3C Digital Credentials API,
// which signs a different session transcript than the URL flow does: OpenID4VP
// Annex B.2.6.2 hashes [origin, nonce, jwkThumbprint] under
// "OpenID4VPDCAPIHandover", where B.2.6.1 hashes
// [clientId, nonce, jwkThumbprint, responseUri] under "OpenID4VPHandover".
//
// They run through the app-facing client API rather than calling the DCQL
// handler directly, because the interesting part is precisely the wiring in
// between: the origin the platform authenticated has to reach the handler as a
// bare value, while the audience carries the same origin behind an "origin:"
// prefix. A unit test on the handler cannot catch that value going missing.
//
// Getting the variant wrong is invisible from the wallet's side — the response
// is built, transmitted and decrypted normally, and only the verifier's
// deviceAuth check fails — so these tests verify the presentation the way a
// conformant verifier would, against a transcript derived here from the spec
// formula rather than from the production helper.

const dcApiMdocQueryId = "av_credential"

func testSessionHandlerForOpenID4VPOverDcApiWithMdoc(t *testing.T) {
	t.Run("an mdoc disclosed over the dc api signs the dc api handover",
		testDcApiMdocDisclosure)
	t.Run("the url-flow handover does not verify an mdoc disclosed over the dc api",
		testDcApiMdocRejectsUrlFlowHandover)
	t.Run("an encrypted dc api response signs the key it is encrypted to",
		testDcApiMdocEncryptedDisclosure)
}

// seedDcApiMdocWallet returns a wallet holding a genuinely issued age credential.
//
// The credential is fetched from the reference issuer over OpenID4VCI rather than
// written into storage: what these subtests are about is the handover deviceAuth
// signs over, but they can only reach it through a stored credential, and a
// hand-built one asserts that the test agrees with itself about how issuance
// stores things -- the device key, the cached namespaced claims, the batch. The
// credential that comes back is signed by the issuer CA the containers are
// configured with, which is what requireDeviceAuthVerifies anchors on.
//
// Issuance runs as session 1, so every subtest below starts its disclosure at 2.
func seedDcApiMdocWallet(t *testing.T) (*client.Client, *MockSessionHandler) {
	t.Helper()

	c, sessionHandler := createPidIssuerTestClient(t)
	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	return c, sessionHandler
}

func testDcApiMdocDisclosure(t *testing.T) {
	c, sessionHandler := seedDcApiMdocWallet(t)
	defer c.Close()

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiMdocData(t, string(openid4vp.ResponseMode_DcApi), nil),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	require.NotEmpty(t, session.DcApiResponse, "the wallet must return a DC API response")

	response := requireDcApiDeviceResponse(t, session.DcApiResponse)
	requireDeviceAuthVerifies(t, response, dcApiSessionTranscript(t, dcApiOrigin, dcApiNonce, nil))
}

// testDcApiMdocRejectsUrlFlowHandover is the negative half. Without it the test
// above would still pass if the wallet signed the URL-flow handover and the two
// variants happened to agree on a digest.
func testDcApiMdocRejectsUrlFlowHandover(t *testing.T) {
	c, sessionHandler := seedDcApiMdocWallet(t)
	defer c.Close()

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiMdocData(t, string(openid4vp.ResponseMode_DcApi), nil),
	})
	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	response := requireDcApiDeviceResponse(t, session.DcApiResponse)

	// The URL-flow handover over the same session's values: over the DC API the
	// audience is the origin-prefixed one and there is no response_uri, which is
	// exactly what a wallet that never learned about the second variant signs.
	urlFlowHandoverInfo, err := cbor.Marshal([]any{
		openid4vp.OriginAudience(dcApiOrigin), dcApiNonce, nil, "",
	})
	require.NoError(t, err)
	urlFlowDigest := sha256.Sum256(urlFlowHandoverInfo)
	urlFlow := stdmdoc.SessionTranscript{
		Handover: []any{"OpenID4VPHandover", urlFlowDigest[:]},
	}

	verifier := stdmdoc.NewVerifier([]*x509.Certificate{eudiPidIssuerPyCACert(t)})
	results, err := verifier.VerifyDeviceResponse(response, avDocType, avDocType, urlFlow)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.False(t, results[0].DeviceAuthValid,
		"a presentation made over the DC API must not verify against the URL-flow handover")
}

// testDcApiMdocEncryptedDisclosure covers dc_api.jwt, which is the path the AV
// Blueprint actually uses and the only one where the handover's third element is
// not null: deviceAuth commits to the thumbprint of the key the response is
// encrypted to, so the wallet has to pick that key before signing and then
// encrypt to that very key. A mismatch decrypts fine and fails the signature.
func testDcApiMdocEncryptedDisclosure(t *testing.T) {
	c, sessionHandler := seedDcApiMdocWallet(t)
	defer c.Close()

	privateKey, clientMetadata := dcApiEncryptionClientMetadata(t)

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiMdocData(t, string(openid4vp.ResponseMode_DcApiJwt), clientMetadata),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	var envelope struct {
		Response string          `json:"response"`
		VpToken  json.RawMessage `json:"vp_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(session.DcApiResponse), &envelope))
	require.NotEmpty(t, envelope.Response, "the encrypted response goes in the response member")
	require.Empty(t, envelope.VpToken, "the vp_token must not be sent in the clear")

	decrypted, err := jwe.Decrypt([]byte(envelope.Response), jwe.WithKey(jwa.ECDH_ES(), privateKey))
	require.NoError(t, err)

	response := requireDcApiDeviceResponse(t, string(decrypted))

	// The thumbprint is derived from the public half of the key the verifier
	// published, independently of what the wallet selected — that agreement is
	// the property under test.
	publicKey, err := privateKey.PublicKey()
	require.NoError(t, err)
	thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	requireDeviceAuthVerifies(t, response,
		dcApiSessionTranscript(t, dcApiOrigin, dcApiNonce, thumbprint))
}

// unsignedDcApiMdocData builds the `data` member of an unsigned DC API request
// querying for the AV mdoc's age_over_18 element.
func unsignedDcApiMdocData(t *testing.T, responseMode string, clientMetadata map[string]any) json.RawMessage {
	t.Helper()
	request := map[string]any{
		"response_type": "vp_token",
		"response_mode": responseMode,
		"nonce":         dcApiNonce,
		"dcql_query": map[string]any{
			"credentials": []any{map[string]any{
				"id":     dcApiMdocQueryId,
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": avDocType,
				},
				"claims": []any{map[string]any{
					"path": []string{avDocType, "age_over_18"},
				}},
			}},
		},
	}
	if clientMetadata != nil {
		request["client_metadata"] = clientMetadata
	}
	data, err := json.Marshal(request)
	require.NoError(t, err)
	return data
}

// requireDcApiDeviceResponse reads the single mdoc presentation out of a DC API
// response. An mso_mdoc vp_token entry is base64url-encoded CBOR rather than the
// compact JWS the SD-JWT helpers expect.
func requireDcApiDeviceResponse(t *testing.T, dcApiResponse string) stdmdoc.DeviceResponse {
	t.Helper()

	presentation := requireSinglePresentation(t, requireVpTokenFromResponse(t, dcApiResponse), dcApiMdocQueryId)

	encoded, err := base64.RawURLEncoding.DecodeString(presentation)
	require.NoError(t, err, "an mso_mdoc vp_token entry is base64url-encoded CBOR")

	var response stdmdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(encoded, &response))
	require.Len(t, response.Documents, 1)
	return response
}

// dcApiSessionTranscript spells out OpenID4VP Annex B.2.6.2 rather than calling
// the wallet's own helper, so a change to either side has to be made twice. This
// is the same reasoning avSessionTranscript follows for the URL flow.
func dcApiSessionTranscript(t *testing.T, origin, nonce string, thumbprint []byte) stdmdoc.SessionTranscript {
	t.Helper()

	handoverInfo, err := cbor.Marshal([]any{origin, nonce, encryptionKeyElement(thumbprint)})
	require.NoError(t, err)
	digest := sha256.Sum256(handoverInfo)

	return stdmdoc.SessionTranscript{
		Handover: []any{"OpenID4VPDCAPIHandover", digest[:]},
	}
}
