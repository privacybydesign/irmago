package sessiontest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Minting adversarial authorization requests
//
// The rig behind the refusal subtests: the reference verifier signs a genuine
// request object, exactly one thing about it is changed, and the result is
// re-signed with the verifier's own key from testdata/eudi/verifier and served in
// place of the original. Everything else — the session at the container, the link,
// the response endpoint — stays real, so a refusal is attributable to the one
// mutation rather than to a hand-built request the wallet would have rejected on
// any number of grounds.
//
// The subtests themselves live with the flow they belong to rather than in a
// violations pile of their own: request-object and DCQL refusals next to the
// disclosure they subvert in openid4vp_mdoc_av_disclosure_test.go, issuance
// refusals beside the issuance in eudi_pid_python_issuer_mdoc_test.go, and so on.
// Only the machinery is shared, and it lives here.
//
// Ported from the mdoc-violations CLI, which reported outcomes rather than
// asserting them. A report is read only when someone runs it; these run with every
// other integration test, so a regression that starts accepting a malformed
// request fails a build instead of waiting to be noticed.
// ============================================================================

// requireMdocViolationRefused asserts a session failed rather than completing.
//
// The wrapped error is not pinned to a string: what these subtests are about is
// that the request was refused, and pinning the message would make every one of
// them fail on a reworded error. Which stage refused it is asserted only where
// that is the point of the subtest.
func requireMdocViolationRefused(t *testing.T, session clientmodels.SessionState) {
	t.Helper()

	require.Equal(t, clientmodels.Status_Error, session.Status,
		"the session should have been refused, but reached status %q", session.Status)
	require.NotNil(t, session.Error, "a refused session must carry an error")
	require.NotEmpty(t, session.Error.WrappedError,
		"a refused session must say why, or the refusal cannot be attributed")
}

// requireMdocAvRequestRefused is the shape most refusal subtests take: issue a
// credential for real, mutate one thing about the verifier's request object, and
// require the wallet to refuse the session.
//
// The credential is issued even for violations refused long before any credential
// is looked at, so that a refusal cannot be the trivial one — "nothing to
// disclose" — dressed up as a protocol check.
func requireMdocAvRequestRefused(t *testing.T, mutate func(hdr, claims map[string]any)) {
	t.Helper()
	requireMdocAvRefusal(t, mdocAvRefusalCase{Mutate: mutate})
}

// requireMdocAvRequestRefusedWithClientId is the same with the wallet link's
// client_id replaced, for mutations that change the client_id inside the request
// object. Empty leaves the verifier's own in place.
func requireMdocAvRequestRefusedWithClientId(
	t *testing.T,
	linkClientId string,
	mutate func(hdr, claims map[string]any),
) {
	t.Helper()
	requireMdocAvRefusal(t, mdocAvRefusalCase{LinkClientId: linkClientId, Mutate: mutate})
}

// mdocAvRefusalCase is one minted-request refusal.
type mdocAvRefusalCase struct {
	// Mutate changes the request object. Required.
	Mutate func(hdr, claims map[string]any)

	// SigningKey re-signs the request with a key other than the reference
	// verifier's, for the subtests about which certificate may authenticate a
	// relying party. Nil signs with the verifier's own.
	SigningKey *ecdsa.PrivateKey

	// RawTransform rewrites the request object as a string, for the subtests about
	// the JWS itself: an unsigned two-segment token or one re-signed as an HMAC
	// cannot be expressed as a change to the header and claims of a signed one.
	// Mutually exclusive with Mutate.
	RawTransform func(t *testing.T, requestJwt string) string

	// ErrorContains pins a fragment of the refusal message.
	//
	// Left empty for most subtests, where the message is not the property under
	// test and pinning it would break on a reword. Set where being refused for the
	// *right* reason is the point: an expired certificate refused as "unknown
	// authority" would mean the date check never ran, and the subtest would pass
	// while covering nothing.
	ErrorContains string

	// VerifierHost picks the container. Empty means the direct_post one, which is
	// the AV Blueprint's response mode; the direct_post.jwt one is needed only by
	// subtests about response encryption, since client_metadata carries a jwks
	// there and nowhere else.
	VerifierHost string

	// LinkClientId replaces the client_id in the wallet link, for mutations that
	// change the client_id inside the request object.
	LinkClientId string
}

func requireMdocAvRefusal(t *testing.T, testCase mdocAvRefusalCase) {
	t.Helper()

	host := testCase.VerifierHost
	if host == "" {
		host = testdata.OpenID4VP_DirectPost_Host
	}

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	require.True(t, (testCase.Mutate == nil) != (testCase.RawTransform == nil),
		"a refusal case sets exactly one of Mutate and RawTransform")

	transform := testCase.RawTransform
	if transform == nil {
		transform = func(t *testing.T, requestJwt string) string {
			return mintRequestVariantSignedBy(t, requestJwt, testCase.SigningKey, testCase.Mutate)
		}
	}

	testSession, _ := startMdocAvSessionServingRequest(t, c, 2, sessionHandler,
		host, createAvMdocAuthRequest(t),
		mdocAvRequestOverrides{
			LinkClientId: testCase.LinkClientId,
			Transform:    transform,
		})

	requireMdocViolationRefused(t, testSession.ClientSession)
	if testCase.ErrorContains != "" {
		require.Contains(t, testSession.ClientSession.Error.WrappedError, testCase.ErrorContains,
			"refused, but not for the reason this subtest is about")
	}
}

// requireMdocAvResponseRefused is for a mutation the wallet does not catch while
// validating the request, and discovers only when it tries to answer.
//
// Worth telling apart from requireMdocAvRefusal rather than folding into one
// "session fails" helper: the wallet asks the user to approve a disclosure it then
// cannot make. Nothing is disclosed, so the security property holds, but the
// refusal lands after consent rather than before it — and which subtests are in
// this shape is the record of where that happens.
func requireMdocAvResponseRefused(t *testing.T, testCase mdocAvRefusalCase) {
	t.Helper()

	host := testCase.VerifierHost
	if host == "" {
		host = testdata.OpenID4VP_DirectPost_Host
	}

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	testSession, _ := startMdocAvSessionServingRequest(t, c, 2, sessionHandler,
		host, createAvMdocAuthRequest(t),
		mdocAvRequestOverrides{
			LinkClientId: testCase.LinkClientId,
			Transform: func(t *testing.T, requestJwt string) string {
				return mintRequestVariant(t, requestJwt, testCase.Mutate)
			},
		})

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 2, makeDisclosureChoice(choice))

	requireMdocViolationRefused(t, awaitSessionState(t, sessionHandler))
}

// ----------------------------------------------------------------------------
// Posting a response without the wallet
// ----------------------------------------------------------------------------

// encodedVpToken returns the presentation the verifier recorded, still encoded, so
// a subtest can post it somewhere it does not belong.
func encodedVpToken(t *testing.T, verifierSession EudiVerifierSession, queryId string) string {
	t.Helper()

	result, err := GetWalletResponseFromEudiVerifier(verifierSession)
	require.NoError(t, err)
	require.Nil(t, result["error"], "verifier returned error: %v", result["error_description"])

	vpToken, ok := result["vp_token"].(map[string]any)
	require.True(t, ok, "vp_token should be a JSON object, got %T", result["vp_token"])

	entry, ok := vpToken[queryId]
	require.True(t, ok, "vp_token should carry query id %q", queryId)

	if encoded, ok := entry.(string); ok {
		return encoded
	}
	list, ok := entry.([]any)
	require.True(t, ok, "vp_token[%q] should be a string or array, got %T", queryId, entry)
	require.Len(t, list, 1)
	encoded, ok := list[0].(string)
	require.True(t, ok)
	return encoded
}

// responseBindingFromRequest reads where a response goes and under what state, out
// of the request object the verifier signed.
func responseBindingFromRequest(t *testing.T, requestJwt string) (responseUri, state string) {
	t.Helper()

	parts := strings.Split(requestJwt, ".")
	require.Len(t, parts, 3)
	claims := decodeJwtSegment(t, parts[1])

	responseUri, _ = claims["response_uri"].(string)
	state, _ = claims["state"].(string)
	require.NotEmpty(t, responseUri, "the request object should name a response_uri")
	require.NotEmpty(t, state, "the request object should carry a state")
	return responseUri, state
}

// postVpTokenDirectly submits a presentation to a response_uri the way the wallet
// would, without the wallet.
//
// The envelope matters: vp_token is an object keyed by DCQL query id, not a bare
// string, and posting a raw token instead makes the verifier fail to parse the body
// — which looks like a rejection while proving nothing.
func postVpTokenDirectly(t *testing.T, responseUri, state, queryId, encodedToken string) (int, string) {
	t.Helper()

	envelope, err := json.Marshal(map[string]any{queryId: []string{encodedToken}})
	require.NoError(t, err)

	form := url.Values{}
	form.Set("vp_token", string(envelope))
	form.Set("state", state)

	response, err := http.PostForm(responseUri, form)
	require.NoError(t, err)
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.StatusCode, string(body)
}

// requireVerifierRefusesCredentialQuery requires the container to refuse a DCQL
// credential query outright, before any wallet is involved.
//
// A structurally invalid query never becomes a session, so there is nothing for a
// wallet to reject and the assertion belongs here. Worth asserting rather than
// skipping: it records which malformed shapes the reference verifier catches, and
// therefore which ones the wallet-side checks can only be reached through a minted
// request object.
func requireVerifierRefusesCredentialQuery(t *testing.T, credential map[string]any) {
	t.Helper()

	authRequest := createAvMdocAuthRequestWithCredentialQuery(t, credential)

	_, err := StartTestSessionAtEudiVerifier(testdata.OpenID4VP_DirectPost_Host, authRequest)
	require.Error(t, err, "the verifier should refuse to start a session for this query")
}

// requireMdocAvRequestUriRefused answers request_uri with something that is not a
// request object, and requires the wallet to refuse the session.
//
// About the fetch rather than its contents: request_uri is a URL the wallet is told
// to go to by a link, so what comes back is whatever that host chooses to send. A
// wallet that treated an unparseable or failed fetch as anything other than the end
// of the session would be proceeding on a request it never read.
func requireMdocAvRequestUriRefused(t *testing.T, body, contentType string, status int) {
	t.Helper()

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	testSession, _ := startMdocAvSessionServingRequest(t, c, 2, sessionHandler,
		testdata.OpenID4VP_DirectPost_Host, createAvMdocAuthRequest(t),
		mdocAvRequestOverrides{
			ServeRaw: &rawServedRequestObject{
				Body:        body,
				ContentType: contentType,
				Status:      status,
			},
		})

	requireMdocViolationRefused(t, testSession.ClientSession)
}

// requireMdocAvQueryRefused starts a real verifier session for a query the
// relying party is not authorized to make, and requires the wallet to refuse it.
//
// Unlike the request-object subtests nothing is minted here: the container signs
// the query as given, because what is under test is the wallet's authorization
// check against the certificate's scheme extension rather than its handling of a
// malformed request.
func requireMdocAvQueryRefused(t *testing.T, docType, format string, claims []map[string]any) {
	t.Helper()

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	authRequest := createAvMdocAuthRequestWithCredentialQuery(t, map[string]any{
		"id":     "age",
		"format": format,
		"meta":   map[string]any{"doctype_value": docType},
		"claims": claims,
	})

	testSession, _ := startMdocAvSessionCapturingRequest(t, c, 2, sessionHandler,
		testdata.OpenID4VP_DirectPost_Host, authRequest)

	requireMdocViolationRefused(t, testSession.ClientSession)
}

// requireMdocAvQueryYieldsNothingToDisclose is for a query the relying party may
// make but no credential can answer.
//
// Distinct from a refusal on purpose: an authorized query that happens to match
// nothing is not a protocol violation, and the wallet is right to reach the
// permission step and show the user that nothing satisfies it. What must not
// happen is a disclosure.
func requireMdocAvQueryYieldsNothingToDisclose(t *testing.T, docType, format string, claims []map[string]any) {
	t.Helper()

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	authRequest := createAvMdocAuthRequestWithCredentialQuery(t, map[string]any{
		"id":     "age",
		"format": format,
		"meta":   map[string]any{"doctype_value": docType},
		"claims": claims,
	})

	testSession, _ := startMdocAvSessionCapturingRequest(t, c, 2, sessionHandler,
		testdata.OpenID4VP_DirectPost_Host, authRequest)

	session := testSession.ClientSession

	// The wallet reaches the permission step with an empty overview rather than
	// erroring, which is the right shape: the request was authentic and authorized,
	// so the user is shown a request they cannot satisfy instead of a failure. What
	// matters is that there is no choice to make — an option here would mean the
	// wallet found a credential for a query nothing it holds can answer.
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.NotNil(t, session.DisclosurePlan)
	require.Empty(t, session.DisclosurePlan.DisclosureChoicesOverview,
		"the wallet holds nothing that satisfies this query and must offer nothing to disclose")
}

// userInteractionAllowingFailure is userInteraction without its require.NoError.
//
// Needed by the issuance refusal subtests: when the token endpoint rejects a
// transaction code, HandleUserInteraction reports that failure to its caller as
// well as moving the session on, so the shared helper's assertion would fail the
// test for the very thing it is asserting happens.
func userInteractionAllowingFailure(c *client.Client, interaction clientmodels.SessionUserInteraction) {
	go func() { _ = c.HandleUserInteraction(interaction) }()
}

// mintRequestVariant re-signs a request object after applying mutate to its header
// and claims, with the reference verifier's own key.
//
// Re-signing rather than editing in place is what keeps the wallet's own checks in
// play: a request whose signature no longer matches is refused before anything
// else is read, so a subtest about (say) an unknown response_mode would be
// answered by the signature check instead of by the code under test.
//
// An "alg": "none" header yields an unsigned two-dot JWT, since signing one would
// contradict the very thing that subtest asserts.
func mintRequestVariant(t *testing.T, requestJwt string, mutate func(hdr, claims map[string]any)) string {
	t.Helper()
	return mintRequestVariantSignedBy(t, requestJwt, nil, mutate)
}

// mintRequestVariantSignedBy is the same signed by an arbitrary key, for the
// subtests about which certificate is allowed to authenticate a relying party. A
// nil key means the reference verifier's own.
func mintRequestVariantSignedBy(
	t *testing.T,
	requestJwt string,
	key *ecdsa.PrivateKey,
	mutate func(hdr, claims map[string]any),
) string {
	t.Helper()

	if key == nil {
		key = verifierSigningKey(t)
	}

	parts := strings.Split(requestJwt, ".")
	require.Len(t, parts, 3, "the verifier's request object should be a three-part JWS")

	hdr := decodeJwtSegment(t, parts[0])
	claims := decodeJwtSegment(t, parts[1])

	mutate(hdr, claims)

	newHdr, err := json.Marshal(hdr)
	require.NoError(t, err)
	newClaims, err := json.Marshal(claims)
	require.NoError(t, err)

	input := base64.RawURLEncoding.EncodeToString(newHdr) + "." +
		base64.RawURLEncoding.EncodeToString(newClaims)

	if hdr["alg"] == "none" {
		return input + "."
	}
	return input + "." + signJwtES256(t, key, input)
}

// corruptJwtSignature flips a bit in the signature, leaving a syntactically valid
// JWS whose signature cannot verify.
//
// The flip is in the decoded bytes rather than in the base64 text on purpose: a
// 64-byte signature encodes to 86 base64url characters whose last character
// carries four unused bits, so flipping the final character can leave the decoded
// bytes identical and the signature still valid — which made the CLI's version of
// this pass or fail at random until it was moved.
func corruptJwtSignature(t *testing.T, requestJwt string) string {
	t.Helper()

	parts := strings.Split(requestJwt, ".")
	require.Len(t, parts, 3)

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	sig[0] ^= 0x01

	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// resignAsHS256 rewrites the request object as an HMAC-signed token whose secret
// is the public key its own x5c header advertises.
//
// The classic algorithm-confusion attack. A verifier that reads alg from the token
// and then looks up "the key" will hand an ECDSA public key to an HMAC
// verification — and that key is public, printed in the certificate the request
// carries, so anyone can compute the MAC. The x5c chain is left untouched, so the
// request still looks like it comes from the real relying party.
func resignAsHS256(t *testing.T, requestJwt string) string {
	t.Helper()

	parts := strings.Split(requestJwt, ".")
	require.Len(t, parts, 3)

	hdr := decodeJwtSegment(t, parts[0])

	// The secret is the SPKI of the certificate's public key: what an
	// implementation that trusted alg would end up using.
	chain, ok := hdr["x5c"].([]any)
	require.True(t, ok, "the request should carry an x5c chain")
	require.NotEmpty(t, chain)
	leaf, ok := chain[0].(string)
	require.True(t, ok)
	der, err := base64.StdEncoding.DecodeString(leaf)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	secret, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	require.NoError(t, err)

	hdr["alg"] = "HS256"
	newHdr, err := json.Marshal(hdr)
	require.NoError(t, err)

	input := base64.RawURLEncoding.EncodeToString(newHdr) + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// dropJwtSignature returns the request object with its signature segment removed
// entirely, leaving two segments where RFC 7515 §3.1 requires three.
func dropJwtSignature(t *testing.T, requestJwt string) string {
	t.Helper()

	parts := strings.Split(requestJwt, ".")
	require.Len(t, parts, 3)
	return parts[0] + "." + parts[1]
}

func decodeJwtSegment(t *testing.T, segment string) map[string]any {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(segment)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	return decoded
}

// verifierSigningKey loads the private key behind the certificate the reference
// verifier container presents, so a minted request carries a signature the
// wallet's trust in that container's chain actually covers.
func verifierSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "eudi", "verifier", "verifier_ec_priv.pem"))
	require.NoError(t, err, "the verifier signing key is needed to mint request variants")

	block, _ := pem.Decode(raw)
	require.NotNil(t, block, "the verifier key should be PEM")

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)

	key, ok := parsed.(*ecdsa.PrivateKey)
	require.True(t, ok, "the verifier key should be ECDSA, got %T", parsed)
	return key
}

// ----------------------------------------------------------------------------
// Certificates to sign an adversarial request with
// ----------------------------------------------------------------------------

// selfSignedLocalhostCert mints a certificate that is correct in every respect
// except its anchor: right common name, right SAN, its own valid signature, and
// nothing above it.
func selfSignedLocalhostCert(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{CommonName: "localhost", Organization: []string{"Rogue"}},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return key, der
}

// relyingPartyCA loads the CA that signs the certificate the reference verifier
// presents, so a subtest can mint leaves the wallet's verifier trust store
// genuinely anchors.
func relyingPartyCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	base := filepath.Join("..", "..", "testdata", "eudi", "verifier")

	certPEM, err := os.ReadFile(filepath.Join(base, "ca.crt"))
	require.NoError(t, err)
	certBlock, _ := pem.Decode(certPEM)
	require.NotNil(t, certBlock, "the verifier CA should be PEM")
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)

	keyPEM, err := os.ReadFile(filepath.Join(base, "ca_ec_priv.pem"))
	require.NoError(t, err)
	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock, "the verifier CA key should be PEM")

	if key, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		return caCert, key
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	key, ok := parsed.(*ecdsa.PrivateKey)
	require.True(t, ok, "the verifier CA key should be ECDSA, got %T", parsed)
	return caCert, key
}

// mintRelyingPartyLeaf issues a leaf from the CA the wallet trusts for relying
// parties, with the validity window the caller asks for.
//
// Everything a wallet checks about a relying party certificate other than the
// dates is left correct — the anchor, the SAN, the key usage — so a refusal is
// about the window and not about the certificate being odd in some other way.
func mintRelyingPartyLeaf(t *testing.T, notBefore, notAfter time.Time) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	caCert, caKey := relyingPartyCA(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost", Organization: []string{"Yivi"}},
		DNSNames:              []string{"localhost"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	return key, der
}

// pidIssuerSigningIdentity loads the PID issuer's document signer key and chain —
// a chain the wallet genuinely trusts, but as an issuer rather than as a relying
// party.
func pidIssuerSigningIdentity(t *testing.T) (*ecdsa.PrivateKey, [][]byte) {
	t.Helper()

	base := filepath.Join("..", "..", "testdata", "eudi-pid-issuer-py", "certs")

	keyPEM, err := os.ReadFile(filepath.Join(base, "issuer.key"))
	require.NoError(t, err)
	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock, "the issuer key should be PEM")

	var key *ecdsa.PrivateKey
	if parsed, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		key = parsed
	} else {
		anyKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		require.NoError(t, err)
		ecKey, ok := anyKey.(*ecdsa.PrivateKey)
		require.True(t, ok, "the issuer key should be ECDSA, got %T", anyKey)
		key = ecKey
	}

	chainPEM, err := os.ReadFile(filepath.Join(base, "issuer-chain.pem"))
	require.NoError(t, err)

	var chain [][]byte
	for rest := chainPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	require.NotEmpty(t, chain, "the issuer chain should hold at least one certificate")

	return key, chain
}

// x5cHeader encodes DER certificates the way a JOSE x5c header carries them.
func x5cHeader(certificates ...[]byte) []any {
	encoded := make([]any, 0, len(certificates))
	for _, der := range certificates {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(der))
	}
	return encoded
}

// signJwtES256 signs the signing input with the fixed-width r||s encoding JWS
// requires, which is not what crypto/ecdsa's ASN.1 output gives.
func signJwtES256(t *testing.T, key *ecdsa.PrivateKey, input string) string {
	t.Helper()

	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	require.NoError(t, err)

	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}
