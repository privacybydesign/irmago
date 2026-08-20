package openid4vp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// A did:web verifier whose verification method carries an X.509 certificate over
// its key is ranked and authorization-checked by that certificate, exactly as an
// x5c-header verifier is, while staying known by its DID.
//
// The certificate channel here is honest rather than a stub: the same trust model
// the validator classifies against backs the client's rung (contextClassifier
// below), so the unanchored case ranks low instead of borrowing a fixed high.

// contextClassifier ranks a certificate by whether it chains to an anchor the
// given context holds, mirroring TrustModel.Classify against a test context so a
// rung follows the same chain build the `anchored` decision does.
type contextClassifier struct {
	ctx     eudi_jwt.X509VerificationContext
	confers clientmodels.TrustLevel
}

func (c contextClassifier) Classify(leaf *x509.Certificate) clientmodels.TrustLevel {
	if leaf == nil || eudi_jwt.VerifyCertificate(c.ctx, leaf, nil) != nil {
		return clientmodels.TrustLevel_Unevaluated
	}
	return c.confers
}

// One attested did:web verifier: the request it signs, the DID it is known by, the
// leaf its key carries in the document, and the trust model it is classified
// against.
type didAttestFixture struct {
	authRequestJwt string
	did            string
	leaf           *x509.Certificate
	ctx            *eudi.TrustModel
	// didClient reaches the DID document the fixture published; see
	// didWebLoopbackTransport for why the test routes this itself.
	didClient *http.Client
}

// newDidAttestFixture builds an attested did:web verifier. opts shapes the leaf,
// anchorRoot decides whether the trust model holds the root it chains to, and
// x5cOverride stages a key-mismatch by embedding a different leaf.
func newDidAttestFixture(
	t *testing.T,
	opts testdata.PkiGenerationOptions,
	anchorRoot bool,
	x5cOverride *x509.Certificate,
) didAttestFixture {
	t.Helper()

	crlDistPoint := "https://yivi.app/crl.crl"
	_, rootCert, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(
		t, testdata.CreateDistinguishedName("ATTEST ROOT"), 1, opts, &crlDistPoint)
	verifierKey, leaf, _ := testdata.CreateEndEntityCertificate(
		t, testdata.CreateDistinguishedName(EndEntityCN), "did.example",
		caCerts[0], caKeys[0], testdata.VerifierCertSchemeData, opts)

	x5cLeaf := leaf
	if x5cOverride != nil {
		x5cLeaf = x5cOverride
	}

	pub, err := jwk.Import(verifierKey.Public())
	require.NoError(t, err)
	chain := &cert.Chain{}
	require.NoError(t, chain.AddString(base64.StdEncoding.EncodeToString(x5cLeaf.Raw)))
	require.NoError(t, pub.Set(jwk.X509CertChainKey, chain))

	var didWeb string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"@context": []string{"https://www.w3.org/ns/did/v1"},
			"id":       didWeb,
			"verificationMethod": []any{map[string]any{
				"id":           didWeb + "#key-1",
				"type":         "JsonWebKey2020",
				"controller":   didWeb,
				"publicKeyJwk": pub,
			}},
		}))
	}))
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	didWeb = "did:web:" + strings.ReplaceAll(serverURL.Host, ":", "%3A")

	authRequestJwt := testdata.CreateTestAuthorizationRequestJWTWithClientId(
		"decentralized_identifier:"+didWeb, verifierKey, leaf,
		func(token *jwt.Token) { delete(token.Header, "x5c") },
	)

	rootPool := x509.NewCertPool()
	if anchorRoot {
		rootPool.AddCert(rootCert)
	}
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(caCerts[0])
	revocationLists := revocationListsFor(t, opts, leaf, caCerts[0], caKeys[0])
	ctx := eudi.NewTestTrustModel(t.TempDir(), rootPool, intermediatePool, revocationLists)

	return didAttestFixture{
		authRequestJwt: authRequestJwt,
		did:            didWeb,
		leaf:           leaf,
		ctx:            ctx,
		didClient:      didWebLoopbackClient(serverURL.Host),
	}
}

// A client whose verifier certificate channel is the same trust model the
// validator classifies against.
func clientForFixture(f didAttestFixture, factory QueryValidatorFactory, confers clientmodels.TrustLevel, checker *lote.Checker) *Client {
	validator := NewDidVerifierValidator(true, f.ctx, factory)
	validator.didWebResolver.HTTPClient = f.didClient
	trustService := services.NewTrustService(checker,
		staticClassifier(clientmodels.TrustLevel_High),
		contextClassifier{ctx: f.ctx, confers: confers})
	client, _ := NewClient(nil, []dcql.DcqlCredentialQueryHandler{stubQueryHandler{}}, validator, nil, trustService)
	return client
}

func TestNewSession_AttestedDidWebVerifier_RanksHighFromItsCertificate(t *testing.T) {
	f := newDidAttestFixture(t, testdata.PkiOption_None, true, nil)
	client := clientForFixture(f, &MockQueryValidatorFactory{}, clientmodels.TrustLevel_High, nil)
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, f.authRequestJwt), handler).Dismiss()

	requestor := handler.awaitRequestor(t)
	require.Equal(t, clientmodels.TrustLevel_High, requestor.TrustLevel,
		"a did:web key attested under the anchors is vouched for at the anchor's level")
	require.Equal(t, "Yivi B.V.", requestor.Name,
		"the attested name comes from the certificate, not the request's own word")
	require.Equal(t, f.did, requestor.Id,
		"an attested DID party is still known by its DID, not a certificate serial")
}

func TestNewSession_AttestedDidWebVerifier_RanksMediumUnderAThirdPartyAnchor(t *testing.T) {
	f := newDidAttestFixture(t, testdata.PkiOption_None, true, nil)
	client := clientForFixture(f, &MockQueryValidatorFactory{}, clientmodels.TrustLevel_Medium, nil)
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, f.authRequestJwt), handler).Dismiss()

	requestor := handler.awaitRequestor(t)
	require.Equal(t, clientmodels.TrustLevel_Medium, requestor.TrustLevel,
		"an anchored third-party CA confers medium on the attested DID key")
	require.Equal(t, "Yivi B.V.", requestor.Name)
	require.Equal(t, f.did, requestor.Id)
}

func TestNewSession_UnanchoredDidWebCertificate_RanksLowAndProceeds(t *testing.T) {
	// A well-formed, in-date certificate the wallet holds no anchor for is absent
	// evidence, not a defect: the session proceeds at low, self-asserted and
	// logoless.
	f := newDidAttestFixture(t, testdata.PkiOption_None, false, nil)
	client := clientForFixture(f, &MockQueryValidatorFactory{}, clientmodels.TrustLevel_High, nil)
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, f.authRequestJwt), handler).Dismiss()

	requestor := handler.awaitRequestor(t)
	require.Equal(t, clientmodels.TrustLevel_Low, requestor.TrustLevel,
		"a certificate no anchor stands behind lifts no rung")
	require.Equal(t, f.did, requestor.Id)
	require.Nil(t, requestor.Image, "nothing an unanchored certificate carries renders a logo")
	require.Equal(t, int32(0), handler.cancels.Load(), "the session still reaches the user")
}

func TestNewSession_KeyMismatchedDidWebCertificate_ReportsPartyValidationFailed(t *testing.T) {
	// A leaf over a different key pasted into the document: the RFC 7517 §4.7
	// forgery. It refuses, and the app must be able to say so.
	foreign := newDidAttestFixture(t, testdata.PkiOption_None, true, nil)
	f := newDidAttestFixture(t, testdata.PkiOption_None, true, foreign.leaf)
	client := clientForFixture(f, &MockQueryValidatorFactory{}, clientmodels.TrustLevel_High, nil)
	handler := newSpyHandler()

	client.NewSession(serveAuthRequest(t, f.authRequestJwt), handler)

	err := handler.awaitFailure(t)
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, err.ErrorType)
}

func TestNewSession_ExpiredDidWebCertificate_ReportsPartyValidationFailed(t *testing.T) {
	f := newDidAttestFixture(t, testdata.PkiOption_ExpiredEndEntity, true, nil)
	client := clientForFixture(f, &MockQueryValidatorFactory{}, clientmodels.TrustLevel_High, nil)
	handler := newSpyHandler()

	client.NewSession(serveAuthRequest(t, f.authRequestJwt), handler)

	err := handler.awaitFailure(t)
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, err.ErrorType,
		"a live party presenting an expired attesting certificate is refused")
}

func TestNewSession_RevokedDidWebCertificate_ReportsPartyValidationFailed(t *testing.T) {
	f := newDidAttestFixture(t, testdata.PkiOption_RevokedEndEntity, true, nil)
	client := clientForFixture(f, &MockQueryValidatorFactory{}, clientmodels.TrustLevel_High, nil)
	handler := newSpyHandler()

	client.NewSession(serveAuthRequest(t, f.authRequestJwt), handler)

	err := handler.awaitFailure(t)
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, err.ErrorType,
		"a revoked attesting certificate is an act of distrust and refuses")
}

func TestNewSession_AttestedDidWebVerifier_OverAsking_FailsAtAnyRung(t *testing.T) {
	// The certificate carries an attribute authorization; a request exceeding it
	// fails, the same hard gate the x5c-header path enforces.
	f := newDidAttestFixture(t, testdata.PkiOption_None, true, nil)
	client := clientForFixture(f, &MockQueryValidatorFactory{failsQueryValidation: true}, clientmodels.TrustLevel_High, nil)
	handler := newSpyHandler()

	client.NewSession(serveAuthRequest(t, f.authRequestJwt), handler)

	err := handler.awaitFailure(t)
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, err.ErrorType,
		"an attested DID verifier over-asking is refused")
}

func TestNewSession_AttestedDidWebVerifier_ListedOnYivisList_RanksHigh(t *testing.T) {
	// A DID-keyed entry keeps granting a party that has since attested its key, so
	// one medium by certificate reaches high through the list.
	f := newDidAttestFixture(t, testdata.PkiOption_None, true, nil)
	list := newYiviListFixture(t)
	list.grant(t, 1, f.did)
	client := clientForFixture(f, &MockQueryValidatorFactory{}, clientmodels.TrustLevel_Medium, list.checker(t))
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, f.authRequestJwt), handler).Dismiss()

	requestor := handler.awaitRequestor(t)
	require.Equal(t, clientmodels.TrustLevel_High, requestor.TrustLevel,
		"a DID-keyed listing lifts the attested-medium party to high")
}
