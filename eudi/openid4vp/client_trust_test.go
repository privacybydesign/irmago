package openid4vp

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// How the OpenID4VP client composes what the wallet knows about a verifier once
// the identity gate has passed: the trust ladder ranks it, the policy applies,
// its authorization is enforced with list-over-certificate precedence, and the
// party the app renders takes its name and logo from the strongest source.

// verifierWorld is one verifier PKI (root, one CA, one leaf with the Yivi scheme
// extension) and a verifier trust model that may or may not anchor it.
type verifierWorld struct {
	root       *x509.Certificate
	ca         *x509.Certificate
	leaf       *x509.Certificate
	trustModel *eudi.TrustModel
	requestJwt string
}

func newVerifierWorld(t *testing.T, anchored bool, schemeData string) *verifierWorld {
	t.Helper()
	crlDistPoint := "https://yivi.app/crl.crl"
	_, rootCert, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("VERIFIER ROOT"), 1, testdata.PkiOption_None, &crlDistPoint)
	opts := testdata.PkiOption_None
	if schemeData == "" {
		opts = testdata.PkiOption_MissingSchemeData
	}
	verifierKey, verifierCert, _ := testdata.CreateEndEntityCertificate(t, testdata.CreateDistinguishedName("Verifier Common Name"), "verifier.example.com", caCerts[0], caKeys[0], schemeData, opts)

	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	if anchored {
		roots.AddCert(rootCert)
		intermediates.AddCert(caCerts[0])
	}
	trustModel := eudi.NewTestTrustModel(t.TempDir(), roots, intermediates, nil)

	return &verifierWorld{
		root:       rootCert,
		ca:         caCerts[0],
		leaf:       verifierCert,
		trustModel: trustModel,
		requestJwt: testdata.CreateTestAuthorizationRequestJWT("verifier.example.com", verifierKey, verifierCert, withVctValues("test.test.email")),
	}
}

// withVctValues names the credential type the test request asks for, so the
// real scheme query validator has something to authorize.
func withVctValues(vct string) func(*jwt.Token) {
	return func(token *jwt.Token) {
		query := token.Claims.(jwt.MapClaims)["dcql_query"].(map[string]any)
		query["credentials"].([]map[string]any)[0]["meta"] = map[string]any{"vct_values": []string{vct}}
	}
}

// evaluator pins views over a fixed snapshot and the world's verifier trust model.
type evaluator struct {
	snapshot   walletconfig.Snapshot
	trustModel *eudi.TrustModel
	appBuild   int64
}

func (e evaluator) Snapshot() trust.View {
	return trust.NewView(e.snapshot, nil, e.trustModel, e.appBuild)
}

func (w *verifierWorld) client(t *testing.T, snapshot walletconfig.Snapshot) *Client {
	t.Helper()
	client, err := NewClient(nil, nil,
		NewRequestorCertificateStoreVerifierValidator(w.trustModel),
		clientmodels.NewCurrentLocale("en"),
		evaluator{snapshot: snapshot, trustModel: w.trustModel},
	)
	require.NoError(t, err)
	return client
}

func emptySnapshot() walletconfig.Snapshot {
	return walletconfig.Snapshot{Environment: walletconfig.Environment{Name: "test"}}
}

func snapshotListing(entity walletconfig.TrustedEntity) walletconfig.Snapshot {
	config := walletconfig.NewTestConfig("test", 1, time.Now())
	config.TrustedEntities = []walletconfig.TrustedEntity{entity}
	return walletconfig.Snapshot{Environment: walletconfig.Environment{Name: "test"}, Config: config, Freshness: walletconfig.Fresh}
}

// An unanchored verifier passes the gate and ranks low: it is shown by the name
// it gave itself, without a logo, and marked unverified.
func TestVerifySignedAuthorizationRequest_UnanchoredVerifierRanksLow(t *testing.T) {
	w := newVerifierWorld(t, false, testdata.VerifierCertSchemeData)
	client := w.client(t, emptySnapshot())

	request, requestor, err := client.verifySignedAuthorizationRequest(w.requestJwt)
	require.NoError(t, err)
	require.NotNil(t, request)
	require.Equal(t, clientmodels.TrustLevel_Low, requestor.TrustLevel)
	require.Equal(t, "Verifier Common Name", requestor.Name, "the certificate's legal name is the verifier's own word when nothing anchors it")
	require.Nil(t, requestor.Image, "an unanchored certificate's logo is not shown")
	require.Equal(t, w.leaf.SerialNumber.String(), requestor.Id)
}

// A verifier under a locally installed anchor is attested: the certificate's
// scheme extension names it and supplies the logo, and it ranks high.
func TestVerifySignedAuthorizationRequest_InstalledAnchorAttestsTheCertificate(t *testing.T) {
	w := newVerifierWorld(t, true, testdata.VerifierCertSchemeData)
	w.trustModel.MarkAnchorsInstalled(w.root)
	client := w.client(t, emptySnapshot())

	_, requestor, err := client.verifySignedAuthorizationRequest(w.requestJwt)
	require.NoError(t, err)
	require.Equal(t, clientmodels.TrustLevel_High, requestor.TrustLevel)
	require.Equal(t, "Yivi B.V.", requestor.Name)
	require.NotNil(t, requestor.Image)
}

// A verifier under a CA the wallet config lists takes the entity's level; the
// entity's name outranks what the certificate says.
func TestVerifySignedAuthorizationRequest_ListedCAConfersItsLevelAndName(t *testing.T) {
	w := newVerifierWorld(t, true, testdata.VerifierCertSchemeData)
	client := w.client(t, snapshotListing(walletconfig.TrustedEntity{
		ID:         "verifier-ca",
		Name:       clientmodels.TranslatedString{"en": "Curated Verifiers"},
		Roles:      []walletconfig.Role{walletconfig.RoleVerifier},
		TrustLevel: clientmodels.TrustLevel_Medium,
		Handles:    []walletconfig.Handle{{Type: walletconfig.HandleTypeX509CA, RootCertificate: &walletconfig.Certificate{Certificate: w.root}}},
	}))

	_, requestor, err := client.verifySignedAuthorizationRequest(w.requestJwt)
	require.NoError(t, err)
	require.Equal(t, clientmodels.TrustLevel_Medium, requestor.TrustLevel)
	require.Equal(t, "Curated Verifiers", requestor.Name)
	require.NotNil(t, requestor.Image, "the attested logo stands in while the entity lists none")
}

// A verifier listed by its exact certificate ranks as listed even when nothing
// anchors the certificate.
func TestVerifySignedAuthorizationRequest_ListedCertificateIsVouchedFor(t *testing.T) {
	w := newVerifierWorld(t, false, testdata.VerifierCertSchemeData)
	client := w.client(t, snapshotListing(walletconfig.TrustedEntity{
		ID:         "listed-verifier",
		Name:       clientmodels.TranslatedString{"en": "Listed Verifier"},
		Roles:      []walletconfig.Role{walletconfig.RoleVerifier},
		TrustLevel: clientmodels.TrustLevel_High,
		Handles:    []walletconfig.Handle{{Type: walletconfig.HandleTypeX509Cert, Certificate: &walletconfig.Certificate{Certificate: w.leaf}}},
	}))

	_, requestor, err := client.verifySignedAuthorizationRequest(w.requestJwt)
	require.NoError(t, err)
	require.Equal(t, clientmodels.TrustLevel_High, requestor.TrustLevel)
	require.Equal(t, "Listed Verifier", requestor.Name)
	require.Nil(t, requestor.Image, "unanchored, so the certificate's logo is still the verifier's own word")
}

func TestVerifySignedAuthorizationRequest_PolicyRefusesBelowMinimum(t *testing.T) {
	w := newVerifierWorld(t, false, testdata.VerifierCertSchemeData)
	snapshot := snapshotListing(walletconfig.TrustedEntity{
		ID: "unrelated", Name: clientmodels.TranslatedString{"en": "Unrelated"},
		Roles: []walletconfig.Role{walletconfig.RoleVerifier}, TrustLevel: clientmodels.TrustLevel_High,
		Handles: []walletconfig.Handle{{Type: walletconfig.HandleTypeDID, DID: "did:web:unrelated.example"}},
	})
	snapshot.Config.Policy.MinimumTrustLevel.Disclosure = clientmodels.TrustLevel_Medium
	client := w.client(t, snapshot)

	_, _, err := client.verifySignedAuthorizationRequest(w.requestJwt)
	require.True(t, errors.Is(err, trust.ErrBelowMinimumTrustLevel))
	require.Equal(t, clientmodels.ErrorType_TrustLevelBelowMinimum, eudi.SessionErrorType(err))
	require.False(t, eudi.IsPartyValidationFailure(err), "a policy refusal is not an identity gate failure")
}

func TestVerifySignedAuthorizationRequest_GateFailureIsAPartyValidationFailure(t *testing.T) {
	w := newVerifierWorld(t, true, testdata.VerifierCertSchemeData)
	client := w.client(t, emptySnapshot())

	_, _, err := client.verifySignedAuthorizationRequest("not a jwt")
	require.True(t, eudi.IsPartyValidationFailure(err))
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, eudi.SessionErrorType(err))
}

// The certificate's own authorization is enforced only when an anchor stands
// behind it: the test request asks for `email`, which the scheme data allows.
func TestVerifySignedAuthorizationRequest_AnchoredCertificateAuthorizationIsEnforced(t *testing.T) {
	narrow := `{"registration":"https://portal.yivi.app/organizations/yivi","organization":{"legalName":{"en":"Narrow"}},"rp":{"authorized":[{"credential":"test.test.email","attributes":["domain"]}]}}`

	anchored := newVerifierWorld(t, true, narrow)
	anchored.trustModel.MarkAnchorsInstalled(anchored.root)
	_, _, err := anchored.client(t, emptySnapshot()).verifySignedAuthorizationRequest(anchored.requestJwt)
	require.True(t, eudi.IsPartyValidationFailure(err))
	require.ErrorContains(t, err, "failed to verify queried credentials")

	unanchored := newVerifierWorld(t, false, narrow)
	_, requestor, err := unanchored.client(t, emptySnapshot()).verifySignedAuthorizationRequest(unanchored.requestJwt)
	require.NoError(t, err, "an unanchored certificate's authorization is its own word and constrains nothing")
	require.Equal(t, clientmodels.TrustLevel_Low, requestor.TrustLevel)
}

// A constraint listed in the wallet config replaces the certificate's
// authorization, in both directions: it can narrow an anchored verifier the
// certificate would allow, and widen one the certificate would refuse.
func TestVerifySignedAuthorizationRequest_ListedConstraintReplacesTheCertificates(t *testing.T) {
	listing := func(w *verifierWorld, attributes ...string) walletconfig.Snapshot {
		return snapshotListing(walletconfig.TrustedEntity{
			ID: "listed", Name: clientmodels.TranslatedString{"en": "Listed"},
			Roles: []walletconfig.Role{walletconfig.RoleVerifier}, TrustLevel: clientmodels.TrustLevel_High,
			Handles: []walletconfig.Handle{{Type: walletconfig.HandleTypeX509Cert, Certificate: &walletconfig.Certificate{Certificate: w.leaf}}},
			Constraints: &walletconfig.Constraints{Disclosure: &walletconfig.DisclosureConstraint{
				AllowedQueries: []walletconfig.AllowedQuery{{Credential: "test.test.email", Attributes: attributes}},
			}},
		})
	}

	// Narrowing: the certificate allows email, the list allows only domain.
	w := newVerifierWorld(t, true, testdata.VerifierCertSchemeData)
	w.trustModel.MarkAnchorsInstalled(w.root)
	_, _, err := w.client(t, listing(w, "domain")).verifySignedAuthorizationRequest(w.requestJwt)
	require.ErrorContains(t, err, "failed to verify queried credentials")

	// Widening: the certificate allows only domain, the list allows any attribute.
	narrow := `{"registration":"https://portal.yivi.app/organizations/yivi","organization":{"legalName":{"en":"Narrow"}},"rp":{"authorized":[{"credential":"test.test.email","attributes":["domain"]}]}}`
	w = newVerifierWorld(t, true, narrow)
	w.trustModel.MarkAnchorsInstalled(w.root)
	_, requestor, err := w.client(t, listing(w)).verifySignedAuthorizationRequest(w.requestJwt)
	require.NoError(t, err)
	require.Equal(t, "Listed", requestor.Name)
}

func TestRelyingPartyFromConstraint(t *testing.T) {
	relyingParty := relyingPartyFromConstraint(&walletconfig.DisclosureConstraint{AllowedQueries: []walletconfig.AllowedQuery{
		{Credential: "a", Attributes: []string{"x", "y"}},
		{Credential: "b"},
	}})
	require.Equal(t, []scheme.AuthorizedAttributeSet{
		{Credential: "a", Attributes: []string{"x", "y"}},
		{Credential: "b", Attributes: []string{"*"}},
	}, relyingParty.AuthorizedQueryableAttributeSets)
}

// The app-build gate refuses every OpenID4VP session before any network call.
func TestNewSession_RefusesWhenTheAppMustUpdate(t *testing.T) {
	w := newVerifierWorld(t, true, testdata.VerifierCertSchemeData)
	snapshot := snapshotListing(walletconfig.TrustedEntity{
		ID: "x", Name: clientmodels.TranslatedString{"en": "X"},
		Roles: []walletconfig.Role{walletconfig.RoleVerifier}, TrustLevel: clientmodels.TrustLevel_High,
		Handles: []walletconfig.Handle{{Type: walletconfig.HandleTypeDID, DID: "did:web:x.example"}},
	})
	snapshot.Config.MinimumAppBuild = 200
	client, err := NewClient(nil, nil, NewRequestorCertificateStoreVerifierValidator(w.trustModel), clientmodels.NewCurrentLocale("en"),
		evaluator{snapshot: snapshot, trustModel: w.trustModel, appBuild: 100})
	require.NoError(t, err)

	handler := newSpyHandler()
	client.NewSession("openid4vp://?request_uri=https://verifier.example/request", handler)
	failure := awaitOn(t, handler.failed, "the session to fail")
	require.Equal(t, clientmodels.ErrorType_AppUpdateRequired, failure.ErrorType)
}
