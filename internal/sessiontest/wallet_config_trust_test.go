package sessiontest

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// The trust system as real wallet sessions: the wallet config decides how far a
// party is trusted, the policy decides what that is worth, and the app sees the
// outcome on the session state and the credential list.
//
// Everything here runs in-process. Verifiers authenticate through signed
// OpenID4VP requests delivered over the Digital Credentials API, so a test signs
// a request with whatever certificate it wants the wallet to meet and needs no
// verifier server. Credentials are seeded straight into the EUDI store, signed by
// an issuer the test controls. Configs are signed by a test config CA and served
// from an in-process server the wallet's staging environment points at; the
// tests run in developer mode, which is the staging environment, so "the active
// environment" is the publisher's.
//
// What needs a live issuer — the OpenID4VCI flow ranking and refusing issuers —
// is in wallet_config_openid4vci_test.go, against the Docker services. The one
// scenario needing the IRMA server (a verifier certificate with scheme data,
// against an IRMA-issued credential) is defined here but runs with the DC API
// group in openid4vp_dc_api_disclosure_test.go.

// seededVct is the type of every seeded credential: a URN, so the disclosure
// handler does not try to fetch type metadata for it over the network when the
// wallet holds no usable instance.
const seededVct = "urn:yivi:test:email"

const seededConfigurationID = "seeded-email"

func TestWalletConfigTrust(t *testing.T) {
	t.Run("a verifier under an installed CA ranks high and is shown from its certificate", testVerifierUnderInstalledCARanksHigh)
	t.Run("a verifier under an unknown CA ranks low and still gets its disclosure", testUnknownCAVerifierRanksLowAndProceeds)
	t.Run("a verifier listed by certificate takes the listed level and name", testListedVerifierCertificateRanks)
	t.Run("a verifier under a listed CA takes the CA's level", testListedVerifierCARanks)
	t.Run("the policy refuses a verifier below the minimum", testPolicyRefusesVerifierBelowMinimum)
	t.Run("a listed constraint narrows what a verifier may ask", testListedConstraintNarrowsTheRequest)
	t.Run("a broken request fails as a party validation failure", testBrokenRequestFailsAsPartyValidation)
	t.Run("a config refresh lifts a verifier and a rollback is refused", testConfigRefreshLiftsAVerifierAndRefusesRollback)
	t.Run("developer mode switches the environment and its anchors", testDeveloperModeSwitchesEnvironment)
	t.Run("an expired config drops listings and keeps CA anchors", testExpiredConfigDropsListingsKeepsAnchors)
	t.Run("a restarted wallet ranks from the persisted config", testRestartedWalletRanksFromPersistedConfig)
	t.Run("the minimum app build refuses OpenID4VC sessions", testMinimumAppBuildRefusesSessions)
	t.Run("a stored credential's issuer follows the config", testStoredCredentialIssuerFollowsTheConfig)
	t.Run("a stored credential below the issuance policy is badged and not disclosed", testStoredCredentialBelowPolicyIsExcluded)
	t.Run("a stored credential from a DID issuer is ranked by its DID", testStoredCredentialFromDIDIssuerRanksByDID)
}

// ========================================================================
// Config publishing
// ========================================================================

// configPublisher publishes signed wallet configs for one environment from an
// in-process server, the way the publishing job serves the real ones.
type configPublisher struct {
	t       *testing.T
	name    string
	signer  *walletconfig.TestSigner
	server  *walletconfig.TestServer
	env     walletconfig.Environment
	version uint64
}

func newConfigPublisher(t *testing.T, environment string) *configPublisher {
	t.Helper()
	signer := walletconfig.NewTestSigner(t)
	server := walletconfig.NewTestServer(t)
	// Nothing published yet: a wallet fetching now holds nothing.
	server.SetStatus(http.StatusNotFound)
	return &configPublisher{
		t:      t,
		name:   environment,
		signer: signer,
		server: server,
		env:    signer.Environment(environment, server.URL),
	}
}

// publish signs and serves the next issue of the environment's config: a fresh
// one with no entities and the default policy, edited by mutate.
func (p *configPublisher) publish(mutate func(*walletconfig.Config)) *walletconfig.Config {
	return p.publishIssuedAt(time.Now(), mutate)
}

// publishIssuedAt is publish with the issue time chosen, for a config that is
// already stale or expired when the wallet fetches it.
func (p *configPublisher) publishIssuedAt(issuedAt time.Time, mutate func(*walletconfig.Config)) *walletconfig.Config {
	p.t.Helper()
	p.version++
	config := walletconfig.NewTestConfig(p.name, p.version, issuedAt)
	config.TrustedEntities = nil
	if mutate != nil {
		mutate(config)
	}
	p.serve(config)
	return config
}

// serve signs and serves config as it is, version and all.
func (p *configPublisher) serve(config *walletconfig.Config) {
	p.t.Helper()
	p.server.SetBody(p.signer.Sign(p.t, config))
}

// unavailable makes the publisher answer every fetch with an error.
func (p *configPublisher) unavailable() {
	p.server.SetStatus(http.StatusServiceUnavailable)
}

func refreshConfig(t *testing.T, c *client.Client) {
	t.Helper()
	require.NoError(t, c.RefreshWalletConfig(context.Background()))
}

func caEntity(id, name string, role walletconfig.Role, level clientmodels.TrustLevel, root *x509.Certificate, intermediates ...*x509.Certificate) walletconfig.TrustedEntity {
	handle := walletconfig.Handle{Type: walletconfig.HandleTypeX509CA, RootCertificate: &walletconfig.Certificate{Certificate: root}}
	for _, intermediate := range intermediates {
		handle.Intermediates = append(handle.Intermediates, walletconfig.Certificate{Certificate: intermediate})
	}
	return walletconfig.TrustedEntity{
		ID: id, Name: clientmodels.TranslatedString{"en": name}, Roles: []walletconfig.Role{role},
		TrustLevel: level, Handles: []walletconfig.Handle{handle},
	}
}

func certEntity(id, name string, role walletconfig.Role, level clientmodels.TrustLevel, certificate *x509.Certificate) walletconfig.TrustedEntity {
	return walletconfig.TrustedEntity{
		ID: id, Name: clientmodels.TranslatedString{"en": name}, Roles: []walletconfig.Role{role},
		TrustLevel: level,
		Handles:    []walletconfig.Handle{{Type: walletconfig.HandleTypeX509Cert, Certificate: &walletconfig.Certificate{Certificate: certificate}}},
	}
}

func didEntity(id, name string, role walletconfig.Role, level clientmodels.TrustLevel, did string) walletconfig.TrustedEntity {
	return walletconfig.TrustedEntity{
		ID: id, Name: clientmodels.TranslatedString{"en": name}, Roles: []walletconfig.Role{role},
		TrustLevel: level,
		Handles:    []walletconfig.Handle{{Type: walletconfig.HandleTypeDID, DID: did}},
	}
}

// ========================================================================
// Wallets
// ========================================================================

// trustTestClient builds a wallet whose staging environment is the publisher's
// — developer mode is on, so staging is the active environment — and whose
// production environment is production, or an unpublished, empty one when nil.
// The refresh throttle is lifted, so every RefreshWalletConfig fetches.
func trustTestClient(t *testing.T, staging *configPublisher, production *walletconfig.Environment, opts testClientOptions) (*client.Client, *irmaclient.MockClientHandler, *MockSessionHandler) {
	t.Helper()
	if production == nil {
		production = &walletconfig.Environment{Name: walletconfig.EnvironmentProduction}
	}
	opts.Environments = []walletconfig.Environment{*production, staging.env}
	opts.WalletConfigRefreshInterval = time.Nanosecond
	return newTestClient(t, opts)
}

// ========================================================================
// Verifiers
// ========================================================================

// verifierIdentity is a verifier's key and certificate, and the host its
// client_id names.
type verifierIdentity struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	host string
}

func (v verifierIdentity) clientID() string {
	return string(openid4vp.ClientIdentifierPrefix_X509SanDns) + v.host
}

// installedCAVerifier issues a verifier certificate under the CA every test
// wallet has installed (testdata/eudi/verifier/ca.crt), without scheme data: an
// anchored verifier whose certificate constrains nothing.
func installedCAVerifier(t *testing.T, host string) verifierIdentity {
	t.Helper()
	caChain, err := x509.ParseCertificates(pemToDER(t, testdata.VerifierCACertBytes))
	require.NoError(t, err)
	caKey := readECPrivateKey(t, filepath.Join(test.FindTestdataFolder(t), "eudi", "verifier", "ca_ec_priv.pem"))
	key, cert := walletconfig.NewTestEndEntity(t, host, caChain[0], caKey, func(template *x509.Certificate) {
		template.DNSNames = []string{host}
	})
	return verifierIdentity{key: key, cert: cert, host: host}
}

// schemeDataVerifier is the test verifier certificate itself: under the installed
// CA, carrying the Yivi scheme extension that names it "Yivi B.V." and authorizes
// the email credential.
func schemeDataVerifier(t *testing.T) verifierIdentity {
	t.Helper()
	dir := filepath.Join(test.FindTestdataFolder(t), "eudi", "verifier")
	raw, err := os.ReadFile(filepath.Join(dir, "verifier.crt"))
	require.NoError(t, err)
	certs, err := x509.ParseCertificates(pemToDER(t, raw))
	require.NoError(t, err)
	return verifierIdentity{key: readECPrivateKey(t, filepath.Join(dir, "verifier_ec_priv.pem")), cert: certs[0], host: "localhost"}
}

// unknownCAVerifier issues a verifier certificate under a CA nothing anchors,
// and returns the CA so a test can list it.
func unknownCAVerifier(t *testing.T, host string) (verifierIdentity, *x509.Certificate) {
	t.Helper()
	caKey, ca := walletconfig.NewTestCA(t, "Unknown Verifier CA", nil, nil)
	key, cert := walletconfig.NewTestEndEntity(t, host, ca, caKey, func(template *x509.Certificate) {
		template.DNSNames = []string{host}
	})
	return verifierIdentity{key: key, cert: cert, host: host}, ca
}

func pemToDER(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	var der []byte
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			der = append(der, block.Bytes...)
		}
	}
	require.NotEmpty(t, der)
	return der
}

func readECPrivateKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.NotNil(t, block, "%s is not PEM", path)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err)
	return key
}

// dcApiRequestSpec is what a signed DC API request says and who signs it.
type dcApiRequestSpec struct {
	verifier       verifierIdentity
	query          map[string]any
	clientMetadata map[string]any
	// tamper breaks the signature after signing.
	tamper bool
}

// signedLocalDcApiRequest is a signed OpenID4VP request the platform would hand
// the wallet over the DC API, signed by the spec's verifier for dcApiOrigin.
func signedLocalDcApiRequest(t *testing.T, spec dcApiRequestSpec) *openid4vp.DcApiRequest {
	t.Helper()
	claims := jwt.MapClaims{
		"client_id":        spec.verifier.clientID(),
		"expected_origins": []string{dcApiOrigin},
		"response_type":    "vp_token",
		"response_mode":    string(openid4vp.ResponseMode_DcApi),
		"nonce":            dcApiNonce,
		"dcql_query":       map[string]any{"credentials": []any{spec.query}},
	}
	if spec.clientMetadata != nil {
		claims["client_metadata"] = spec.clientMetadata
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = openid4vp.AuthRequestJwtTyp
	token.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(spec.verifier.cert.Raw)}
	signed, err := token.SignedString(spec.verifier.key)
	require.NoError(t, err)
	if spec.tamper {
		// Flip the first character of the signature. (The last one would only
		// touch base64 padding bits, which decode to the same bytes.)
		parts := strings.SplitN(signed, ".", 3)
		replacement := "A"
		if parts[2][0] == 'A' {
			replacement = "B"
		}
		signed = parts[0] + "." + parts[1] + "." + replacement + parts[2][1:]
	}
	return &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolSigned,
		Origin:   dcApiOrigin,
		Data:     signedDcApiData(t, signed),
	}
}

// emailQuery asks for the IRMA-issued email credential, with the holder binding
// the IRMA key binder provides.
func emailQuery() map[string]any {
	return map[string]any{
		"id":     dcApiQueryId,
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []string{"test.test.email"}},
		"claims": []any{map[string]any{"path": []string{"email"}}},
	}
}

// seededQuery asks for the seeded credential. Seeded credentials carry no holder
// binding key, so the query waives cryptographic holder binding.
func seededQuery() map[string]any {
	return map[string]any{
		"id":                                   dcApiQueryId,
		"format":                               "dc+sd-jwt",
		"meta":                                 map[string]any{"vct_values": []string{seededVct}},
		"claims":                               []any{map[string]any{"path": []string{"email"}}},
		"require_cryptographic_holder_binding": false,
	}
}

// discloseSeeded runs a signed DC API request for the seeded credential through
// to the permission prompt and returns that state, failing the test on an error
// state so the reason is printed.
func requestDisclosure(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionID int, spec dcApiRequestSpec) clientmodels.SessionState {
	t.Helper()
	session := startDcApiSession(t, c, sessionID, sessionHandler, signedLocalDcApiRequest(t, spec))
	requireSessionState(t, session, sessionID, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	return session
}

// requestDisclosureFails runs a signed DC API request that the wallet must refuse
// and returns the error it reports.
func requestDisclosureFails(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionID int, spec dcApiRequestSpec) *clientmodels.SessionError {
	t.Helper()
	session := startDcApiSession(t, c, sessionID, sessionHandler, signedLocalDcApiRequest(t, spec))
	require.Equal(t, clientmodels.Status_Error, session.Status, "the session must fail, but reached %s", session.Status)
	require.NotNil(t, session.Error)
	return session.Error
}

// completeDisclosure grants the single owned option and returns the final state.
func completeDisclosure(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, session clientmodels.SessionState) clientmodels.SessionState {
	t.Helper()
	grantDcApiDisclosure(t, c, session.Id, session)
	final := awaitSessionState(t, sessionHandler)
	requireSessionState(t, final, session.Id, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	require.NotEmpty(t, final.DcApiResponse)
	return final
}

// ========================================================================
// Issuers and seeded credentials
// ========================================================================

// testIssuer is an issuer the test controls: a key, and either a certificate
// under its own CA or a did:jwk.
type testIssuer struct {
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	url   string
	did   string
}

// newX5cIssuer is an issuer signing with a certificate under a CA of its own,
// identified by the URL its certificate names.
func newX5cIssuer(t *testing.T, host string) *testIssuer {
	t.Helper()
	caKey, ca := walletconfig.NewTestCA(t, "Test Issuer CA "+host, nil, nil)
	issuerURL := "https://" + host
	key, cert := walletconfig.NewTestEndEntity(t, host, ca, caKey, func(template *x509.Certificate) {
		template.DNSNames = []string{host}
		template.URIs = []*url.URL{{Scheme: "https", Host: host}}
	})
	return &testIssuer{key: key, cert: cert, ca: ca, caKey: caKey, url: issuerURL}
}

// newDidIssuer is an issuer signing under a did:jwk, which resolves offline.
func newDidIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, _ := walletconfig.NewTestCA(t, "unused", nil, nil)
	publicKey, err := jwk.Import[jwk.Key](key.Public())
	require.NoError(t, err)
	document, err := (&didjwk.DocumentBuilder{}).FromJwk(publicKey)
	require.NoError(t, err)
	return &testIssuer{key: key, did: document.ID, url: document.ID}
}

// mint issues an SD-JWT VC of the seeded type with the given selectively
// disclosable claims.
func (i *testIssuer) mint(t *testing.T, claims map[string]string) string {
	t.Helper()
	now := time.Now()
	elements := []*sdjwt.ClaimElement{
		sdjwt.Claim(sdjwtvc.VerifiableCredentialTypeKey, seededVct),
		sdjwt.Claim("iss", i.url),
		sdjwt.Claim("iat", now.Unix()),
		sdjwt.Claim("exp", now.Add(24*time.Hour).Unix()),
	}
	keys := make([]string, 0, len(claims))
	for key := range claims {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		elements = append(elements, sdjwt.SdClaim(key, claims[key]))
	}

	if i.did != "" {
		// The SD-JWT VC builder insists on an https issuer, so a DID issuer goes
		// through the plain SD-JWT builder with the kid header the DID key
		// provider resolves.
		raw, err := sdjwt.NewBuilder().WithPayload(elements...).WithTyp(sdjwtvc.SdJwtVcTyp).
			Build(kidJwtCreator{inner: sdjwt.NewJwtCreator(i.key), kid: i.did + "#0"})
		require.NoError(t, err)
		return string(raw)
	}
	raw, err := sdjwtvc.NewSdJwtVcBuilder().WithPayload(elements...).
		WithIssuerCertificateChain([]string{base64.StdEncoding.EncodeToString(i.cert.Raw)}).
		Build(sdjwt.NewJwtCreator(i.key))
	require.NoError(t, err)
	return string(raw)
}

// kidJwtCreator signs like the default creator but names the key by kid and
// drops the empty x5c the builder always writes.
type kidJwtCreator struct {
	inner sdjwt.JwtCreator
	kid   string
}

func (c kidJwtCreator) CreateSignedJwt(headers map[string]any, payload string) (string, error) {
	delete(headers, "x5c")
	headers["kid"] = c.kid
	return c.inner.CreateSignedJwt(headers, payload)
}

// seed stores a credential of the seeded type from this issuer in the wallet.
func (i *testIssuer) seed(t *testing.T, c *client.Client, claims map[string]string) {
	t.Helper()
	en := "en"
	issuerMetadata := metadata.CredentialIssuerMetadata{
		CredentialIssuer: i.url,
		Display:          metadata.CredentialIssuerDisplays{{Display: metadata.Display{Name: "Seeded Issuer", Locale: &en}}},
		CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{
			seededConfigurationID: {
				Format:                   metadata.CredentialFormatIdentifier_SdJwtVc,
				VerifiableCredentialType: seededVct,
				CredentialMetadata: &metadata.CredentialMetadata{
					Display: metadata.CredentialDisplays{{Display: metadata.Display{Name: "Seeded Email", Locale: &en}}},
					Claims:  []metadata.ClaimsDescription{{Path: metadata.ClaimsPathPointer{"email"}, Display: []metadata.Display{{Name: "Email", Locale: &en}}}},
				},
			},
		},
	}
	require.NoError(t, c.SeedSdJwtVcForTesting(i.mint(t, claims), issuerMetadata, seededConfigurationID))
}

// seededCredential is the stored credential of the seeded type as the app lists it.
func seededCredential(t *testing.T, c *client.Client) *clientmodels.Credential {
	t.Helper()
	credentials, _, err := c.GetCredentials()
	require.NoError(t, err)
	for _, credential := range credentials {
		if credential.CredentialId == seededVct {
			return credential
		}
	}
	t.Fatalf("no stored credential of type %s", seededVct)
	return nil
}

// ========================================================================
// Verifier tests
// ========================================================================

func testVerifierUnderInstalledCARanksHigh(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	newX5cIssuer(t, "issuer.example").seed(t, c, map[string]string{"email": "seeded@example.com"})

	verifier := installedCAVerifier(t, "anchored.verifier.example")
	session := requestDisclosure(t, c, sessionHandler, 1, dcApiRequestSpec{verifier: verifier, query: seededQuery()})

	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel,
		"a CA installed in the wallet stands in for Yivi's own")
	require.Equal(t, "anchored.verifier.example", session.Requestor.Name,
		"an anchored certificate without scheme data names the verifier by its common name")
	require.Equal(t, verifier.cert.SerialNumber.String(), session.Requestor.Id)

	final := completeDisclosure(t, c, sessionHandler, session)
	vpToken := requireVpTokenFromResponse(t, final.DcApiResponse)
	presentation := requireSinglePresentation(t, vpToken, dcApiQueryId)
	require.Equal(t, "seeded@example.com", extractDisclosedClaims(t, presentation)["email"])
}

// The test verifier certificate carries the Yivi scheme extension: the wallet
// shows the legal name it attests, and enforces the attribute authorization it
// carries. Run against the IRMA-issued email credential, which is what that
// authorization names, so this one needs the IRMA server and is registered with
// the other DC API scenarios in testSessionHandlerForOpenID4VPOverDcApi.
func testDcApiSchemeDataNamesAndConstrainsVerifier(t *testing.T, irmaServer *IrmaServer, c *client.Client, sessionHandler *MockSessionHandler) {
	issueEmailCredential(t, irmaServer, c, sessionHandler, 1)
	verifier := schemeDataVerifier(t)

	session := requestDisclosure(t, c, sessionHandler, 2, dcApiRequestSpec{
		verifier: verifier,
		query:    emailQuery(),
		// The self-asserted name loses to the attested one.
		clientMetadata: map[string]any{"client_name": "Someone Else"},
	})
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel)
	require.Equal(t, "Yivi B.V.", session.Requestor.Name)
	require.NotNil(t, session.Requestor.Image, "an attested logo is shown")
	completeDisclosure(t, c, sessionHandler, session)

	// A request beyond the certificate's authorization fails at any rung.
	overAsk := emailQuery()
	overAsk["claims"] = []any{map[string]any{"path": []string{"email"}}, map[string]any{"path": []string{"secret"}}}
	failure := requestDisclosureFails(t, c, sessionHandler, 3, dcApiRequestSpec{verifier: verifier, query: overAsk})
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, failure.ErrorType)
	require.Contains(t, failure.WrappedError, "failed to verify queried credentials")
}

func testUnknownCAVerifierRanksLowAndProceeds(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	newX5cIssuer(t, "issuer.example").seed(t, c, map[string]string{"email": "seeded@example.com"})

	verifier, _ := unknownCAVerifier(t, "stranger.example")
	session := requestDisclosure(t, c, sessionHandler, 1, dcApiRequestSpec{
		verifier:       verifier,
		query:          seededQuery(),
		clientMetadata: map[string]any{"client_name": "Stranger BV"},
	})
	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel,
		"a certificate no anchor stands behind is absent evidence, not a failure")
	require.Equal(t, "Stranger BV", session.Requestor.Name, "with nothing attested, the verifier is shown under the name it gives itself")
	require.Nil(t, session.Requestor.Image, "and never under a logo it chose itself")
	require.Equal(t, verifier.cert.SerialNumber.String(), session.Requestor.Id)

	completeDisclosure(t, c, sessionHandler, session)

	// Without client metadata the certificate's common name is the fallback.
	session = requestDisclosure(t, c, sessionHandler, 2, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, "stranger.example", session.Requestor.Name)
}

func testListedVerifierCertificateRanks(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	newX5cIssuer(t, "issuer.example").seed(t, c, map[string]string{"email": "seeded@example.com"})
	verifier, _ := unknownCAVerifier(t, "listed.example")

	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			certEntity("listed-verifier", "Curated Verifier BV", walletconfig.RoleVerifier, clientmodels.TrustLevel_High, verifier.cert),
		}
	})
	refreshConfig(t, c)

	session := requestDisclosure(t, c, sessionHandler, 1, dcApiRequestSpec{
		verifier:       verifier,
		query:          seededQuery(),
		clientMetadata: map[string]any{"client_name": "Stranger BV"},
	})
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel, "being listed by Yivi is being onboarded")
	require.Equal(t, "Curated Verifier BV", session.Requestor.Name, "the curated name outranks the verifier's own")
	completeDisclosure(t, c, sessionHandler, session)
}

func testListedVerifierCARanks(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	newX5cIssuer(t, "issuer.example").seed(t, c, map[string]string{"email": "seeded@example.com"})
	verifier, ca := unknownCAVerifier(t, "under-ca.example")

	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			caEntity("third-party-ca", "Third Party CA", walletconfig.RoleVerifier, clientmodels.TrustLevel_Medium, ca),
		}
	})
	refreshConfig(t, c)

	session := requestDisclosure(t, c, sessionHandler, 1, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_Medium, session.Requestor.TrustLevel, "a chain to a listed CA confers the CA's level")
	require.Equal(t, "Third Party CA", session.Requestor.Name)
	completeDisclosure(t, c, sessionHandler, session)

	// The CA is listed for verifiers only: as an issuer it vouches for nobody.
	// (Covered on the issuer side by the stored-credential tests.)
}

func testPolicyRefusesVerifierBelowMinimum(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	newX5cIssuer(t, "issuer.example").seed(t, c, map[string]string{"email": "seeded@example.com"})
	stranger, _ := unknownCAVerifier(t, "stranger.example")
	listed, _ := unknownCAVerifier(t, "listed.example")

	staging.publish(func(config *walletconfig.Config) {
		config.Policy.MinimumTrustLevel.Disclosure = clientmodels.TrustLevel_Medium
		config.TrustedEntities = []walletconfig.TrustedEntity{
			certEntity("listed-verifier", "Listed", walletconfig.RoleVerifier, clientmodels.TrustLevel_Medium, listed.cert),
		}
	})
	refreshConfig(t, c)

	failure := requestDisclosureFails(t, c, sessionHandler, 1, dcApiRequestSpec{verifier: stranger, query: seededQuery()})
	require.Equal(t, clientmodels.ErrorType_TrustLevelBelowMinimum, failure.ErrorType)
	require.Contains(t, failure.WrappedError, "disclosure requires at least medium")

	session := requestDisclosure(t, c, sessionHandler, 2, dcApiRequestSpec{verifier: listed, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_Medium, session.Requestor.TrustLevel)
	completeDisclosure(t, c, sessionHandler, session)

	// The policy is a config publish, not an app release: the same stranger is
	// admitted again once the minimum drops.
	staging.publish(nil)
	refreshConfig(t, c)
	session = requestDisclosure(t, c, sessionHandler, 3, dcApiRequestSpec{verifier: stranger, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel)
}

func testListedConstraintNarrowsTheRequest(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	newX5cIssuer(t, "issuer.example").seed(t, c, map[string]string{"email": "seeded@example.com"})
	verifier, _ := unknownCAVerifier(t, "constrained.example")

	listing := certEntity("constrained-verifier", "Constrained", walletconfig.RoleVerifier, clientmodels.TrustLevel_High, verifier.cert)
	listing.Constraints = &walletconfig.Constraints{Disclosure: &walletconfig.DisclosureConstraint{
		AllowedQueries: []walletconfig.AllowedQuery{{Credential: "urn:yivi:test:something-else"}},
	}}
	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{listing}
	})
	refreshConfig(t, c)

	failure := requestDisclosureFails(t, c, sessionHandler, 1, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, failure.ErrorType, "a request beyond the listed constraint fails at any rung")
	require.Contains(t, failure.WrappedError, "failed to verify queried credentials")

	// Widening the constraint to what is asked lets the same request through.
	listing.Constraints.Disclosure.AllowedQueries = []walletconfig.AllowedQuery{{Credential: seededVct, Attributes: []string{"email"}}}
	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{listing}
	})
	refreshConfig(t, c)
	session := requestDisclosure(t, c, sessionHandler, 2, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel)
	completeDisclosure(t, c, sessionHandler, session)
}

func testBrokenRequestFailsAsPartyValidation(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()

	verifier := installedCAVerifier(t, "anchored.verifier.example")
	failure := requestDisclosureFails(t, c, sessionHandler, 1, dcApiRequestSpec{verifier: verifier, query: seededQuery(), tamper: true})
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, failure.ErrorType,
		"a request whose signature does not hold is a party the wallet cannot identify")
}

// ========================================================================
// Lifecycle tests
// ========================================================================

func testConfigRefreshLiftsAVerifierAndRefusesRollback(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	newX5cIssuer(t, "issuer.example").seed(t, c, map[string]string{"email": "seeded@example.com"})
	verifier, _ := unknownCAVerifier(t, "lifted.example")

	session := requestDisclosure(t, c, sessionHandler, 1, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel, "before any config lists it")

	// Version 1 lists nobody, version 2 lists the verifier.
	staging.publish(nil)
	refreshConfig(t, c)
	listing := staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			certEntity("lifted", "Lifted BV", walletconfig.RoleVerifier, clientmodels.TrustLevel_High, verifier.cert),
		}
	})
	refreshConfig(t, c)
	session = requestDisclosure(t, c, sessionHandler, 2, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel, "the refresh lifted it")

	// A replay of version 1 must not un-list anyone.
	rollback := walletconfig.NewTestConfig(walletconfig.EnvironmentStaging, 1, time.Now())
	rollback.TrustedEntities = nil
	staging.serve(rollback)
	err := c.RefreshWalletConfig(context.Background())
	require.ErrorContains(t, err, "rolls back")
	session = requestDisclosure(t, c, sessionHandler, 3, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel, "the held config stays in force")

	// A re-signing of the held version is adopted; an unreachable publisher
	// changes nothing.
	staging.serve(listing)
	refreshConfig(t, c)
	staging.unavailable()
	require.Error(t, c.RefreshWalletConfig(context.Background()))
	session = requestDisclosure(t, c, sessionHandler, 4, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel)
}

// Developer mode is the environment switch: what staging's config lists is
// trusted in staging and nowhere else, and switching back restores it.
func testDeveloperModeSwitchesEnvironment(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	production := newConfigPublisher(t, walletconfig.EnvironmentProduction)
	c, _, sessionHandler := trustTestClient(t, staging, &production.env, testClientOptions{})
	defer c.Close()
	newX5cIssuer(t, "issuer.example").seed(t, c, map[string]string{"email": "seeded@example.com"})
	verifier, _ := unknownCAVerifier(t, "staging-only.example")

	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			certEntity("staging-verifier", "Staging Verifier", walletconfig.RoleVerifier, clientmodels.TrustLevel_High, verifier.cert),
		}
	})
	production.publish(nil)
	refreshConfig(t, c)
	require.Equal(t, walletconfig.EnvironmentStaging, c.WalletConfigEnvironment(), "developer mode is staging")

	session := requestDisclosure(t, c, sessionHandler, 1, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel)

	c.SetPreferences(clientsettings.Preferences{DeveloperMode: false})
	require.Equal(t, walletconfig.EnvironmentProduction, c.WalletConfigEnvironment())
	refreshConfig(t, c)
	session = requestDisclosure(t, c, sessionHandler, 2, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel, "production trusts nothing staging listed")
	require.Equal(t, "staging-only.example", session.Requestor.Name)

	c.SetPreferences(clientsettings.Preferences{DeveloperMode: true})
	require.Equal(t, walletconfig.EnvironmentStaging, c.WalletConfigEnvironment())
	session = requestDisclosure(t, c, sessionHandler, 3, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel, "the persisted staging config is back in force")
}

// Past its grace period a config's individual listings stop counting, while the
// CAs it anchors keep working: the list input expires, the certificate input does
// not.
func testExpiredConfigDropsListingsKeepsAnchors(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	newX5cIssuer(t, "issuer.example").seed(t, c, map[string]string{"email": "seeded@example.com"})
	listedVerifier, _ := unknownCAVerifier(t, "listed.example")
	caVerifier, ca := unknownCAVerifier(t, "under-ca.example")

	// Issued 40 days ago, next update 30 days later, a week of grace: expired.
	staging.publishIssuedAt(time.Now().Add(-40*24*time.Hour), func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			certEntity("listed-verifier", "Listed", walletconfig.RoleVerifier, clientmodels.TrustLevel_High, listedVerifier.cert),
			caEntity("listed-ca", "Listed CA", walletconfig.RoleVerifier, clientmodels.TrustLevel_Medium, ca),
		}
	})
	refreshConfig(t, c)

	session := requestDisclosure(t, c, sessionHandler, 1, dcApiRequestSpec{verifier: listedVerifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel, "an expired listing confers nothing")
	require.Equal(t, "listed.example", session.Requestor.Name, "nor a curated name")

	session = requestDisclosure(t, c, sessionHandler, 2, dcApiRequestSpec{verifier: caVerifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_Medium, session.Requestor.TrustLevel, "the CA anchor still confers its level")
}

func testRestartedWalletRanksFromPersistedConfig(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	verifier, _ := unknownCAVerifier(t, "persisted.example")
	issuer := newX5cIssuer(t, "issuer.example")

	first, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{StoragePath: storagePath})
	issuer.seed(t, first, map[string]string{"email": "seeded@example.com"})
	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			certEntity("persisted", "Persisted BV", walletconfig.RoleVerifier, clientmodels.TrustLevel_High, verifier.cert),
		}
	})
	refreshConfig(t, first)
	session := requestDisclosure(t, first, sessionHandler, 1, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel)
	require.NoError(t, first.Close())

	// The publisher is dark for the restart: whatever the wallet knows, it
	// knows from disk.
	staging.unavailable()
	second, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{StoragePath: storagePath})
	defer second.Close()
	require.Equal(t, walletconfig.EnvironmentStaging, second.WalletConfigEnvironment(), "developer mode is persisted too")

	session = requestDisclosure(t, second, sessionHandler, 1, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel, "ranked from the persisted config")
	require.Equal(t, "Persisted BV", session.Requestor.Name)
	require.Equal(t, clientmodels.TrustLevel_Low, seededCredential(t, second).Issuer.TrustLevel, "and the stored credential is still there")
}

func testMinimumAppBuildRefusesSessions(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{AppBuild: 100})
	defer c.Close()
	newX5cIssuer(t, "issuer.example").seed(t, c, map[string]string{"email": "seeded@example.com"})
	verifier := installedCAVerifier(t, "anchored.verifier.example")

	staging.publish(func(config *walletconfig.Config) { config.MinimumAppBuild = 100 })
	refreshConfig(t, c)
	requestDisclosure(t, c, sessionHandler, 1, dcApiRequestSpec{verifier: verifier, query: seededQuery()})

	staging.publish(func(config *walletconfig.Config) { config.MinimumAppBuild = 200 })
	refreshConfig(t, c)
	failure := requestDisclosureFails(t, c, sessionHandler, 2, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Equal(t, clientmodels.ErrorType_AppUpdateRequired, failure.ErrorType, "an OpenID4VC session is refused until the app updates")

	// The IRMA side keeps working: the gate's scope is the config's.
	credentials, _, err := c.GetCredentials()
	require.NoError(t, err)
	require.NotEmpty(t, credentials)
}

// ========================================================================
// Stored credential tests
// ========================================================================

func testStoredCredentialIssuerFollowsTheConfig(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, _ := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	issuer := newX5cIssuer(t, "issuer.example")
	issuer.seed(t, c, map[string]string{"email": "seeded@example.com"})

	credential := seededCredential(t, c)
	require.Equal(t, clientmodels.TrustLevel_Low, credential.Issuer.TrustLevel, "nobody vouches for the issuer yet")
	require.False(t, credential.IssuerNotTrusted, "the default policy admits low")
	require.Equal(t, "Seeded Issuer", credential.Issuer.Name)

	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			caEntity("issuer-ca", "Issuer CA", walletconfig.RoleIssuer, clientmodels.TrustLevel_High, issuer.ca),
		}
	})
	refreshConfig(t, c)
	require.Equal(t, clientmodels.TrustLevel_High, seededCredential(t, c).Issuer.TrustLevel,
		"the certificate the credential was signed with now chains to a listed CA")

	// Listed for verifiers only, the same CA vouches for no issuer.
	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			caEntity("issuer-ca", "Issuer CA", walletconfig.RoleVerifier, clientmodels.TrustLevel_High, issuer.ca),
		}
	})
	refreshConfig(t, c)
	require.Equal(t, clientmodels.TrustLevel_Low, seededCredential(t, c).Issuer.TrustLevel, "roles are separate grants")
}

func testStoredCredentialBelowPolicyIsExcluded(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	issuer := newX5cIssuer(t, "issuer.example")
	issuer.seed(t, c, map[string]string{"email": "seeded@example.com"})
	verifier := installedCAVerifier(t, "anchored.verifier.example")

	// A minimum the issuer does not reach: the credential stays, badged, and is
	// not offered.
	staging.publish(func(config *walletconfig.Config) {
		config.Policy.MinimumTrustLevel.Issuance = clientmodels.TrustLevel_Medium
	})
	refreshConfig(t, c)

	credential := seededCredential(t, c)
	require.Equal(t, clientmodels.TrustLevel_Low, credential.Issuer.TrustLevel)
	require.True(t, credential.IssuerNotTrusted)

	session := requestDisclosure(t, c, sessionHandler, 1, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	require.Empty(t, session.DisclosurePlan.DisclosureChoicesOverview, "nothing to choose from")
	require.NotNil(t, session.DisclosurePlan.IssueDuringDisclosure, "the wallet holds nothing usable of this type")
	require.Nil(t, session.DisclosurePlan.IssueDuringDisclosure.Steps[0].Options[0].Credentials[0].IssueURL,
		"and knows nowhere to obtain it")

	// Listing the issuer's CA lifts it over the minimum, and the credential is
	// disclosable again.
	staging.publish(func(config *walletconfig.Config) {
		config.Policy.MinimumTrustLevel.Issuance = clientmodels.TrustLevel_Medium
		config.TrustedEntities = []walletconfig.TrustedEntity{
			caEntity("issuer-ca", "Issuer CA", walletconfig.RoleIssuer, clientmodels.TrustLevel_Medium, issuer.ca),
		}
	})
	refreshConfig(t, c)
	credential = seededCredential(t, c)
	require.Equal(t, clientmodels.TrustLevel_Medium, credential.Issuer.TrustLevel)
	require.False(t, credential.IssuerNotTrusted)

	session = requestDisclosure(t, c, sessionHandler, 2, dcApiRequestSpec{verifier: verifier, query: seededQuery()})
	owned := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.Len(t, owned, 1)
	require.Equal(t, clientmodels.TrustLevel_Medium, owned[0].Credentials[0].Issuer.TrustLevel, "the candidate carries the issuer's level too")
	completeDisclosure(t, c, sessionHandler, session)
}

func testStoredCredentialFromDIDIssuerRanksByDID(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, _ := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	issuer := newDidIssuer(t)
	issuer.seed(t, c, map[string]string{"email": "seeded@example.com"})

	require.Equal(t, clientmodels.TrustLevel_Low, seededCredential(t, c).Issuer.TrustLevel, "an unlisted DID is low: the DID hole is closed")

	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			didEntity("did-issuer", "DID Issuer", walletconfig.RoleIssuer, clientmodels.TrustLevel_High, issuer.did),
		}
	})
	refreshConfig(t, c)
	require.Equal(t, clientmodels.TrustLevel_High, seededCredential(t, c).Issuer.TrustLevel, "listed by its exact DID")

	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			didEntity("other-did", "Other", walletconfig.RoleIssuer, clientmodels.TrustLevel_High, issuer.did+":sub"),
		}
	})
	refreshConfig(t, c)
	require.Equal(t, clientmodels.TrustLevel_Low, seededCredential(t, c).Issuer.TrustLevel, "exact match, no prefixes")
}
