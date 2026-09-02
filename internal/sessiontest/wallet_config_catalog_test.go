package sessiontest

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

// The credential catalogue as the app meets it, against the OpenID4VP verifiers
// from docker-compose.yml: a verifier asks for a credential the wallet does not
// hold, and the session state shows where to obtain it instead of a dead end.
//
// The catalogue arrives in the staging config from the same publisher the trust
// tests use. The email type's metadata and the test issuer's metadata are the
// ones the TLS proxy serves for the veramo issuer, so the descriptors are
// resolved from the same documents the issuance tests run on. The one type
// nothing in Docker describes, the PID URN, gets its metadata from an in-process
// TLS server through the entry's vct_metadata_url: the case that URL exists for.
//
// Metadata caching per config issue is covered by the catalogue service's unit
// tests; here the documents are simply live.

const (
	// veramoEmailVct is the email credential the veramo issuer issues and the TLS
	// proxy describes.
	veramoEmailVct = "https://localhost:8443/vct/email"
	// veramoMissingVct is a type nothing describes: its URL answers 404.
	veramoMissingVct = "https://localhost:8443/vct/does-not-exist-anywhere"
	// veramoQueryID is the DCQL query id the veramo verifier sessions use.
	veramoQueryID = "email-cred"

	pidMetadataPath = "/types/pid"
)

func TestWalletConfigCatalog(t *testing.T) {
	t.Run("a catalogue hit turns a missing credential into an issuance step", testCatalogTurnsMissingCredentialIntoIssuanceStep)
	t.Run("an offering's issuer is soft-matched to a trusted entity", testCatalogOfferingIssuerIsSoftMatchedToTrustedEntity)
	t.Run("the step follows the wallet's locale", testCatalogStepFollowsTheWalletLocale)
	t.Run("the first listed type among the requested ones wins", testCatalogFirstListedRequestedTypeWins)
	t.Run("an obtained credential replaces the step and the disclosure completes", testCatalogStepIsReplacedOnceTheCredentialIsObtained)
	t.Run("a URN type resolves through its metadata URL at the EUDI verifier", testCatalogResolvesURNTypeThroughItsMetadataURL)
	t.Run("the store lists opted-in entries, one item per offering", testCatalogStoreListsOptedInEntriesPerOffering)
	t.Run("the store renders the raw type when metadata is unresolvable", testCatalogStoreRendersRawTypeWhenMetadataIsUnresolvable)
	t.Run("the catalogue follows the config lifecycle", testCatalogFollowsTheConfigLifecycle)
}

// ========================================================================
// Catalogue entries
// ========================================================================

// emailEntry is the catalogue entry for the veramo email type, with its metadata
// URL listed explicitly.
func emailEntry(inStore bool, offerings ...walletconfig.Offering) walletconfig.CatalogEntry {
	return walletconfig.CatalogEntry{
		VCT:            veramoEmailVct,
		VCTMetadataURL: veramoEmailVct,
		InStore:        inStore,
		Offerings:      offerings,
	}
}

// testIssuerOffering is an offering by the veramo test issuer, whose metadata the
// TLS proxy serves, with issuance pages in three languages.
func testIssuerOffering() walletconfig.Offering {
	return walletconfig.Offering{
		IssuerMetadataURL: preAuthIssuerURL,
		IssuanceURLs: map[string]string{
			"default": "https://issue.example/start",
			"en":      "https://issue.example/en/start",
			"nl":      "https://issue.example/nl/start",
		},
	}
}

// webOffering is an offering that names no issuer: a web page at host, in the
// default language and Dutch.
func webOffering(host string) walletconfig.Offering {
	return walletconfig.Offering{
		IssuanceURLs: map[string]string{
			"default": "https://" + host + "/start",
			"nl":      "https://" + host + "/nl/start",
		},
	}
}

// withCatalog is a config edit carrying the catalogue, under the schema that
// introduced it.
func withCatalog(entities []walletconfig.TrustedEntity, entries ...walletconfig.CatalogEntry) func(*walletconfig.Config) {
	return func(config *walletconfig.Config) {
		config.SchemaVersion = walletconfig.CurrentSchemaVersion
		config.TrustedEntities = entities
		config.CredentialCatalog = entries
	}
}

// ========================================================================
// Sessions
// ========================================================================

// veramoEmailQuery is the veramo verifier's DCQL for the email claim of any of
// the given types.
func veramoEmailQuery(vcts ...string) string {
	vctValues, err := json.Marshal(vcts)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf(`{
		"dcql": {
			"credentials": [
				{
					"id": %q,
					"format": "dc+sd-jwt",
					"meta": { "vct_values": %s },
					"claims": [ { "path": ["email"] } ]
				}
			]
		}
	}`, veramoQueryID, vctValues)
}

// requestVeramoDisclosure starts a session at the veramo verifier with the query
// and returns the wallet's first state along with the verifier's session.
func requestVeramoDisclosure(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionID int, dcql string) (clientmodels.SessionState, veramoVerifierSession) {
	t.Helper()
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcql)
	startOpenID4VPDisclosureSession(t, c, sessionID, veramoSession.RequestUri)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionID, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	return session, veramoSession
}

// requestPidAtEudiVerifier starts a session at the EUDI reference verifier asking
// for the PID's name claims and returns the wallet's first state.
func requestPidAtEudiVerifier(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionID int) clientmodels.SessionState {
	t.Helper()
	startRequest := fmt.Sprintf(`{
		"type": "vp_token",
		"dcql_query": {
			"credentials": [
				{
					"id": "pid",
					"format": "dc+sd-jwt",
					"meta": { "vct_values": [%q] },
					"claims": [
						{ "path": ["given_name"] },
						{ "path": ["family_name"] }
					]
				}
			]
		},
		"nonce": "nonce",
		"jar_mode": "by_reference",
		"request_uri_method": "get",
		"intended_use_id": %q
	}`, eudiPidIssuerPyVct, eudiVerifierIntendedUseId)
	verifierSession, err := StartTestSessionAtEudiVerifier(eudiPidIssuerPyOpenID4VPVerifierHost, startRequest)
	require.NoError(t, err)
	startOpenID4VPDisclosureSession(t, c, sessionID, verifierSession.SessionLink)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionID, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	return session
}

// issuanceOptions is the one issuance step a session for a credential the wallet
// lacks must carry: the ways to obtain it.
func issuanceOptions(t *testing.T, session clientmodels.SessionState) []*clientmodels.IssuanceBundle {
	t.Helper()
	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.Nil(t, plan.DisclosureChoicesOverview, "with a credential to obtain first, there is nothing to choose from yet")
	require.NotNil(t, plan.IssueDuringDisclosure)
	require.Len(t, plan.IssueDuringDisclosure.Steps, 1)
	return plan.IssueDuringDisclosure.Steps[0].Options
}

// singleCredential is the one descriptor a DCQL issuance bundle carries.
func singleCredential(t *testing.T, bundle *clientmodels.IssuanceBundle) *clientmodels.CredentialDescriptor {
	t.Helper()
	require.Len(t, bundle.Credentials, 1, "DCQL maps each query to a single-credential bundle")
	return bundle.Credentials[0]
}

// requireCatalogAttributes checks the attributes a descriptor lists, in order:
// claim paths with display names and no values.
func requireCatalogAttributes(t *testing.T, attributes []clientmodels.Attribute, expected ...[2]string) {
	t.Helper()
	require.Len(t, attributes, len(expected))
	for i, want := range expected {
		require.Equal(t, []any{want[0]}, attributes[i].ClaimPath)
		require.NotNil(t, attributes[i].DisplayName, "attribute %s has no display name", want[0])
		require.Equal(t, want[1], *attributes[i].DisplayName)
		require.Nil(t, attributes[i].Value, "a catalogue item describes a type, it carries no values")
	}
}

func storeItems(t *testing.T, c *client.Client) []*clientmodels.CredentialDescriptor {
	t.Helper()
	return c.GetOpenID4VCCredentialStore()
}

// ========================================================================
// Veramo verifier
// ========================================================================

func testCatalogTurnsMissingCredentialIntoIssuanceStep(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()

	// Without a catalogue the wallet describes the request from the type's own
	// metadata, and has nowhere to send the user.
	session, _ := requestVeramoDisclosure(t, c, sessionHandler, 1, veramoEmailQuery(veramoEmailVct))
	options := issuanceOptions(t, session)
	require.Len(t, options, 1)
	before := singleCredential(t, options[0])
	require.Equal(t, veramoEmailVct, before.CredentialId)
	require.Nil(t, before.IssueURL, "no URL is today's signal that the session cannot be completed")
	require.Equal(t, "Email Credential (SD-JWT)", before.Name)

	staging.publish(withCatalog(nil, emailEntry(false, testIssuerOffering(), webOffering("other.example"))))
	refreshConfig(t, c)

	session, _ = requestVeramoDisclosure(t, c, sessionHandler, 2, veramoEmailQuery(veramoEmailVct))
	require.Equal(t, "test-verifier", session.Requestor.Name)
	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel, "a did:web verifier nobody vouches for")

	options = issuanceOptions(t, session)
	require.Len(t, options, 2, "one way to obtain the credential per offering")

	described := singleCredential(t, options[0])
	require.Equal(t, veramoEmailVct, described.CredentialId)
	require.Equal(t, "Email Credential (SD-JWT)", described.Name, "named from the type metadata the entry points at")
	requireCatalogAttributes(t, described.Attributes, [2]string{"email", "Email"})
	require.NotNil(t, described.IssueURL, "a URL is what turns the dead end into a step")
	require.Equal(t, "https://issue.example/en/start", *described.IssueURL)
	require.Equal(t, preAuthIssuerURL, described.Issuer.Id)
	require.Equal(t, "Test Issuer", described.Issuer.Name, "the issuer is named from its metadata")
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, described.Issuer.TrustLevel, "presence in the catalogue is not a trust level")

	bare := singleCredential(t, options[1])
	require.Equal(t, veramoEmailVct, bare.CredentialId)
	require.Equal(t, "https://other.example/start", *bare.IssueURL, "no English page: the default")
	require.Equal(t, clientmodels.TrustedParty{}, bare.Issuer, "an offering naming no issuer has none")
}

// D20: the catalogue vouches for nobody, but when an offering's host is one a
// trusted issuer's handle carries, that entity's name and level are shown.
func testCatalogOfferingIssuerIsSoftMatchedToTrustedEntity(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()

	entities := []walletconfig.TrustedEntity{
		// The veramo issuer's did:web is at localhost, the offering's host.
		didEntity("veramo", "Curated Test Issuer", walletconfig.RoleIssuer, clientmodels.TrustLevel_High, veramoIssuerDID),
	}
	staging.publish(withCatalog(entities, emailEntry(false, testIssuerOffering())))
	refreshConfig(t, c)

	session, _ := requestVeramoDisclosure(t, c, sessionHandler, 1, veramoEmailQuery(veramoEmailVct))
	described := singleCredential(t, issuanceOptions(t, session)[0])
	require.Equal(t, "Curated Test Issuer", described.Issuer.Name, "the entity's name outranks the metadata's")
	require.Equal(t, clientmodels.TrustLevel_High, described.Issuer.TrustLevel)
	require.Equal(t, preAuthIssuerURL, described.Issuer.Id, "the metadata's identifier stays")
	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel, "the match says nothing about the verifier")
}

func testCatalogStepFollowsTheWalletLocale(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{Locale: "nl"})
	defer c.Close()
	staging.publish(withCatalog(nil, emailEntry(false, testIssuerOffering())))
	refreshConfig(t, c)

	session, _ := requestVeramoDisclosure(t, c, sessionHandler, 1, veramoEmailQuery(veramoEmailVct))
	described := singleCredential(t, issuanceOptions(t, session)[0])
	require.Equal(t, "E-mail Credential (SD-JWT)", described.Name)
	requireCatalogAttributes(t, described.Attributes, [2]string{"email", "E-mailadres"})
	require.Equal(t, "https://issue.example/nl/start", *described.IssueURL)
	require.Equal(t, "Test Uitgever", described.Issuer.Name)
}

func testCatalogFirstListedRequestedTypeWins(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	staging.publish(withCatalog(nil, emailEntry(false, testIssuerOffering())))
	refreshConfig(t, c)

	// The verifier accepts either type; the catalogue lists only the second.
	session, _ := requestVeramoDisclosure(t, c, sessionHandler, 1, veramoEmailQuery(veramoMissingVct, veramoEmailVct))
	options := issuanceOptions(t, session)
	require.Len(t, options, 1)
	described := singleCredential(t, options[0])
	require.Equal(t, veramoEmailVct, described.CredentialId, "the type the catalogue lists is the one offered")
	require.Equal(t, "https://issue.example/en/start", *described.IssueURL)
}

func testCatalogStepIsReplacedOnceTheCredentialIsObtained(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	staging.publish(withCatalog(nil, emailEntry(false, testIssuerOffering())))
	refreshConfig(t, c)

	session, _ := requestVeramoDisclosure(t, c, sessionHandler, 1, veramoEmailQuery(veramoEmailVct))
	require.NotNil(t, singleCredential(t, issuanceOptions(t, session)[0]).IssueURL)

	// The user follows the URL and comes back with the credential; here the
	// issuer's OpenID4VCI flow stands in for that browser session.
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "catalogue@example.com",
		"domain": "example.com"
	}`)

	session, veramoSession := requestVeramoDisclosure(t, c, sessionHandler, 3, veramoEmailQuery(veramoEmailVct))
	require.Nil(t, session.DisclosurePlan.IssueDuringDisclosure, "the catalogue has nothing to add to a credential the wallet holds")
	owned := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.Len(t, owned, 1)
	grantPermission(t, c, session.Id, makeDisclosureChoice(owned[0]))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, veramoQueryID, claim([]any{"email"}, "catalogue@example.com"))
}

// ========================================================================
// EUDI reference verifier
// ========================================================================

// The PID is a URN type: the wallet cannot fetch metadata for it by the vct, so
// today a request for one the wallet lacks shows the bare URN. The catalogue's
// metadata URL is what makes it resolvable.
func testCatalogResolvesURNTypeThroughItsMetadataURL(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	meta := newMetadataServer(t)
	meta.serve(pidMetadataPath, map[string]any{
		"vct":  eudiPidIssuerPyVct,
		"name": "PID",
		"display": []any{
			map[string]any{"lang": "en", "name": "Person Identification Data"},
			map[string]any{"lang": "nl", "name": "Persoonsgegevens"},
		},
		"claims": []any{
			map[string]any{"path": []any{"given_name"}, "display": []any{map[string]any{"lang": "en", "label": "Given name"}}},
			map[string]any{"path": []any{"family_name"}, "display": []any{map[string]any{"lang": "en", "label": "Family name"}}},
			map[string]any{"path": []any{"birthdate"}, "display": []any{map[string]any{"lang": "en", "label": "Date of birth"}}},
		},
	})
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()

	session := requestPidAtEudiVerifier(t, c, sessionHandler, 1)
	require.Equal(t, "Yivi B.V.", session.Requestor.Name, "the reference verifier is anchored under the installed CA")
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel)
	before := singleCredential(t, issuanceOptions(t, session)[0])
	require.Equal(t, eudiPidIssuerPyVct, before.CredentialId)
	require.Nil(t, before.IssueURL)
	require.Empty(t, before.Name, "a URN resolves to nothing on its own")

	staging.publish(withCatalog(nil, walletconfig.CatalogEntry{
		VCT:            eudiPidIssuerPyVct,
		VCTMetadataURL: meta.url(pidMetadataPath),
		Offerings:      []walletconfig.Offering{webOffering("pid.example")},
	}))
	refreshConfig(t, c)

	session = requestPidAtEudiVerifier(t, c, sessionHandler, 2)
	options := issuanceOptions(t, session)
	require.Len(t, options, 1)
	described := singleCredential(t, options[0])
	require.Equal(t, eudiPidIssuerPyVct, described.CredentialId)
	require.Equal(t, "Person Identification Data", described.Name, "named through the listed metadata URL")
	requireCatalogAttributes(t, described.Attributes, [2]string{"given_name", "Given name"}, [2]string{"family_name", "Family name"})
	require.Equal(t, "https://pid.example/start", *described.IssueURL)
	require.Equal(t, clientmodels.TrustedParty{}, described.Issuer)
}

// ========================================================================
// Store
// ========================================================================

func testCatalogStoreListsOptedInEntriesPerOffering(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, _ := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()

	require.Empty(t, storeItems(t, c), "no config, no OpenID4VC section")

	staging.publish(withCatalog(nil,
		emailEntry(true, testIssuerOffering(), webOffering("other.example")),
		walletconfig.CatalogEntry{VCT: veramoMissingVct, Offerings: []walletconfig.Offering{webOffering("hidden.example")}},
	))
	refreshConfig(t, c)

	items := storeItems(t, c)
	require.Len(t, items, 2, "one item per offering of the opted-in entry; the other entry is not in the store")
	for _, item := range items {
		require.Equal(t, veramoEmailVct, item.CredentialId)
		require.Equal(t, "Email Credential (SD-JWT)", item.Name, "named from the type metadata")
		requireCatalogAttributes(t, item.Attributes, [2]string{"email", "Email"}, [2]string{"domain", "Domain"})
		require.Nil(t, item.Image, "catalogue items carry no logo")
	}

	described := items[0]
	require.Equal(t, "https://issue.example/en/start", *described.IssueURL)
	require.Equal(t, "Test Issuer", described.Issuer.Name)
	require.Equal(t, preAuthIssuerURL, described.Issuer.Id)
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, described.Issuer.TrustLevel)

	bare := items[1]
	require.Equal(t, "https://other.example/start", *bare.IssueURL, "no English page: the default")
	require.Equal(t, clientmodels.TrustedParty{}, bare.Issuer)
}

func testCatalogStoreRendersRawTypeWhenMetadataIsUnresolvable(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, _ := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()

	staging.publish(withCatalog(nil,
		// A URN with no metadata URL resolves nowhere.
		walletconfig.CatalogEntry{VCT: eudiPidIssuerPyVct, InStore: true, Offerings: []walletconfig.Offering{webOffering("pid.example")}},
		// A metadata URL that answers 404.
		walletconfig.CatalogEntry{VCT: veramoMissingVct, InStore: true, Offerings: []walletconfig.Offering{webOffering("missing.example")}},
	))
	refreshConfig(t, c)

	items := storeItems(t, c)
	require.Len(t, items, 2)
	require.Equal(t, eudiPidIssuerPyVct, items[0].Name, "the raw vct is the last resort")
	require.Empty(t, items[0].Attributes)
	require.Equal(t, "https://pid.example/start", *items[0].IssueURL, "the offering stands regardless")
	require.Equal(t, veramoMissingVct, items[1].Name)
	require.Empty(t, items[1].Attributes)
}

func testCatalogFollowsTheConfigLifecycle(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	production := newConfigPublisher(t, walletconfig.EnvironmentProduction)
	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	c, _, _ := trustTestClient(t, staging, &production.env, testClientOptions{StoragePath: storagePath})

	production.publish(nil)
	staging.publish(withCatalog(nil, emailEntry(true, testIssuerOffering())))
	refreshConfig(t, c)
	require.Len(t, storeItems(t, c), 1)

	// Production has no catalogue: leaving developer mode empties the section,
	// returning restores it.
	c.SetPreferences(clientsettings.Preferences{DeveloperMode: false})
	refreshConfig(t, c)
	require.Empty(t, storeItems(t, c), "the catalogue is the environment's")
	c.SetPreferences(clientsettings.Preferences{DeveloperMode: true})
	require.Len(t, storeItems(t, c), 1)

	// Delisting is a config publish.
	staging.publish(nil)
	refreshConfig(t, c)
	require.Empty(t, storeItems(t, c))

	// Relisted, persisted, and read back after a restart with the publisher dark.
	staging.publish(withCatalog(nil, emailEntry(true, testIssuerOffering())))
	refreshConfig(t, c)
	require.Len(t, storeItems(t, c), 1)
	require.NoError(t, c.Close())

	staging.unavailable()
	restarted, _, _ := trustTestClient(t, staging, &production.env, testClientOptions{StoragePath: storagePath})
	defer restarted.Close()
	items := storeItems(t, restarted)
	require.Len(t, items, 1, "the catalogue comes from the persisted config")
	require.Equal(t, "Email Credential (SD-JWT)", items[0].Name, "and its metadata is fetched afresh")
}

// ========================================================================
// Metadata server
// ========================================================================

// metadataServer serves JSON documents over TLS under the test localhost
// certificate, for type metadata nothing in Docker publishes.
type metadataServer struct {
	t      *testing.T
	server *httptest.Server
	host   string

	mu   sync.Mutex
	docs map[string][]byte
}

func newMetadataServer(t *testing.T) *metadataServer {
	t.Helper()
	m := &metadataServer{t: t, docs: map[string][]byte{}}
	certDir := filepath.Join(testdataFolder, "configurations", "certs")
	certificate, err := tls.LoadX509KeyPair(filepath.Join(certDir, "localhost.crt"), filepath.Join(certDir, "localhost.key"))
	require.NoError(t, err)

	m.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		body, ok := m.docs[r.URL.Path]
		m.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	m.server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	m.server.StartTLS()
	t.Cleanup(m.server.Close)

	// The certificate names localhost, so that is how the wallet must address
	// the server.
	parsed, err := url.Parse(m.server.URL)
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(parsed.Host)
	require.NoError(t, err)
	m.host = "localhost:" + port
	return m
}

func (m *metadataServer) url(path string) string {
	return "https://" + m.host + path
}

func (m *metadataServer) serve(path string, document any) {
	body, err := json.Marshal(document)
	require.NoError(m.t, err)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.docs[path] = body
}
