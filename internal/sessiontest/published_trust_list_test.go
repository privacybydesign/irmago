package sessiontest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/require"
)

// The recognized-list channel against a real published list: the compose LoTE
// publisher (testdata/lote-publisher), which signs with the openssl CLI rather
// than the JWS library the wallet verifies with, served over TLS through the same
// nginx proxy as the other EUDI services.
//
// A test belongs here when it needs a real fetch, TLS, a restart, the passage of
// time, or a downloaded asset; otherwise it goes in-process in
// trust_levels_test.go. Counting fetches is in-process only, since
// lote.TestLoteServer.Hits() is the only thing that can see one happen — as is
// tamper and sequence-regress coverage, where a foreign signer adds no signal.

const (
	// The publisher's public origin, through the tls_proxy.
	publishedListURL = "https://localhost:8446"

	// publishedListId must equal the LOTE_LIST_ID the compose service declares: it
	// becomes the document's English SchemeName, which the wallet pins.
	publishedListId = "urn:yivi:trustlist:sessiontest"

	publishedLogoURI = publishedListURL + "/logo.png"
)

func testSessionHandlerForPublishedTrustList(t *testing.T) {
	t.Run("a foreign-signed list is accepted and grants its source's level", testPublishedListGrants)
	t.Run("a held list crossing next_update caps parties at low", testPublishedListExpiresWhileHeld)
	t.Run("the scheduled refresh wakes the app once on a content change", testScheduledRefreshWakesTheAppOnce)
	t.Run("a session completes while the publisher is dark", testSessionCompletesWhilePublisherIsDark)
	t.Run("a restarted wallet ranks from the persisted list", testRestartedWalletRanksFromDisk)
	t.Run("curated name and logo beat the certificate's own", testCuratedDisplayBeatsAttested)
}

// This suite's tracer: a list signed by the openssl CLI, assembled by hand and
// fetched over TLS from another process, verifies and lifts the issuer it grants
// to high in a real session. Everything else here depends on it.
func testPublishedListGrants(t *testing.T) {
	c, _, sessionHandler := newPublishedListClient(t)
	defer c.Close()

	publishList(t, 1, publishedNextUpdateDefault, listedIssuerEntity("Published Issuer BV"))
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	offer := createPreAuthOffer(t)
	startOpenID4VCISession(t, c, 1, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel,
		"a party granted on the published list ranks what its source confers")
	require.Equal(t, "Published Issuer BV", session.Requestor.Name,
		"and is shown under the curated name the entry carries")

	grantPermission(t, c, session.Id)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

// A list the wallet has already adopted stops being evidence when it crosses its
// next_update. Published dated just inside the skew window so the fetch accepts it
// and it goes stale seconds later — see skewBoundaryOffset.
func testPublishedListExpiresWhileHeld(t *testing.T) {
	c, _, sessionHandler := newPublishedListClient(t)
	defer c.Close()

	const expiresWithin = 6 * time.Second
	publishList(t, 1, skewBoundaryOffset(expiresWithin), listedIssuerEntity("Briefly Listed BV"))
	require.NoError(t, c.RefreshTrustLists(context.Background()),
		"a list just inside the skew window is still accepted at fetch")

	require.Equal(t, clientmodels.TrustLevel_High, issuerLevelOfOffer(t, c, 1, sessionHandler),
		"while it is current, the list grants")

	time.Sleep(expiresWithin + time.Second)

	require.Equal(t, clientmodels.TrustLevel_Low, issuerLevelOfOffer(t, c, 2, sessionHandler),
		"past next_update the held list is no evidence, and the issuer caps at low")
}

// The background job: the wallet notices changed entries without being asked, and
// tells the app exactly once, while a re-confirmation stays silent.
func testScheduledRefreshWakesTheAppOnce(t *testing.T) {
	publishList(t, 1, publishedNextUpdateDefault, listedIssuerEntity("Scheduled BV"))

	c, clientHandler, _ := newPublishedListClient(t)
	defer c.Close()

	// The CRL job is parked an hour out and the status sweep off, so the trust-list
	// refresh is the only thing on the schedule.
	c.InitJobs(time.Hour, 0, 2*time.Second)

	// The first, immediate run adopts the list, which is not a change: the app was
	// showing no verdict from it before.
	require.Never(t, func() bool { return clientHandler.CredentialsChangedCount() > 0 },
		5*time.Second, 500*time.Millisecond,
		"adopting a list for the first time must not wake the app")

	publishList(t, 2, publishedNextUpdateDefault, listedIssuerEntity("Scheduled BV Renamed"))
	require.Eventually(t, func() bool { return clientHandler.CredentialsChangedCount() == 1 },
		20*time.Second, 250*time.Millisecond,
		"a scheduled refresh that finds changed entries wakes the app")

	// Nothing changes from here on, so no later tick may wake it again.
	require.Never(t, func() bool { return clientHandler.CredentialsChangedCount() > 1 },
		6*time.Second, 500*time.Millisecond,
		"re-confirming the same entries stays silent")
}

// A wallet holding a valid copy is fully functional with the publisher gone; the
// refresh reports the outage to its caller only.
func testSessionCompletesWhilePublisherIsDark(t *testing.T) {
	c, _, sessionHandler := newPublishedListClient(t)
	defer c.Close()

	publishList(t, 1, publishedNextUpdateDefault, listedIssuerEntity("Offline BV"))
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	darkenPublisher(t)
	require.Error(t, c.RefreshTrustLists(context.Background()),
		"the refresh reports the outage to whoever asked for it")

	require.Equal(t, clientmodels.TrustLevel_High, issuerLevelOfOffer(t, c, 1, sessionHandler),
		"and the wallet keeps ranking on the copy it holds")
}

// The signed document survives a restart and is re-verified against the anchors
// in force when read. The publisher is dark for the second wallet's whole life, so
// nothing it ranks came off the wire.
func testRestartedWalletRanksFromDisk(t *testing.T) {
	storagePath := filepath.Join(test.CreateTestStorage(t), "client")

	publishList(t, 1, publishedNextUpdateDefault, listedIssuerEntity("Persisted BV"))
	first, _, _ := newPublishedListClientAt(t, storagePath)
	require.NoError(t, first.RefreshTrustLists(context.Background()))
	require.NoError(t, first.Close())

	darkenPublisher(t)

	second, _, sessionHandler := newPublishedListClientAt(t, storagePath)
	defer second.Close()

	require.Equal(t, clientmodels.TrustLevel_High, issuerLevelOfOffer(t, second, 1, sessionHandler),
		"the persisted list still grants after a restart, with the publisher unreachable")
}

// Display precedence and certificate keying in one session: a certificate-bearing
// party is high whether or not a list grants it, so the only way to see that a
// certificate-keyed entry matched is the curated display it attaches.
//
// The EUDI Kotlin verifier is the only party in the compose stack whose
// certificate carries both an attested name and an attested logo.
func testCuratedDisplayBeatsAttested(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	publishList(t, 1, publishedNextUpdateDefault, listedVerifierEntity(t, "Curated Verifier BV"))

	c, clientHandler, sessionHandler := newPublishedListClient(t)
	defer c.Close()
	c.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, clientHandler.AwaitEnrollmentResult())
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	session := startOpenID4VPSessionWithAuthRequest(t, c, 1, sessionHandler, createEmailAuthRequestRequest()).ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel,
		"the certificate channel already puts this verifier at the top rung, list or no list")
	require.Equal(t, "Curated Verifier BV", session.Requestor.Name,
		"the curated name beats the attested Yivi B.V. the certificate carries")
	requirePublishedLogo(t, session.Requestor)
}

// ----------------------------------------------------------------------------
// Wiring
// ----------------------------------------------------------------------------

// listedVerifierEntity grants the EUDI Kotlin verifier, keyed on its signing
// leaf's subject key identifier plus its organizationIdentifier. Both are read
// from the certificate, so regenerating the material cannot leave the entry
// stale.
func listedVerifierEntity(t *testing.T, name string) map[string]any {
	t.Helper()
	leaf := eudiVerifierLeaf(t)

	return map[string]any{
		"name":                    name,
		"logo_uri":                publishedLogoURI,
		"organization_identifier": subjectOrganizationIdentifier(t, leaf),
		"services": []map[string]any{{
			"role": "Verifier",
			// []byte marshals to base64, which is what X509SKIs holds.
			"ski": leaf.SubjectKeyId,
		}},
	}
}

// certFromPemFile parses the first certificate out of a committed PEM file,
// tolerating a fixture that later grows intermediates.
func certFromPemFile(t *testing.T, parts ...string) *x509.Certificate {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join(append([]string{testdataFolder}, parts...)...))
	require.NoError(t, err)
	chain, err := utils.ParsePemCertificateChain(pemBytes)
	require.NoError(t, err)
	require.NotEmpty(t, chain)
	return chain[0]
}

func eudiVerifierLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	return certFromPemFile(t, "eudi", "verifier", "verifier.crt")
}

// subjectOrganizationIdentifier reads the entity identifier a list entry is keyed
// on out of a certificate, through the matcher the wallet reads it with.
func subjectOrganizationIdentifier(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	value := lote.CertificateOrganizationIdentifier(cert)
	require.NotEmpty(t, value,
		"certificate subject carries no organizationIdentifier; re-run testdata/eudi/verifier/gen-cert-chain.sh")
	return value
}

// issuerLevelOfOffer drives a pre-authorized issuance to the permission screen,
// reads the issuer's rung off it, and dismisses the session.
func issuerLevelOfOffer(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
) clientmodels.TrustLevel {
	t.Helper()

	offer := createPreAuthOffer(t)
	startOpenID4VCISession(t, c, sessionId, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	level := session.Requestor.TrustLevel

	// Dismissed rather than granted: this helper is called several times per test
	// and issuance would consume the offer.
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_DismissSession,
	})
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)

	return level
}

// publishedNextUpdateDefault is a next_update far enough out that a test which
// does not care about currency never has to think about it.
const publishedNextUpdateDefault = 3600

// A wallet whose one recognized list is the compose publisher's, with the
// publisher's root installed as an issuer trust anchor.
func newPublishedListClient(t *testing.T) (*client.Client, *irmaclient.MockClientHandler, *MockSessionHandler) {
	t.Helper()
	return newPublishedListClientAt(t, filepath.Join(test.CreateTestStorage(t), "client"))
}

// newPublishedListClientAt is newPublishedListClient at a caller-supplied storage
// path, so a second wallet can be built over the first one's data.
func newPublishedListClientAt(t *testing.T, storagePath string) (*client.Client, *irmaclient.MockClientHandler, *MockSessionHandler) {
	t.Helper()
	return instantiateClientAtPath(t, storagePath, nil, "en", publisherRoot(t),
		[]lote.Source{{
			ListId:   publishedListId,
			LoTEType: lote.LoTETypeRecognizedParties,
			URL:      publishedListURL,
			Confers:  clientmodels.TrustLevel_High,
		}})
}

func publisherRoot(t *testing.T) *x509.Certificate {
	t.Helper()
	return certFromPemFile(t, "lote-publisher", "certs", "root.crt")
}

// publishList replaces what the publisher serves. nextUpdateSeconds may be
// negative: the wallet is current while now - lote.ClockSkew < next_update, so
// backdating to just inside that window expires a held list in seconds.
func publishList(t *testing.T, sequenceNumber int, nextUpdateSeconds int, entities ...map[string]any) {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"entities":            entities,
		"sequence_number":     sequenceNumber,
		"next_update_seconds": nextUpdateSeconds,
	})
	require.NoError(t, err)

	resp, err := http.Post(publishedListURL+"/admin/publish", "application/json", bytes.NewReader(body))
	require.NoError(t, err, "the publisher must be reachable; is the compose stack up?")
	defer func() { require.NoError(t, resp.Body.Close()) }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// darkenPublisher makes the publisher answer 503 until the next publish, taking
// the list away without stopping a container the rest of the suite shares.
func darkenPublisher(t *testing.T) {
	t.Helper()
	resp, err := http.Post(publishedListURL+"/admin/dark", "application/json", bytes.NewReader([]byte("{}")))
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func listedIssuerEntity(name string, markings ...string) map[string]any {
	return map[string]any{
		"name":     name,
		"logo_uri": publishedLogoURI,
		"services": []map[string]any{{
			"role":     "Issuer",
			"did":      testIssuerDid,
			"markings": markings,
		}},
	}
}

// skewBoundaryOffset is a next_update offset a fetch still accepts and that
// expires `within` afterwards. Derived from lote.ClockSkew, so if that ever
// shrinks below `within` the fetch rejects the list and the test fails loudly
// instead of waiting forever.
func skewBoundaryOffset(within time.Duration) int {
	return -int((lote.ClockSkew - within) / time.Second)
}

func requirePublishedLogo(t *testing.T, party clientmodels.TrustedParty) {
	t.Helper()
	require.NotNil(t, party.Image, "a curated logo must reach the app")
	decoded, err := base64.StdEncoding.DecodeString(party.Image.Base64)
	require.NoError(t, err)

	resp, err := http.Get(publishedLogoURI)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	served, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, served, decoded, "the cached logo must be the bytes the publisher served")
	require.NotNil(t, party.Image.MimeType)
	require.Equal(t, "image/png", *party.Image.MimeType)
}
