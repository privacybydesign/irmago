package sessiontest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/require"
)

// The recognized-list channel against a **real published list**: the compose
// LoTE publisher (testdata/lote-publisher), which signs with the openssl CLI
// rather than the JWS library the wallet verifies with, served over TLS through
// the same nginx proxy as the other EUDI services.
//
// # Which mechanism does a new trust-level test belong to?
//
//	Needs a real fetch, TLS, a restart, the passage of time, or a downloaded
//	asset → write it here, against the published list. Otherwise → in-process,
//	in trust_levels_test.go. Needs to know how many times the list was fetched →
//	in-process only, because lote.TestLoteServer.Hits() is the only mechanism
//	that can see a fetch happen.
//
// The two mechanisms are therefore not two ways of doing one thing: the
// publisher deliberately has no fetch-count route, and the in-process server
// cannot be on the other side of a restart. Tamper and sequence-regress
// coverage stays in-process permanently — an invalid document is invalid
// whoever signed it, so a foreign signer adds no signal there.
//
// Specified in docs/plans/lote-e2e-tests.md.

const (
	// publishedListURL is the publisher's public origin, through the tls_proxy.
	publishedListURL = "https://localhost:8446"

	// publishedListId must equal the LOTE_LIST_ID the compose service declares:
	// the wallet refuses a document whose list_identifier is not the one its
	// source expects.
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

// testPublishedListGrants is this suite's tracer. Everything else here
// depends on it: a list signed by the openssl CLI, assembled by hand, fetched
// over TLS from a service the test does not share a process with, is verified by
// the wallet and lifts the issuer it grants to the level the source confers —
// high, because the publisher stands in for Yivi's own LoTE — in a real session.
//
// If this fails, the finding is about the wallet or about
// docs/plans/yivi-lote-publishing.md — not about the test.
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

// testPublishedListExpiresWhileHeld is the passage of time, which no in-process
// server can stand on the other side of: a list the wallet has already adopted
// stops being evidence when it crosses its next_update, and the parties it
// granted fall back to what the other channels say.
//
// The list is published dated just inside the skew window, so the fetch accepts
// it and it goes stale seconds later — see skewBoundaryOffset. Waiting out the
// full three-minute window would prove exactly the same thing.
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

// testScheduledRefreshWakesTheAppOnce covers the background job: the wallet
// notices a list whose entries changed without anyone asking it to, and tells the
// app exactly once — while a re-confirmation of the same content stays silent.
func testScheduledRefreshWakesTheAppOnce(t *testing.T) {
	publishList(t, 1, publishedNextUpdateDefault, listedIssuerEntity("Scheduled BV"))

	c, clientHandler, _ := newPublishedListClient(t)
	defer c.Close()

	// A short trust-list interval; the CRL job is parked an hour out and the
	// status sweep off, so this is the only thing on the schedule.
	c.InitJobs(time.Hour, 0, 2*time.Second)

	// The first, immediate run adopts the list. Adopting is not a change: the app
	// was showing no verdict from this list before.
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

// testSessionCompletesWhilePublisherIsDark is fail-soft where it matters most: a
// wallet holding a valid copy is fully functional with the publisher gone. The
// refresh reports the outage to its caller and nothing else changes.
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

// testRestartedWalletRanksFromDisk is the other side of the same guarantee: the
// signed document itself survives a restart, and is re-verified against the
// anchors in force when it is read. The publisher is dark for the second wallet's
// whole life, so nothing it ranks can have come off the wire.
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

// testCuratedDisplayBeatsAttested is the display precedence and certificate keying
// in one session, because they are the same session: a certificate-bearing party
// is high whether or not a list grants it, so the *only* way to see that a
// certificate-keyed entry matched is the curated display it attaches.
//
// The EUDI Kotlin verifier is the party for it. It authenticates with a Yivi
// certificate whose extension carries an attested name ("Yivi B.V.") *and* an
// attested logo — the only party in the compose stack that has both — so it is
// the only place the rule "curated beats attested" can be exercised for a logo at
// all. The entry keys on its subject key identifier plus the
// organizationIdentifier its subject carries: the certificate says which key, the
// organization identifier says whose, and a match needs both.
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

// listedVerifierEntity grants the EUDI Kotlin verifier, keyed on the subject key
// identifier of its committed signing leaf plus the organizationIdentifier that
// leaf's subject carries. Both halves are read from the certificate rather than
// hardcoded, so regenerating the material cannot leave the entry silently stale.
func listedVerifierEntity(t *testing.T, name string) map[string]any {
	t.Helper()
	leaf := eudiVerifierLeaf(t)

	return map[string]any{
		"name":                    map[string]string{"en": name},
		"logo_uri":                publishedLogoURI,
		"organization_identifier": subjectOrganizationIdentifier(t, leaf),
		"services": []map[string]any{{
			"type":             "verifier",
			"status":           "granted",
			"digital_identity": map[string]any{"x509_ski": leaf.SubjectKeyId},
		}},
	}
}

// eudiVerifierLeaf parses the committed certificate the EUDI Kotlin verifier
// signs its authorization requests with.
func eudiVerifierLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	leafPem, err := os.ReadFile(filepath.Join(testdataFolder, "eudi", "verifier", "verifier.crt"))
	require.NoError(t, err)
	block, _ := pem.Decode(leafPem)
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return leaf
}

// subjectOrganizationIdentifier reads the X.520 organizationIdentifier attribute
// (2.5.4.97) out of a subject. Go's pkix.Name has no field for it.
func subjectOrganizationIdentifier(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	oid := asn1.ObjectIdentifier{2, 5, 4, 97}
	for _, attr := range cert.Subject.Names {
		if attr.Type.Equal(oid) {
			value, ok := attr.Value.(string)
			require.True(t, ok)
			return value
		}
	}
	t.Fatalf("certificate subject carries no organizationIdentifier; re-run testdata/eudi/verifier/gen-cert-chain.sh")
	return ""
}

// issuerLevelOfOffer drives a pre-authorized issuance to the permission screen,
// reads the issuer's rung off it, and dismisses the session — the cheapest real
// session that shows what the wallet currently thinks of the test issuer.
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

// newPublishedListClient builds a wallet whose one recognized list is the
// compose publisher's, with the publisher's root installed as an issuer trust
// anchor — where the wallet looks for the key a list signature must chain to.
func newPublishedListClient(t *testing.T) (*client.Client, *irmaclient.MockClientHandler, *MockSessionHandler) {
	t.Helper()
	return newPublishedListClientAt(t, filepath.Join(test.CreateTestStorage(t), "client"))
}

// newPublishedListClientAt is newPublishedListClient at a storage path the
// caller supplies, so a second wallet can be built over the first one's data —
// which is how the restart scenario reads a list back off disk.
func newPublishedListClientAt(t *testing.T, storagePath string) (*client.Client, *irmaclient.MockClientHandler, *MockSessionHandler) {
	t.Helper()
	return instantiateClientAtPath(t, storagePath, nil, "en", publisherRoot(t),
		[]lote.Source{{ListId: publishedListId, URL: publishedListURL, Confers: clientmodels.TrustLevel_High}})
}

// publisherRoot reads the committed root the publisher's signing leaf chains to.
func publisherRoot(t *testing.T) *x509.Certificate {
	t.Helper()
	rootPem, err := os.ReadFile(filepath.Join(testdataFolder, "lote-publisher", "certs", "root.crt"))
	require.NoError(t, err)
	block, _ := pem.Decode(rootPem)
	require.NotNil(t, block, "publisher root must be PEM")
	root, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return root
}

// publishList replaces what the publisher serves. nextUpdateSeconds may be
// negative: the wallet treats a list as current while
// now - lote.ClockSkew < next_update, so backdating to just inside that window
// is how a held list is made to expire in seconds rather than in three minutes.
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

// darkenPublisher makes the publisher answer 503 until the next publish, which
// is how the offline scenarios take the list away without stopping a container
// the rest of the suite shares.
func darkenPublisher(t *testing.T) {
	t.Helper()
	resp, err := http.Post(publishedListURL+"/admin/dark", "application/json", bytes.NewReader([]byte("{}")))
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// listedIssuerEntity grants the veramo OpenID4VCI test issuer, keyed on the DID
// it signs its credentials with.
func listedIssuerEntity(name string, markings ...string) map[string]any {
	return map[string]any{
		"name":     map[string]string{"en": name},
		"logo_uri": publishedLogoURI,
		"services": []map[string]any{{
			"type":             "issuer",
			"status":           "granted",
			"markings":         markings,
			"digital_identity": map[string]any{"other_ids": []map[string]string{{"type": "did", "value": testIssuerDid}}},
		}},
	}
}

// skewBoundaryOffset is a next_update offset that a fetch still accepts and that
// expires `within` afterwards. Derived from lote.ClockSkew rather than hardcoded:
// the wallet is current while now - ClockSkew < next_update, so a list dated
// ClockSkew-minus-a-few-seconds ago is accepted now and stale in a few seconds.
// If ClockSkew ever shrinks below `within`, the fetch rejects the list and the
// test fails loudly instead of quietly waiting forever.
func skewBoundaryOffset(within time.Duration) int {
	return -int((lote.ClockSkew - within) / time.Second)
}

// requirePublishedLogo asserts the party carries the logo the publisher served,
// byte for byte.
func requirePublishedLogo(t *testing.T, party clientmodels.TrustedParty) {
	t.Helper()
	require.NotNil(t, party.Image, "a curated logo must reach the app")
	decoded, err := base64.StdEncoding.DecodeString(party.Image.Base64)
	require.NoError(t, err)

	resp, err := http.Get(publishedLogoURI)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	served := make([]byte, 0, 128)
	buf := make([]byte, 128)
	for {
		n, readErr := resp.Body.Read(buf)
		served = append(served, buf[:n]...)
		if readErr != nil {
			break
		}
	}
	require.Equal(t, served, decoded, "the cached logo must be the bytes the publisher served")
	require.NotNil(t, party.Image.MimeType)
	require.Equal(t, "image/png", *party.Image.MimeType)
}
