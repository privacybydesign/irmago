package client

import (
	"context"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testhelpers"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const testTrustListId = "urn:yivi:trustlist:client-test"

// These tests go through the real client wiring — the construction seam, the
// SQLCipher-backed document store, the trust models the list signature is checked
// against — because what they are about is that the pieces are connected.

// newClientWithTrustLists builds a client whose recognized-list set is the given
// one, at a caller-supplied storage path so a second client can be built over the
// same data. The signer's root is installed as an issuer trust anchor.
func newClientWithTrustLists(t *testing.T, storagePath string, signer *lote.TestLoteSigner, sources []lote.Source) *Client {
	t.Helper()
	c, _ := newClientWithTrustListsAndHandler(t, storagePath, signer, sources)
	return c
}

// newClientWithTrustLists, handing back the app-facing handler so a test can count
// how often the wallet woke the app.
func newClientWithTrustListsAndHandler(
	t *testing.T,
	storagePath string,
	signer *lote.TestLoteSigner,
	sources []lote.Source,
) (*Client, *testhelpers.TestClientHandler) {
	t.Helper()

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	eudiAppDataPath := filepath.Join(storagePath, "eudi")

	// The list signer's root goes in the trustlists container, not the issuers
	// one: a certificate that may issue credentials must not thereby be able to
	// define who is trusted.
	trustListCertsPath := filepath.Join(eudiAppDataPath, "trustlists", "certificates")
	require.NoError(t, common.EnsureDirectoryExists(trustListCertsPath))

	// The EUDI filesystem storage decrypts what it reads, so the anchor has to
	// go in encrypted.
	rootPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.RootCert.Raw})
	encrypted, err := encryption.NewAESEncryptionMiddleware(aesKey).Encrypt(rootPem)
	require.NoError(t, err)
	require.NoError(t, common.SaveFile(filepath.Join(trustListCertsPath, "lote-test-root.pem"), encrypted))

	handler := &testhelpers.TestClientHandler{T: t}
	c, err := New(Config{
		StoragePath:           storagePath,
		IrmaConfigurationPath: filepath.Join(test.FindTestdataFolder(t), "irma_configuration"),
		EudiAppDataPath:       eudiAppDataPath,
		Handler:               handler,
		Signer:                test.NewSigner(t),
		AesKey:                aesKey,
		Locale:                "en",
		RecognizedTrustLists:  sources,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c, handler
}

// verifierLevel is the rung the wallet would put a bare DID verifier on right
// now, taken through the same evaluator a session uses.
func verifierLevel(c *Client, did string) clientmodels.TrustLevel {
	return c.trustService.
		Snapshot().
		Verifier(trust.Evidence{Identifiers: []string{did}}).
		Level
}

func TestClient_RefreshTrustLists_ListedVerifierRanksMedium(t *testing.T) {
	const did = "did:web:verifier.example.com"

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed BV", "", lote.NewTestDidService(trust.RoleVerifier, did))))

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	c := newClientWithTrustLists(t, storagePath, signer, []lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_Medium)})

	require.Equal(t, clientmodels.TrustLevel_Low, verifierLevel(c, did),
		"a wallet that has not fetched a list yet vouches for nobody")

	require.NoError(t, c.RefreshTrustLists(context.Background()))

	require.Equal(t, clientmodels.TrustLevel_Medium, verifierLevel(c, did))
}

func TestClient_TrustListSurvivesARestart(t *testing.T) {
	const did = "did:web:verifier.example.com"

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed BV", "", lote.NewTestDidService(trust.RoleVerifier, did))))
	source := server.Source(testTrustListId, clientmodels.TrustLevel_Medium)

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	first := newClientWithTrustLists(t, storagePath, signer, []lote.Source{source})
	require.NoError(t, first.RefreshTrustLists(context.Background()))
	require.NoError(t, first.Close())

	// A second wallet over the same storage, publisher gone: everything comes off
	// disk.
	server.Close()
	second := newClientWithTrustLists(t, storagePath, signer, []lote.Source{source})

	require.Equal(t, clientmodels.TrustLevel_Medium, verifierLevel(second, did))
}

func TestClient_UnreachableTrustList_LeavesTheWalletUsable(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	source := server.Source(testTrustListId, clientmodels.TrustLevel_Medium)
	server.Close()

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	c := newClientWithTrustLists(t, storagePath, signer, []lote.Source{source})

	// Reported to the caller; the wallet carries on with the channels it has.
	require.Error(t, c.RefreshTrustLists(context.Background()))
	require.Equal(t, clientmodels.TrustLevel_Low, verifierLevel(c, "did:web:verifier.example.com"))
}

func TestClient_NoRecognizedLists_RefreshHasNothingToDo(t *testing.T) {
	// What a released wallet does today: no recognized lists, so a refresh has
	// nothing to fail at.
	signer := lote.NewTestLoteSigner(t)
	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	c := newClientWithTrustLists(t, storagePath, signer, nil)

	require.NoError(t, c.RefreshTrustLists(context.Background()))
	require.Equal(t, clientmodels.TrustLevel_Low, verifierLevel(c, "did:web:verifier.example.com"))
}

func TestClient_RefreshTrustLists_ListingConfersTheSourcesLevel(t *testing.T) {
	const did = "did:web:verifier.example.com"

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed BV", "",
			lote.NewTestDidService(trust.RoleVerifier, did))))

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	// The same list, once configured as Yivi's own and once as another operator's:
	// identical bytes, and the rung is the source's word.
	yivis := newClientWithTrustLists(t, storagePath, signer,
		[]lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_High)})
	require.NoError(t, yivis.RefreshTrustLists(context.Background()))

	require.Equal(t, clientmodels.TrustLevel_High, verifierLevel(yivis, did))

	othersPath := filepath.Join(test.CreateTestStorage(t), "client")
	others := newClientWithTrustLists(t, othersPath, signer,
		[]lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_Medium)})
	require.NoError(t, others.RefreshTrustLists(context.Background()))

	require.Equal(t, clientmodels.TrustLevel_Medium, verifierLevel(others, did),
		"a list that is not Yivi's own confers the level its source declares")
}

// ----------------------------------------------------------------------------
// Transitions on stored credentials
// ----------------------------------------------------------------------------

// seedBatchWithoutIssuerEvidence stores a batch the way a version before the
// trust ladder did: only the issuer identifier, no certificate. Those batches
// must still rank through the list channel.
func seedBatchWithoutIssuerEvidence(t *testing.T, gdb *gorm.DB, issuer string) {
	t.Helper()

	now := time.Now().UTC()
	require.NoError(t, gdb.Create(&models.CredentialBatch{
		IssuerIdentifier:           issuer,
		CredentialIssuerIdentifier: issuer,
		VerifiableCredentialType:   "https://vct.example/pre-feature",
		Format:                     models.CredentialFormatSdJwtVc,
		Hash:                       "pre-feature-batch",
		ProcessedSdJwtPayload:      datatypes.JSON(`{"sub":"u"}`),
		IssuedAt:                   datatypes.NullTime{V: now.Truncate(time.Second), Valid: true},
		BatchSize:                  1,
		RemainingCount:             1,
		Instances:                  []models.IssuedCredentialInstance{{RawCredential: []byte("raw")}},
	}).Error)
}

// storedIssuerLevel is the rung the credential list puts a stored credential's
// issuer on right now — the read the transition behaviour is about.
func storedIssuerLevel(t *testing.T, c *Client) clientmodels.TrustLevel {
	t.Helper()
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	return creds[0].Issuer.TrustLevel
}

// TestStoredCredentialIssuerRanksAtRead pins evaluate-at-read: the wallet stores
// what it knew about the issuer, not the rung it gave it, so the same credential
// listed after the list changed shows the rung the list says now. The batch here
// carries no certificate, as a pre-ladder one would, so it ranks through the list
// channel alone.
func TestStoredCredentialIssuerRanksAtRead(t *testing.T) {
	const issuer = "did:web:issuer.example.com"

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	listed := lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed Issuer BV", "", lote.NewTestDidService(trust.RoleIssuer, issuer)))
	server.Serve(t, signer, listed)

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	c := newClientWithTrustLists(t, storagePath, signer, []lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_Medium)})
	seedBatchWithoutIssuerEvidence(t, c.eudiStorage.Db(), issuer)

	require.Equal(t, clientmodels.TrustLevel_Low, storedIssuerLevel(t, c),
		"before any list is fetched nobody vouches for the issuer")

	require.NoError(t, c.RefreshTrustLists(context.Background()))
	require.Equal(t, clientmodels.TrustLevel_Medium, storedIssuerLevel(t, c),
		"the issuer is granted on a recognized list, so the stored credential promotes on the next read")

	// Delisted: the entry is gone from a newer issue of the same list.
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 2))
	require.NoError(t, c.RefreshTrustLists(context.Background()))
	require.Equal(t, clientmodels.TrustLevel_Low, storedIssuerLevel(t, c),
		"a delisted issuer demotes on the next read, without a migration")
}

// TestTrustListRefreshNotifiesOnContentChange pins the line between a change and
// a re-confirmation: a list saying something different about the parties on it
// wakes the app once, a re-issue saying the same thing stays silent.
func TestTrustListRefreshNotifiesOnContentChange(t *testing.T) {
	const issuer = "did:web:issuer.example.com"

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	entity := lote.NewTestEntity("Listed Issuer BV", "", lote.NewTestDidService(trust.RoleIssuer, issuer))
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1, entity))

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	c, handler := newClientWithTrustListsAndHandler(t, storagePath, signer,
		[]lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_Medium)})

	// The first fetch is not a change: the app was showing no verdict from this
	// list.
	require.NoError(t, c.RefreshTrustLists(context.Background()))
	require.Equal(t, 0, handler.CredentialsChangedCount(), "adopting a list for the first time is silent")

	// A re-issue of the same entries: fresh next_update, new sequence number, new
	// signature, nothing new said about anybody.
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 2, entity))
	require.NoError(t, c.RefreshTrustLists(context.Background()))
	require.Equal(t, 0, handler.CredentialsChangedCount(), "a re-sign with identical entries wakes nobody")

	// The entry is withdrawn. Rebuilt through the same builder as the granted
	// entity, so the withdrawal is the only difference between the two issues.
	withdrawnService := lote.NewTestDidService(trust.RoleIssuer, issuer)
	withdrawnService.Information.Status = lote.ServiceStatusWithdrawn
	withdrawn := lote.NewTestEntity("Listed Issuer BV", "", withdrawnService)
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 3, withdrawn))
	require.NoError(t, c.RefreshTrustLists(context.Background()))
	require.Equal(t, 1, handler.CredentialsChangedCount(), "an entry content change wakes the app exactly once")

	// And once is once: fetching the same content again is a re-confirmation.
	require.NoError(t, c.RefreshTrustLists(context.Background()))
	require.Equal(t, 1, handler.CredentialsChangedCount(), "re-confirming the changed list does not wake it again")
}
