package client

import (
	"context"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testhelpers"
	"github.com/stretchr/testify/require"
)

const testTrustListId = "urn:yivi:trustlist:client-test"

// These tests go through the real client wiring — the construction seam, the
// SQLCipher-backed document store, the trust models the list signature is
// checked against — rather than around it, because what they are about is that
// the pieces are connected, not what the lote package decides.

// newClientWithTrustLists builds a client whose recognized-list set is the
// given one, at a storage path the caller supplies so a second client can be
// built over the same data. The signer's root is installed as an issuer trust anchor,
// which is where the wallet looks for the key a list signature has to chain to.
func newClientWithTrustLists(t *testing.T, storagePath string, signer *lote.TestLoteSigner, sources []lote.Source) *Client {
	t.Helper()

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	eudiAppDataPath := filepath.Join(storagePath, "eudi")
	issuerCertsPath := filepath.Join(eudiAppDataPath, "issuers", "certificates")
	require.NoError(t, common.EnsureDirectoryExists(issuerCertsPath))

	// The EUDI filesystem storage decrypts what it reads, so the anchor has to
	// go in encrypted.
	rootPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.RootCert.Raw})
	encrypted, err := encryption.NewAESEncryptionMiddleware(aesKey).Encrypt(rootPem)
	require.NoError(t, err)
	require.NoError(t, common.SaveFile(filepath.Join(issuerCertsPath, "lote-test-root.pem"), encrypted))

	c, err := NewWithRecognizedTrustLists(
		storagePath,
		filepath.Join(test.FindTestdataFolder(t), "irma_configuration"),
		eudiAppDataPath,
		&testhelpers.TestClientHandler{T: t},
		nil,
		test.NewSigner(t),
		aesKey,
		"en",
		sources,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// verifierLevel is the rung the wallet would put a bare DID verifier on right
// now, taken through the same evaluator a session uses.
func verifierLevel(c *Client, did string) clientmodels.TrustLevel {
	return c.trustService.
		Snapshot(context.Background()).
		Verifier(trust.Evidence{Identifiers: []string{did}}).
		Level
}

func TestClient_RefreshTrustLists_ListedVerifierRanksMedium(t *testing.T) {
	const did = "did:web:verifier.example.com"

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed BV", "", lote.NewTestDidService(lote.ServiceTypeVerifier, did))))

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	c := newClientWithTrustLists(t, storagePath, signer, []lote.Source{server.Source(testTrustListId, false)})

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
		lote.NewTestEntity("Listed BV", "", lote.NewTestDidService(lote.ServiceTypeVerifier, did))))
	source := server.Source(testTrustListId, false)

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	first := newClientWithTrustLists(t, storagePath, signer, []lote.Source{source})
	require.NoError(t, first.RefreshTrustLists(context.Background()))
	require.NoError(t, first.Close())

	// A second wallet over the same storage, with the publisher gone: what it
	// knows about the verifier has to come off disk.
	server.Close()
	second := newClientWithTrustLists(t, storagePath, signer, []lote.Source{source})

	require.Equal(t, clientmodels.TrustLevel_Medium, verifierLevel(second, did))
}

func TestClient_UnreachableTrustList_LeavesTheWalletUsable(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	source := server.Source(testTrustListId, false)
	server.Close()

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	c := newClientWithTrustLists(t, storagePath, signer, []lote.Source{source})

	// The refresh reports the failure to whoever asked for it, and the wallet
	// carries on ranking parties by the channels it does have.
	require.Error(t, c.RefreshTrustLists(context.Background()))
	require.Equal(t, clientmodels.TrustLevel_Low, verifierLevel(c, "did:web:verifier.example.com"))
}

func TestClient_NoRecognizedLists_RefreshHasNothingToDo(t *testing.T) {
	// What a released wallet does today: ProductionSources is empty, so the
	// list channel contributes nothing and a refresh has nothing to fail at.
	require.Empty(t, lote.ProductionSources)

	signer := lote.NewTestLoteSigner(t)
	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	c := newClientWithTrustLists(t, storagePath, signer, nil)

	require.NoError(t, c.RefreshTrustLists(context.Background()))
	require.Equal(t, clientmodels.TrustLevel_Low, verifierLevel(c, "did:web:verifier.example.com"))
}

func TestClient_RefreshTrustLists_MarkedOnYivisListRanksHigh(t *testing.T) {
	const did = "did:web:verifier.example.com"

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed BV", "",
			lote.NewTestDidService(lote.ServiceTypeVerifier, did, lote.MarkingOnboardedByYivi))))

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	// The same list, once as Yivi's own and once as another operator's: the
	// marking is the same bytes on the wire, and only the first is Yivi's word.
	yivis := newClientWithTrustLists(t, storagePath, signer, []lote.Source{server.Source(testTrustListId, true)})
	require.NoError(t, yivis.RefreshTrustLists(context.Background()))

	require.Equal(t, clientmodels.TrustLevel_High, verifierLevel(yivis, did))

	othersPath := filepath.Join(test.CreateTestStorage(t), "client")
	others := newClientWithTrustLists(t, othersPath, signer, []lote.Source{server.Source(testTrustListId, false)})
	require.NoError(t, others.RefreshTrustLists(context.Background()))

	require.Equal(t, clientmodels.TrustLevel_Medium, verifierLevel(others, did),
		"another operator marking a party as onboarded by Yivi is not Yivi vouching for it")
}
