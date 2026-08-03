package client

import (
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/eudi/lote"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testhelpers"
	"github.com/stretchr/testify/require"
)

func TestProductionRecognizedLists_IsEmpty(t *testing.T) {
	// The wallet ships recognizing no trust list, so the medium rung is not
	// reachable in production yet and every rung comes from the certificate
	// channel. Filling this in is a deliberate act, not something a refactor
	// should be able to do by accident.
	require.Empty(t, productionRecognizedLists)
}

func TestWithRecognizedLists_ReplacesTheCompiledInSet(t *testing.T) {
	signer := lote.NewTestListSigner(t)
	server := lote.NewTestListServer(t)
	recognizedList := server.RecognizedList("yivi-test", signer)

	options := options{recognizedLists: productionRecognizedLists}
	WithRecognizedLists(recognizedList)(&options)

	require.Equal(t, []lote.RecognizedList{recognizedList}, options.recognizedLists)
}

func TestNew_WithRecognizedLists(t *testing.T) {
	// The seam a session test uses: a wallet built pointing at a trust list it
	// serves itself.
	signer := lote.NewTestListSigner(t)
	server := lote.NewTestListServer(t)
	server.Serve(t, signer, lote.NewTestList(lote.TestListOpts{
		Id: "yivi-test",
		Providers: []lote.TrustServiceProvider{
			lote.GrantedVerifier("Listed Verifier", lote.DidIdentity("did:web:verifier.example.com")),
		},
	}))

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")

	c, err := New(
		storagePath,
		filepath.Join(path, "irma_configuration"),
		filepath.Join(storagePath, "eudi"),
		&testhelpers.TestClientHandler{},
		nil,
		test.NewSigner(t),
		aesKey,
		"en",
		WithRecognizedLists(server.RecognizedList("yivi-test", signer)),
	)
	require.NoError(t, err)
	defer c.Close()

	// Recognizing a list does not reach out for it. The lists are resolved when
	// a session pins its view, so starting the wallet does not wait on a trust
	// list endpoint — nor does an unreachable one delay startup.
	require.Equal(t, int64(0), server.Hits())
}
