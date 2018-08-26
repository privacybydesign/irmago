package sessiontest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Create HTTP server for scheme managers
	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()

	StartRequestorServer()
	defer StopRequestorServer()

	test.CreateTestStorage(nil)
	defer test.ClearTestStorage(nil)

	os.Exit(m.Run())
}

func parseStorage(t *testing.T) *irmaclient.Client {
	test.SetupTestStorage(t)
	path := test.FindTestdataFolder(t)
	client, err := irmaclient.New(
		filepath.Join(path, "storage", "test"),
		filepath.Join(path, "irma_configuration"),
		"",
		&TestClientHandler{t: t},
	)
	require.NoError(t, err)
	return client
}
