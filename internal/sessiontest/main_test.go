package sessiontest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Create HTTP server for scheme managers
	test.StartSchemeManagerHttpServer()

	test.ClearTestStorage(nil)
	test.CreateTestStorage(nil)
	retCode := m.Run()
	test.ClearTestStorage(nil)

	test.StopSchemeManagerHttpServer()
	os.Exit(retCode)
}

func parseStorage(t *testing.T) *irmaclient.Client {
	path := test.FindTestdataFolder(t)
	require.NoError(t, fs.CopyDirectory(filepath.Join(path, "teststorage"), filepath.Join(path, "storage", "test")))
	client, err := irmaclient.New(
		filepath.Join(path, "storage", "test"),
		filepath.Join(path, "irma_configuration"),
		"",
		&TestClientHandler{t: t},
	)
	require.NoError(t, err)
	return client
}
