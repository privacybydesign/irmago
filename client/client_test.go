package client

import (
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testhelpers"
	"github.com/stretchr/testify/require"
)

func TestInstantiateNewEmptyClient(t *testing.T) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")

	client, err := New(storagePath, irmaConfigurationPath, &testhelpers.TestClientHandler{}, nil, test.NewSigner(t), aesKey)
	require.NoError(t, err)
	defer client.Close()

	credentials, err := client.GetCredentials()
	require.NoError(t, err)
	require.Empty(t, credentials)

	client.GetIrmaConfiguration()
}

func TestInstantiateClientWithExistingIrmaStorage(t *testing.T) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.SetupTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")

	client, err := New(storagePath, irmaConfigurationPath, &testhelpers.TestClientHandler{}, nil, test.NewSigner(t), aesKey)
	require.NoError(t, err)
	defer client.Close()

	credentials, err := client.GetCredentials()
	require.NoError(t, err)
	require.NotEmpty(t, credentials)

	client.GetIrmaConfiguration()
}
