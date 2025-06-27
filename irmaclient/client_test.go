package irmaclient

import (
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestInstantiateNewEmptyClient(t *testing.T) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")

	client, err := New(storagePath, irmaConfigurationPath, &TestClientHandler{}, test.NewSigner(t), aesKey)

	require.NoError(t, err)

	credentials := client.CredentialInfoList()
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

	client, err := New(storagePath, irmaConfigurationPath, &TestClientHandler{}, test.NewSigner(t), aesKey)

	require.NoError(t, err)

	credentials := client.CredentialInfoList()
	require.NotEmpty(t, credentials)

	client.GetIrmaConfiguration()
}
