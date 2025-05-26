package irmaclient

import (
	"os"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func TestStoringSdJwtVc(t *testing.T) {
	defer os.Remove("/tmp/sdjwtvc.db")

	db, err := bbolt.Open("/tmp/sdjwtvc.db", 0600, &bbolt.Options{Timeout: 1 * time.Second})
	require.NoError(t, err)

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	storage := NewBBoltSdJwtVcStorage(db, aesKey)

	sdjwt, err := createSdJwtVc("pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})
	require.NoError(t, err)
	info, err := createCredentialInfoFromSdJwtVc(sdjwt)
	require.NoError(t, err)
	err = storage.StoreCredentials(*info, []sdjwtvc.SdJwtVc{sdjwt})
	require.NoError(t, err)

	result := storage.GetCredentialsForId("pbdf.pbdf.email")
	require.Equal(t, len(result), 1)

	first := result[0]
	require.Equal(t, first.Info, *info)
}
