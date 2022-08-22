package testkeyshare

import (
	"context"
	"encoding/base64"
	"net/http"
	"path/filepath"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare/keyshareserver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var keyshareServ *http.Server

func StartKeyshareServer(t *testing.T, l *logrus.Logger) {
	db := keyshareserver.NewMemoryDB()
	err := db.AddUser(&keyshareserver.User{
		Username: "",
		Secrets:  keysharecore.UserSecrets{},
	})
	require.NoError(t, err)
	secrets, err := base64.StdEncoding.DecodeString("YWJjZBdd6z/4lW/JBgEjVxcAnhK16iimfeyi1AAtWPzkfbWYyXHAad8A+Xzc6mE8bMj6dMQ5CgT0xcppEWYN9RFtO5+Wv4Carfq3TEIX9IWEDuU+lQG0noeHzKZ6k1J22iNAiL7fEXNWNy2H7igzJbj6svbH2LTRKxEW2Cj9Qkqzip5UapHmGZf6G6E7VkMvmJsbrW5uoZAVq2vP+ocuKmzBPaBlqko9F0YKglwXyhfaQQQ0Y3x4secMwC12")
	require.NoError(t, err)
	err = db.AddUser(&keyshareserver.User{
		Username: "legacyuser",
		Secrets:  secrets,
	})
	require.NoError(t, err)

	secrets, err = base64.StdEncoding.DecodeString("YWJjZHpSayGYcjcKbUNfJJjNOXxgxV+GWTVYinpeKqTSfUjUuT4+Hs2uZY68+KvnXkPkoV1eo4HvpVzxy683DHi8Ih+P4Nuqz4FhhLddFnZlzPn1sHuvSjs8S2qGP/jO5+3075I/TWiT2CxO8B83ezMX7tmlwvTbWdYbmV1saEyCVFssuzTARcfvee0f6YvFe9eX1iHfAwXvPsdrt0eTqbTcUzDzv5pQb/t18MtJsK6cB2vh3XJO0psbBWsshGNJYIkMaiGmhi457zejvIt1xcC+dsZZUJVpvoGrZvHd25gH9PLQ/VSU0atrhXS93nsdW8+Y4M4tDFZ8R9pZsseZKt4Zuj1FbxD/qZcdm2w8KaCQgVjzzJJu6//Z5/qF0Neycmm6uiAs4zQWVkibtR9BLEmwHsLd2u4n1EhPAzp14kyzI72/")
	require.NoError(t, err)
	err = db.AddUser(&keyshareserver.User{
		Username: "testusername",
		Secrets:  secrets,
	})
	require.NoError(t, err)

	testdataPath := test.FindTestdataFolder(t)
	s, err := keyshareserver.New(&keyshareserver.Configuration{
		Configuration: &server.Configuration{
			SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
			IssuerPrivateKeysPath: filepath.Join(testdataPath, "privatekeys"),
			Logger:                l,
			URL:                   "http://localhost:8080/",
		},
		DB:                    db,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareAttribute:     irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"),
	})
	require.NoError(t, err)

	keyshareServ = &http.Server{
		Addr:    "localhost:8080",
		Handler: s.Handler(),
	}

	go func() {
		err := keyshareServ.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		assert.NoError(t, err)
	}()
}

func StopKeyshareServer(t *testing.T) {
	err := keyshareServ.Shutdown(context.Background())
	assert.NoError(t, err)
}
