package testkeyshare

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
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

type keyshareServer struct {
	http.Server
	t *testing.T
}

func StartKeyshareServer(t *testing.T, l *logrus.Logger, schemeID irma.SchemeManagerIdentifier) *keyshareServer {
	db := keyshareserver.NewMemoryDB()
	err := db.AddUser(&keyshareserver.User{
		Username: "",
		Secrets:  keysharecore.UserSecrets{},
	})
	require.NoError(t, err)
	secrets, err := base64.StdEncoding.DecodeString("YWJjZBdd6z/4lW/JBgEjVxcAnhK16iimfeyi1AAtWPzkfbWYyXHAad8A+Xzc6mE8bMj6dMQ5CgT0xcppEWYN9RFtO5+Wv4Carfq3TEIX9IWEDuU+lQG0noeHzKZ6k1J22iNAiL7fEXNWNy2H7igzJbj6svbH2LTRKxEW2Cj9Qkqzip5UapHmGZf6G6E7VkMvmJsbrW5uoZAVq2vP+ocuKmzBPaBlqko9F0YKglwXyhfaQQQ0Y3x4secMwC12")
	require.NoError(t, err)
	err = db.AddUser(&keyshareserver.User{
		Username: "testusername",
		Secrets:  secrets,
	})
	require.NoError(t, err)

	testdataPath := test.FindTestdataFolder(t)
	schemesPath := filepath.Join(testdataPath, "irma_configuration")
	conf, err := irma.NewConfiguration(schemesPath, irma.ConfigurationOptions{})
	require.NoError(t, err)
	err = conf.ParseFolder()
	require.NoError(t, err)
	parsedURL, err := url.Parse(conf.SchemeManagers[schemeID].KeyshareServer)
	require.NoError(t, err)

	keyshareAttr := irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.test.mijnirma.email", schemeID))
	s, err := keyshareserver.New(&keyshareserver.Configuration{
		Configuration: &server.Configuration{
			SchemesPath:           schemesPath,
			IssuerPrivateKeysPath: filepath.Join(testdataPath, "privatekeys"),
			Logger:                l,
			URL:                   parsedURL.String(),
		},
		DB:                    db,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareAttribute:     keyshareAttr,
	})
	require.NoError(t, err)

	keyshareServ := &keyshareServer{http.Server{
		Addr:    parsedURL.Host,
		Handler: s.Handler(),
	}, t}

	go func() {
		err := keyshareServ.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		assert.NoError(t, err)
	}()
	return keyshareServ
}

func (ks *keyshareServer) Stop() {
	err := ks.Shutdown(context.Background())
	assert.NoError(ks.t, err)
}
