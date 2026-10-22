package keyshareserver

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConf(t *testing.T) *Configuration {
	testdataPath := test.FindTestdataFolder(t)
	return &Configuration{
		Configuration: &server.Configuration{
			SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
			IssuerPrivateKeysPath: filepath.Join(testdataPath, "privatekeys"),
			Logger:                irma.Logger,
		},
		DBType:                DBTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "test-kss-sk-0.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareAttribute:     irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"),
		EmailTokenValidity:    168,
	}
}

func TestConf(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)

	_, err := New(validConf(t))
	assert.NoError(t, err)

	conf := validConf(t)
	conf.JwtPrivateKeyFile = ""
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConf(t)
	conf.StoragePrimaryKeyFile = ""
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConf(t)
	conf.JwtPrivateKeyFile = filepath.Join(testdataPath, "jwtkeys", "test-kss-sk-does-not-exist.pem")
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConf(t)
	conf.StoragePrimaryKeyFile = filepath.Join(testdataPath, "keyshareStorageTestkey-does-not-exist")
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConf(t)
	conf.StoragePrimaryKeyFile = filepath.Join(testdataPath, "jwtkeys", "test-kss-sk-0.pem")
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConf(t)
	conf.DBType = "undefined"
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConf(t)
	conf.KeyshareAttribute = irma.NewAttributeTypeIdentifier("test.test.foo.bar")
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConf(t)
	conf.IssuerPrivateKeysPath = testdataPath // no private keys here
	_, err = New(conf)
	assert.Error(t, err)
}

func TestKeyshareAttributeValidity(t *testing.T) {
	issuedValidity := func(t *testing.T, s *Server) time.Time {
		req := s.keyshareAttributeIssuanceRequest("username")
		require.Len(t, req.Credentials, 1)
		require.NotNil(t, req.Credentials[0].Validity)
		return time.Time(*req.Credentials[0].Validity)
	}

	t.Run("defaults to one year", func(t *testing.T) {
		s, err := New(validConf(t))
		require.NoError(t, err)
		assert.Equal(t, 365, s.conf.KeyshareAttributeValidity)
		assert.WithinDuration(t, time.Now().AddDate(0, 0, 365), issuedValidity(t, s), time.Minute)
	})

	t.Run("configured number of days", func(t *testing.T) {
		conf := validConf(t)
		conf.KeyshareAttributeValidity = 30
		s, err := New(conf)
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().AddDate(0, 0, 30), issuedValidity(t, s), time.Minute)
	})

	t.Run("negative is rejected", func(t *testing.T) {
		conf := validConf(t)
		conf.KeyshareAttributeValidity = -1
		_, err := New(conf)
		assert.Error(t, err)
	})
}
