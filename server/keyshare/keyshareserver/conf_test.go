package keyshareserver

import (
	"path/filepath"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/assert"
)

func validConf(t *testing.T) *Configuration {
	testdataPath := test.FindTestdataFolder(t)
	return &Configuration{
		Configuration: &server.Configuration{
			SchemesPath: filepath.Join(testdataPath, "irma_configuration"),
			Logger:      irma.Logger,
		},
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareAttribute:     irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"),
	}
}

func TestConfInvalidAESKey(t *testing.T) {
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
	conf.JwtPrivateKeyFile = filepath.Join(testdataPath, "jwtkeys", "kss-sk-does-not-exist.pem")
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConf(t)
	conf.StoragePrimaryKeyFile = filepath.Join(testdataPath, "keyshareStorageTestkey-does-not-exist")
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConf(t)
	conf.StoragePrimaryKeyFile = filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem")
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConf(t)
	conf.DBType = "undefined"
	_, err = New(conf)
	assert.Error(t, err)
}
