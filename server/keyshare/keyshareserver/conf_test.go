package keyshareserver

import (
	"html/template"
	"path/filepath"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConf(t *testing.T) *Configuration {
	testdataPath := test.FindTestdataFolder(t)
	return &Configuration{
		Configuration: &server.Configuration{
			SchemesPath: filepath.Join(testdataPath, "irma_configuration"),
			Logger:      irma.Logger,
		},
		KeyshareURL:           "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
	}
}

func validConfWithEmail(t *testing.T) *Configuration {
	conf := validConf(t)
	conf.EmailServer = "doesnotexist"
	conf.DefaultLanguage = "en"
	return conf
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

	conf = validConfWithEmail(t)
	conf.RegistrationEmailSubject = map[string]string{
		"en": "testsubject",
	}
	conf.VerificationURL = map[string]string{
		"en": "test",
	}
	_, err = New(conf)
	assert.Error(t, err)

	testTemplate := template.New("test")
	_, err = testTemplate.Parse("testtemplate {{.VerificationURL}}")
	require.NoError(t, err)

	conf = validConfWithEmail(t)
	conf.RegistrationEmailTemplates = map[string]*template.Template{
		"en": testTemplate,
	}
	conf.VerificationURL = map[string]string{
		"en": "test",
	}
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.RegistrationEmailTemplates = map[string]*template.Template{
		"en": testTemplate,
	}
	conf.RegistrationEmailSubject = map[string]string{
		"en": "testsubject",
	}
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.RegistrationEmailTemplates = map[string]*template.Template{
		"en": testTemplate,
	}
	conf.RegistrationEmailSubject = map[string]string{
		"en": "testsubject",
	}
	conf.VerificationURL = map[string]string{
		"en": "test",
	}
	_, err = New(conf)
	assert.NoError(t, err)

	conf = validConfWithEmail(t)
	conf.RegistrationEmailFiles = map[string]string{
		"en": filepath.Join(testdataPath, "does-not-exist"),
	}
	conf.RegistrationEmailSubject = map[string]string{
		"en": "testsubject",
	}
	conf.VerificationURL = map[string]string{
		"en": "test",
	}
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.RegistrationEmailFiles = map[string]string{
		"en": filepath.Join(testdataPath, "emailtemplate.html"),
	}
	conf.RegistrationEmailSubject = map[string]string{
		"en": "testsubject",
	}
	conf.VerificationURL = map[string]string{
		"en": "test",
	}
	_, err = New(conf)
	assert.NoError(t, err)

	conf = validConfWithEmail(t)
	conf.RegistrationEmailFiles = map[string]string{
		"en": filepath.Join(testdataPath, "invalidemailtemplate.html"),
	}
	conf.RegistrationEmailSubject = map[string]string{
		"en": "testsubject",
	}
	conf.VerificationURL = map[string]string{
		"en": "test",
	}
	_, err = New(conf)
	assert.Error(t, err)
}
