//+build !local_tests

package myirmaserver

import (
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/assert"
)

func validConfWithEmail(t *testing.T) *Configuration {
	testdataPath := test.FindTestdataFolder(t)
	conf := validConf(t)
	conf.EmailServer = "localhost:1025"
	conf.DefaultLanguage = "en"
	conf.LoginEmailFiles = map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")}
	conf.LoginEmailSubject = map[string]string{"en": "testsubject"}
	conf.LoginEmailBaseURL = map[string]string{"en": "localhost:8000/test/"}
	conf.DeleteEmailFiles = map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")}
	conf.DeleteEmailSubject = map[string]string{"en": "testsubject"}
	conf.DeleteAccountFiles = map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")}
	conf.DeleteAccountSubject = map[string]string{"en": "testsubject"}
	return conf
}

func TestConfEmailValidation(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)

	conf := validConf(t)
	conf.DBType = DatabaseTypePostgres
	conf.DBConnstring = "postgresql://localhost:5432/test"
	_, err := New(conf)
	assert.NoError(t, err)

	_, err = New(validConfWithEmail(t))
	assert.NoError(t, err)

	conf = validConfWithEmail(t)
	conf.DBType = DatabaseTypePostgres
	conf.DBConnstring = "postgresql://localhost:54321/test"
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.EmailServer = "http://localhost:1025"
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.LoginEmailFiles = map[string]string{"en": filepath.Join(testdataPath, "invalidemailtemplate.html")}
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.LoginEmailFiles = map[string]string{}
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.LoginEmailSubject = map[string]string{}
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.LoginEmailBaseURL = map[string]string{}
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.DeleteEmailFiles = map[string]string{"de": filepath.Join(testdataPath, "emailtemplate.html")}
	_, err = New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.DeleteEmailSubject = map[string]string{"de": "testsubject"}
	_, err = New(conf)
	assert.Error(t, err)
}
