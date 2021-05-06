//+build !local_tests

package keyshareserver

import (
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/assert"
)

func validConfWithEmail(t *testing.T) *Configuration {
	conf := validConf(t)
	conf.EmailServer = "localhost:1025"
	conf.DefaultLanguage = "en"
	return conf
}

func TestEmailConfiguration(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)

	conf := validConfWithEmail(t)
	conf.RegistrationEmailSubject = map[string]string{
		"en": "testsubject",
	}
	conf.VerificationURL = map[string]string{
		"en": "test",
	}
	_, err := New(conf)
	assert.Error(t, err)

	conf = validConfWithEmail(t)
	conf.RegistrationEmailFiles = map[string]string{
		"en": filepath.Join(testdataPath, "emailtemplate.html"),
	}
	conf.RegistrationEmailSubject = map[string]string{
		"en": "testsubject",
	}
	_, err = New(conf)
	assert.Error(t, err)

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
