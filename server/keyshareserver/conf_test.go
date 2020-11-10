package keyshareserver

import (
	"html/template"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfInvalidAESKey(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)

	_, err := New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk-does-not-exist.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey-does-not-exist"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                "undefined",
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
		EmailServer:           "doesnotexist",
		DefaultLanguage:       "en",
		RegistrationEmailSubject: map[string]string{
			"en": "testsubject",
		},
		VerificationURL: map[string]string{
			"en": "test",
		},
	})
	assert.Error(t, err)

	testTemplate := template.New("test")
	_, err = testTemplate.Parse("testtemplate {{.VerificationURL}}")
	require.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
		EmailServer:           "doesnotexist",
		DefaultLanguage:       "en",
		RegistrationEmailTemplates: map[string]*template.Template{
			"en": testTemplate,
		},
		VerificationURL: map[string]string{
			"en": "test",
		},
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
		EmailServer:           "doesnotexist",
		DefaultLanguage:       "en",
		RegistrationEmailTemplates: map[string]*template.Template{
			"en": testTemplate,
		},
		RegistrationEmailSubject: map[string]string{
			"en": "testsubject",
		},
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
		EmailServer:           "doesnotexist",
		DefaultLanguage:       "en",
		RegistrationEmailTemplates: map[string]*template.Template{
			"en": testTemplate,
		},
		RegistrationEmailSubject: map[string]string{
			"en": "testsubject",
		},
		VerificationURL: map[string]string{
			"en": "test",
		},
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
		EmailServer:           "doesnotexist",
		DefaultLanguage:       "en",
		RegistrationEmailFiles: map[string]string{
			"en": filepath.Join(testdataPath, "does-not-exist"),
		},
		RegistrationEmailSubject: map[string]string{
			"en": "testsubject",
		},
		VerificationURL: map[string]string{
			"en": "test",
		},
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
		EmailServer:           "doesnotexist",
		DefaultLanguage:       "en",
		RegistrationEmailFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		RegistrationEmailSubject: map[string]string{
			"en": "testsubject",
		},
		VerificationURL: map[string]string{
			"en": "test",
		},
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DBType:                DatabaseTypeMemory,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
		EmailServer:           "doesnotexist",
		DefaultLanguage:       "en",
		RegistrationEmailFiles: map[string]string{
			"en": filepath.Join(testdataPath, "invalidemailtemplate.html"),
		},
		RegistrationEmailSubject: map[string]string{
			"en": "testsubject",
		},
		VerificationURL: map[string]string{
			"en": "test",
		},
	})
	assert.Error(t, err)
}
