package myirma

import (
	"path/filepath"
	"testing"

	irma "github.com/privacybydesign/irmago"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/assert"
)

func TestConfValidation(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)

	_, err := New(&Configuration{
		SchemesPath:            filepath.Join(testdataPath, "irma_configuration"),
		URL:                    "http://localhost:8000/",
		DBType:                 DatabaseTypeMemory,
		SessionLifetime:        60,
		KeyshareAttributeNames: []string{"test.test.mijnirma.email"},
		EmailAttributeNames:    []string{"test.test.email.email"},
		Logger:                 irma.Logger,
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DBType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		Logger:             irma.Logger,
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DBType:             DatabaseTypeMemory,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		Logger:             irma.Logger,
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DBType:             DatabaseTypePostgres,
		DBConnstring:       "postgresql://localhost:5432/test/",
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		Logger:             irma.Logger,
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000",
		DBType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		Logger:             irma.Logger,
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:     filepath.Join(testdataPath, "irma_configuration"),
		URL:             "http://localhost:8000/",
		DBType:          DatabaseTypeMemory,
		SessionLifetime: 60,
		EmailAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		Logger:          irma.Logger,
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DBType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		Logger:             irma.Logger,
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000",
		DBType:             "UNKNOWN",
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		Logger:             irma.Logger,
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:          filepath.Join(testdataPath, "irma_configuration"),
		URL:                  "http://localhost:8000/",
		DBType:               DatabaseTypeMemory,
		SessionLifetime:      60,
		KeyshareAttributes:   []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:      []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:          "localhost:1025",
		DefaultLanguage:      "en",
		LoginEmailFiles:      map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		LoginEmailSubject:    map[string]string{"en": "testsubject"},
		LoginEmailBaseURL:    map[string]string{"en": "localhost:8000/test/"},
		DeleteEmailFiles:     map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteEmailSubject:   map[string]string{"en": "testsubject"},
		DeleteAccountFiles:   map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteAccountSubject: map[string]string{"en": "testsubject"},
		Logger:               irma.Logger,
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:          filepath.Join(testdataPath, "irma_configuration"),
		URL:                  "http://localhost:8000/",
		DBType:               DatabaseTypeMemory,
		SessionLifetime:      60,
		KeyshareAttributes:   []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:      []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:          "localhost:1025",
		DefaultLanguage:      "en",
		LoginEmailFiles:      map[string]string{"en": filepath.Join(testdataPath, "invalidemailtemplate.html")},
		LoginEmailSubject:    map[string]string{"en": "testsubject"},
		LoginEmailBaseURL:    map[string]string{"en": "localhost:8000/test/"},
		DeleteEmailFiles:     map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteEmailSubject:   map[string]string{"en": "testsubject"},
		DeleteAccountFiles:   map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteAccountSubject: map[string]string{"en": "testsubject"},
		Logger:               irma.Logger,
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:          filepath.Join(testdataPath, "irma_configuration"),
		URL:                  "http://localhost:8000/",
		DBType:               DatabaseTypeMemory,
		SessionLifetime:      60,
		KeyshareAttributes:   []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:      []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:          "localhost:1025",
		DefaultLanguage:      "en",
		LoginEmailFiles:      map[string]string{},
		LoginEmailSubject:    map[string]string{"en": "testsubject"},
		LoginEmailBaseURL:    map[string]string{"en": "localhost:8000/test/"},
		DeleteEmailFiles:     map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteEmailSubject:   map[string]string{"en": "testsubject"},
		DeleteAccountFiles:   map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteAccountSubject: map[string]string{"en": "testsubject"},
		Logger:               irma.Logger,
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:          filepath.Join(testdataPath, "irma_configuration"),
		URL:                  "http://localhost:8000/",
		DBType:               DatabaseTypeMemory,
		SessionLifetime:      60,
		KeyshareAttributes:   []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:      []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:          "localhost:1025",
		DefaultLanguage:      "en",
		LoginEmailFiles:      map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		LoginEmailSubject:    map[string]string{},
		LoginEmailBaseURL:    map[string]string{"en": "localhost:8000/test/"},
		DeleteEmailFiles:     map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteEmailSubject:   map[string]string{"en": "testsubject"},
		DeleteAccountFiles:   map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteAccountSubject: map[string]string{"en": "testsubject"},
		Logger:               irma.Logger,
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:          filepath.Join(testdataPath, "irma_configuration"),
		URL:                  "http://localhost:8000/",
		DBType:               DatabaseTypeMemory,
		SessionLifetime:      60,
		KeyshareAttributes:   []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:      []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:          "localhost:1025",
		DefaultLanguage:      "en",
		LoginEmailFiles:      map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		LoginEmailSubject:    map[string]string{"en": "testsubject"},
		LoginEmailBaseURL:    map[string]string{},
		DeleteEmailFiles:     map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteEmailSubject:   map[string]string{"en": "testsubject"},
		DeleteAccountFiles:   map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteAccountSubject: map[string]string{"en": "testsubject"},
		Logger:               irma.Logger,
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:          filepath.Join(testdataPath, "irma_configuration"),
		URL:                  "http://localhost:8000/",
		DBType:               DatabaseTypeMemory,
		SessionLifetime:      60,
		KeyshareAttributes:   []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:      []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:          "localhost:1025",
		DefaultLanguage:      "en",
		LoginEmailFiles:      map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		LoginEmailSubject:    map[string]string{"en": "testsubject"},
		LoginEmailBaseURL:    map[string]string{"en": "localhost:8000/test/"},
		DeleteEmailFiles:     map[string]string{"de": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteEmailSubject:   map[string]string{"en": "testsubject"},
		DeleteAccountFiles:   map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteAccountSubject: map[string]string{"en": "testsubject"},
		Logger:               irma.Logger,
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:          filepath.Join(testdataPath, "irma_configuration"),
		URL:                  "http://localhost:8000/",
		DBType:               DatabaseTypeMemory,
		SessionLifetime:      60,
		KeyshareAttributes:   []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:      []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:          "localhost:1025",
		DefaultLanguage:      "en",
		LoginEmailFiles:      map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		LoginEmailSubject:    map[string]string{"en": "testsubject"},
		LoginEmailBaseURL:    map[string]string{"en": "localhost:8000/test/"},
		DeleteEmailFiles:     map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteEmailSubject:   map[string]string{"de": "testsubject"},
		DeleteAccountFiles:   map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		DeleteAccountSubject: map[string]string{"en": "testsubject"},
		Logger:               irma.Logger,
	})
	assert.Error(t, err)
}
