package myirmaserver

import (
	"path/filepath"
	"testing"

	irma "github.com/privacybydesign/irmago"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/assert"
)

func TestConfInvalidAESKey(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)

	_, err := New(&Configuration{
		SchemesPath:            filepath.Join(testdataPath, "irma_configuration"),
		URL:                    "http://localhost:8000/",
		DbType:                 DatabaseTypeMemory,
		SessionLifetime:        60,
		KeyshareAttributeNames: []string{"test.test.mijnirma.email"},
		EmailAttributeNames:    []string{"test.test.email.email"},
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DbType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DbType:             DatabaseTypeMemory,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DbType:             DatabaseTypePostgres,
		DbConnstring:       "postgresql://localhost:5432/test/",
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000",
		DbType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:     filepath.Join(testdataPath, "irma_configuration"),
		URL:             "http://localhost:8000/",
		DbType:          DatabaseTypeMemory,
		SessionLifetime: 60,
		EmailAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DbType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000",
		DbType:             "UNKNOWN",
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DbType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:        "localhost:1025",
		DefaultLanguage:    "en",
		LoginEmailFiles:    map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		LoginEmailSubject:  map[string]string{"en": "testsubject"},
		LoginEmailBaseURL:  map[string]string{"en": "localhost:8000/test/"},
	})
	assert.NoError(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DbType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:        "localhost:1025",
		DefaultLanguage:    "en",
		LoginEmailFiles:    map[string]string{"en": filepath.Join(testdataPath, "invalidemailtemplate.html")},
		LoginEmailSubject:  map[string]string{"en": "testsubject"},
		LoginEmailBaseURL:  map[string]string{"en": "localhost:8000/test/"},
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DbType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:        "localhost:1025",
		DefaultLanguage:    "en",
		LoginEmailFiles:    map[string]string{},
		LoginEmailSubject:  map[string]string{"en": "testsubject"},
		LoginEmailBaseURL:  map[string]string{"en": "localhost:8000/test/"},
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DbType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:        "localhost:1025",
		DefaultLanguage:    "en",
		LoginEmailFiles:    map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		LoginEmailSubject:  map[string]string{},
		LoginEmailBaseURL:  map[string]string{"en": "localhost:8000/test/"},
	})
	assert.Error(t, err)

	_, err = New(&Configuration{
		SchemesPath:        filepath.Join(testdataPath, "irma_configuration"),
		URL:                "http://localhost:8000/",
		DbType:             DatabaseTypeMemory,
		SessionLifetime:    60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		EmailServer:        "localhost:1025",
		DefaultLanguage:    "en",
		LoginEmailFiles:    map[string]string{"en": filepath.Join(testdataPath, "emailtemplate.html")},
		LoginEmailSubject:  map[string]string{"en": "testsubject"},
		LoginEmailBaseURL:  map[string]string{},
	})
	assert.Error(t, err)
}
