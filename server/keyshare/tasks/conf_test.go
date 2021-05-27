package tasks

import (
	"path/filepath"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server/keyshare"
	"github.com/stretchr/testify/assert"
)

func TestConfiguration(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)

	err := processConfiguration(&Configuration{Logger: irma.Logger})
	assert.NoError(t, err)

	err = processConfiguration(&Configuration{
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     "localhost:1025",
			EmailFrom:       "test@test.com",
			DefaultLanguage: "en",
		},
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteExpiredAccountSubjects: map[string]string{
			"en": "testsubject",
		},
		Logger: irma.Logger,
	})
	assert.NoError(t, err)

	err = processConfiguration(&Configuration{
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer: "localhost:1025",
			EmailFrom:   "test@test.com",
		},
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteExpiredAccountSubjects: map[string]string{
			"en": "testsubject",
		},
		Logger: irma.Logger,
	})
	assert.Error(t, err)

	err = processConfiguration(&Configuration{
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     "localhost:1025",
			EmailFrom:       "test@test.com",
			DefaultLanguage: "en",
		},
		DeleteExpiredAccountSubjects: map[string]string{
			"en": "testsubject",
		},
		Logger: irma.Logger,
	})
	assert.Error(t, err)

	err = processConfiguration(&Configuration{
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     "localhost:1025",
			EmailFrom:       "test@test.com",
			DefaultLanguage: "en",
		},
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		Logger: irma.Logger,
	})
	assert.Error(t, err)
}
