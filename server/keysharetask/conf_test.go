package keysharetask

import (
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/assert"
)

func TestConfiguration(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)

	err := processConfiguration(&Configuration{})
	assert.NoError(t, err)

	err = processConfiguration(&Configuration{
		EmailServer:     "localhost:1025",
		EmailFrom:       "test@test.com",
		DefaultLanguage: "en",
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteExpiredAccountSubject: map[string]string{
			"en": "testsubject",
		},
	})
	assert.NoError(t, err)

	err = processConfiguration(&Configuration{
		EmailServer: "localhost:1025",
		EmailFrom:   "test@test.com",
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteExpiredAccountSubject: map[string]string{
			"en": "testsubject",
		},
	})
	assert.Error(t, err)

	err = processConfiguration(&Configuration{
		EmailServer:     "localhost:1025",
		EmailFrom:       "test@test.com",
		DefaultLanguage: "en",
		DeleteExpiredAccountSubject: map[string]string{
			"en": "testsubject",
		},
	})
	assert.Error(t, err)

	err = processConfiguration(&Configuration{
		EmailServer:     "localhost:1025",
		EmailFrom:       "test@test.com",
		DefaultLanguage: "en",
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
	})
	assert.Error(t, err)
}
