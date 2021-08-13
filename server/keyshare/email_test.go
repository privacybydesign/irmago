package keyshare

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestParseEmailTemplates(t *testing.T) {
	lang := "en"
	testdataPath := test.FindTestdataFolder(t)

	_, err := ParseEmailTemplates(
		map[string]string{},
		map[string]string{lang: "subject"},
		lang,
	)
	require.Error(t, err)

	_, err = ParseEmailTemplates(
		map[string]string{lang: filepath.Join(testdataPath, "emailtemplate.html")},
		map[string]string{},
		lang,
	)
	require.Error(t, err)

	_, err = ParseEmailTemplates(
		map[string]string{lang: filepath.Join(testdataPath, "invalidemailtemplate.html")},
		map[string]string{lang: "subject"},
		lang,
	)
	require.Error(t, err)

	templ, err := ParseEmailTemplates(
		map[string]string{lang: filepath.Join(testdataPath, "emailtemplate.html")},
		map[string]string{lang: "subject"},
		lang,
	)
	require.NoError(t, err)
	require.Contains(t, templ, lang)

	var msg bytes.Buffer
	require.NoError(t, templ[lang].Execute(&msg, map[string]string{"VerificationURL": "123"}))
	require.Equal(t, "This is a test template 123", msg.String())
}
