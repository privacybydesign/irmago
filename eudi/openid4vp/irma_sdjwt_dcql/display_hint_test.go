package irma_sdjwt_dcql

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The scheme's display hint is passed to the client unchanged, so it can render
// values for hints irmago doesn't interpret itself, such as "currency:EUR".
func TestBuildAttributeValue_PassesDisplayHint(t *testing.T) {
	amount := "12.50"
	val := buildAttributeValue("currency:EUR", &amount)
	assert.Equal(t, clientmodels.AttributeType_String, val.Type)
	require.NotNil(t, val.String)
	assert.Equal(t, "12.50", *val.String)
	require.NotNil(t, val.DisplayHint)
	assert.Equal(t, "currency:EUR", *val.DisplayHint)

	yes := "yes"
	val = buildAttributeValue("yesno", &yes)
	require.NotNil(t, val.Bool)
	require.NotNil(t, val.DisplayHint)
	assert.Equal(t, "yesno", *val.DisplayHint)

	val = buildAttributeValue("currency:EUR", nil)
	require.NotNil(t, val.DisplayHint)
	assert.Equal(t, "currency:EUR", *val.DisplayHint)
}

func TestBuildAttributeValue_NoDisplayHint(t *testing.T) {
	amount := "12.50"
	val := buildAttributeValue("", &amount)
	assert.Nil(t, val.DisplayHint)
}

// A photo gets the MIME type of the image it holds, so the app can pick a
// renderer.
func TestBuildAttributeValue_PhotoMimeType(t *testing.T) {
	png := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
	val := buildAttributeValue("portraitPhoto", &png)
	assert.Equal(t, clientmodels.AttributeType_Base64Image, val.Type)
	require.NotNil(t, val.MimeType)
	assert.Equal(t, clientmodels.MimeTypePNG, *val.MimeType)
}
