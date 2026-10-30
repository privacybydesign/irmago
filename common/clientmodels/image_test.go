package clientmodels

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A valid 1x1 PNG.
const testPNGBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"

func TestImageMimeType(t *testing.T) {
	png, err := base64.StdEncoding.DecodeString(testPNGBase64)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{"png", string(png), MimeTypePNG},
		{"jpeg", "\xFF\xD8\xFF\xE0\x00\x10JFIF", MimeTypeJPEG},
		{"gif87a", "GIF87a\x01\x00", MimeTypeGIF},
		{"gif89a", "GIF89a\x01\x00", MimeTypeGIF},
		{"webp", "RIFF\x24\x00\x00\x00WEBPVP8 ", MimeTypeWebP},
		{"svg", `<svg xmlns="http://www.w3.org/2000/svg"/>`, MimeTypeSVG},
		{"svg with declaration, comment and doctype",
			"\xEF\xBB\xBF<?xml version=\"1.0\"?>\n<!-- badge -->\n<!DOCTYPE svg>\n<svg>\n</svg>", MimeTypeSVG},
		{"svg root directly closed", "<svg>", MimeTypeSVG},
		{"other xml root", `<?xml version="1.0"?><html/>`, ""},
		{"a root named svgfoo", "<svgfoo/>", ""},
		{"unterminated comment", "<!-- <svg/>", ""},
		{"riff that is not webp", "RIFF\x24\x00\x00\x00WAVEfmt ", ""},
		{"text", "hello", ""},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ImageMimeType([]byte(tc.data)))
		})
	}
}

func TestBase64ImageMimeType(t *testing.T) {
	assert.Equal(t, MimeTypePNG, Base64ImageMimeType(testPNGBase64))
	assert.Equal(t, MimeTypePNG, Base64ImageMimeType(" "+testPNGBase64+"\n"), "surrounding whitespace is ignored")
	assert.Equal(t, "", Base64ImageMimeType("not base64!"))
	assert.Equal(t, "", Base64ImageMimeType(" "))

	// Only a prefix is decoded: a large image whose tail is not even base64
	// is still recognised by its start.
	large := base64.StdEncoding.EncodeToString([]byte("GIF89a"+strings.Repeat("x", 3*base64SniffLength))) + "!!"
	assert.Equal(t, MimeTypeGIF, Base64ImageMimeType(large))
}

func TestNewBase64ImageValue(t *testing.T) {
	value := NewBase64ImageValue(testPNGBase64)
	assert.Equal(t, AttributeType_Base64Image, value.Type)
	require.NotNil(t, value.Base64Image)
	assert.Equal(t, testPNGBase64, *value.Base64Image)
	require.NotNil(t, value.MimeType)
	assert.Equal(t, MimeTypePNG, *value.MimeType)

	unknown := NewBase64ImageValue(base64.StdEncoding.EncodeToString([]byte("hello")))
	assert.Nil(t, unknown.MimeType, "an unrecognised image has no MIME type")
}

func TestSetImageMimeType(t *testing.T) {
	stale := MimeTypeSVG
	value := &AttributeValue{Type: AttributeType_Base64Image, Base64Image: new(" "), MimeType: &stale}
	value.SetImageMimeType()
	assert.Nil(t, value.MimeType, "a MIME type the image does not have is cleared")

	text := &AttributeValue{Type: AttributeType_String, String: new("x")}
	text.SetImageMimeType()
	assert.Nil(t, text.MimeType)

	var none *AttributeValue
	none.SetImageMimeType()
}
