package services

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

const testImageDataURI = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"

// payloadFromJSON decodes a payload the way a processed SD-JWT is held: JSON
// objects as map[string]any, arrays as []any.
func payloadFromJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(s), &payload))
	return payload
}

func TestFindClaimImages_DataURI(t *testing.T) {
	payload := payloadFromJSON(t, `{
		"credentialSubject": {
			"photo": "`+testImageDataURI+`",
			"name": "Vera",
			"attachment": "data:application/pdf;base64,JVBERi0=",
			"thumbnails": ["`+testImageDataURI+`"]
		},
		"loud": "DATA:IMAGE/PNG;base64,AAAA"
	}`)

	for _, openBadges := range []bool{false, true} {
		images := FindClaimImages(payload, openBadges)
		require.Equal(t, []ClaimImage{
			{Path: []any{"credentialSubject", "photo"}, Source: testImageDataURI},
			{Path: []any{"credentialSubject", "thumbnails", 0}, Source: testImageDataURI},
			{Path: []any{"loud"}, Source: "DATA:IMAGE/PNG;base64,AAAA"},
		}, images, "an image data URI is an image in any credential, whatever its case; a PDF is not")
		for _, image := range images {
			require.True(t, image.IsDataURI())
		}
	}
}

// The Image object of MBO Beek's OpenBadge credential.
const testBadgeJSON = `{
	"credentialSubject": {
		"achievement": {
			"name": "Schildertechnieken",
			"image": {"id": "https://pba.dev.eduwallet.nl/images/mbob/microcredentials/11br.001.01.png", "type": "Image", "caption": "Badge"},
			"alignment": [
				{"type": ["Alignment"], "targetUrl": "https://data.example.com/decisions/AV-11BR.001.01"}
			]
		},
		"type": ["VerifiableCredential", "OpenBadgeCredential"]
	}
}`

func TestFindClaimImages_OpenBadgesImage(t *testing.T) {
	images := FindClaimImages(payloadFromJSON(t, testBadgeJSON), true)
	require.Equal(t, []ClaimImage{{
		Path:   []any{"credentialSubject", "achievement", "image", "id"},
		Source: "https://pba.dev.eduwallet.nl/images/mbob/microcredentials/11br.001.01.png",
	}}, images, "the id leaf is the image; the caption and other URLs are not")
	require.False(t, images[0].IsDataURI())
}

func TestFindClaimImages_ImageObjectOutsideOpenBadges(t *testing.T) {
	require.Empty(t, FindClaimImages(payloadFromJSON(t, testBadgeJSON), false),
		"outside an Open Badges credential nothing says what an Image object means")
}

func TestFindClaimImages_OpenBadgesImageShapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		image string
		want  []ClaimImage
	}{
		{"type in an array", `{"id": "https://example.com/a.png", "type": ["Image"]}`,
			[]ClaimImage{{Path: []any{"image", "id"}, Source: "https://example.com/a.png"}}},
		{"id that is a data URI", `{"id": "` + testImageDataURI + `", "type": "Image"}`,
			[]ClaimImage{{Path: []any{"image", "id"}, Source: testImageDataURI}}},
		{"http URL, which the download refuses later", `{"id": "http://example.com/a.png", "type": "Image"}`,
			[]ClaimImage{{Path: []any{"image", "id"}, Source: "http://example.com/a.png"}}},
		{"no id", `{"type": "Image", "caption": "x"}`, nil},
		{"id that is not a string", `{"id": 5, "type": "Image"}`, nil},
		{"id that is no URL", `{"id": "urn:uuid:1234", "type": "Image"}`, nil},
		{"id that is a data URI of no image", `{"id": "data:text/plain,hello", "type": "Image"}`, nil},
		{"another type", `{"id": "https://example.com/a.png", "type": "Profile"}`, nil},
		{"no type", `{"id": "https://example.com/a.png"}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			images := FindClaimImages(payloadFromJSON(t, `{"image": `+tc.image+`}`), true)
			require.Equal(t, tc.want, images)
		})
	}
}

func TestFindClaimImages_NestedInArrays(t *testing.T) {
	payload := payloadFromJSON(t, `{
		"evidence": [
			{"name": "first", "image": {"id": "https://example.com/1.png", "type": "Image"}},
			{"name": "second", "image": {"id": "https://example.com/2.png", "type": "Image"}}
		]
	}`)
	require.Equal(t, []ClaimImage{
		{Path: []any{"evidence", 0, "image", "id"}, Source: "https://example.com/1.png"},
		{Path: []any{"evidence", 1, "image", "id"}, Source: "https://example.com/2.png"},
	}, FindClaimImages(payload, true))
}

// The order is the one the card shows without metadata, so a limit on the
// number of images keeps the first ones the user sees.
func TestFindClaimImages_Order(t *testing.T) {
	payload := payloadFromJSON(t, `{
		"zeta": {"id": "https://example.com/z.png", "type": "Image"},
		"alpha": {"id": "https://example.com/a.png", "type": "Image"},
		"middle": "`+testImageDataURI+`"
	}`)
	var sources []string
	for _, image := range FindClaimImages(payload, true) {
		sources = append(sources, image.Source)
	}
	require.Equal(t, []string{"https://example.com/a.png", testImageDataURI, "https://example.com/z.png"}, sources)
}

// The paths are fresh slices: one image's path is never a view of another's.
func TestFindClaimImages_PathsDoNotAlias(t *testing.T) {
	payload := payloadFromJSON(t, `{"list": [
		{"a": {"id": "https://example.com/a.png", "type": "Image"}},
		{"b": {"id": "https://example.com/b.png", "type": "Image"}}
	]}`)
	images := FindClaimImages(payload, true)
	require.Len(t, images, 2)
	images[0].Path[len(images[0].Path)-1] = "changed"
	require.Equal(t, []any{"list", 1, "b", "id"}, images[1].Path)
}

func TestFindClaimImages_NoImages(t *testing.T) {
	require.Empty(t, FindClaimImages(payloadFromJSON(t, `{"given_name": "Vera", "age": 30}`), true))
	require.Empty(t, FindClaimImages(nil, true))
}
