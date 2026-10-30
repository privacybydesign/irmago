package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
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

const testPNGBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"

func textAttr(path []any, value string) clientmodels.Attribute {
	return clientmodels.Attribute{ClaimPath: path, Value: clientmodels.NewAttributeValue(value)}
}

func requireImage(t *testing.T, value *clientmodels.AttributeValue, wantBase64, wantMimeType string) {
	t.Helper()
	require.NotNil(t, value)
	require.Equal(t, clientmodels.AttributeType_Base64Image, value.Type)
	require.Nil(t, value.String)
	require.NotNil(t, value.Base64Image)
	require.Equal(t, wantBase64, *value.Base64Image)
	require.NotNil(t, value.MimeType)
	require.Equal(t, wantMimeType, *value.MimeType)
}

func requireText(t *testing.T, value *clientmodels.AttributeValue, want string) {
	t.Helper()
	require.NotNil(t, value)
	require.Equal(t, clientmodels.AttributeType_String, value.Type)
	require.NotNil(t, value.String)
	require.Equal(t, want, *value.String)
}

func TestShowClaimImages_DataURIs(t *testing.T) {
	svg := `<svg xmlns="http://www.w3.org/2000/svg"/>`
	svgURI := "data:image/svg+xml," + url.PathEscape(svg)
	notAnImage := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("hello"))
	badBase64 := "data:image/png;base64,not base64!"
	payload := map[string]any{
		"photo":    testImageDataURI,
		"logo":     svgURI,
		"fake":     notAnImage,
		"broken":   badBase64,
		"document": "data:application/pdf;base64,JVBERi0=",
		"name":     "Vera",
	}
	attrs := ShowClaimImages([]clientmodels.Attribute{
		textAttr([]any{"photo"}, testImageDataURI),
		textAttr([]any{"logo"}, svgURI),
		textAttr([]any{"fake"}, notAnImage),
		textAttr([]any{"broken"}, badBase64),
		textAttr([]any{"document"}, "data:application/pdf;base64,JVBERi0="),
		textAttr([]any{"name"}, "Vera"),
	}, payload, false, nil)

	requireImage(t, attrs[0].Value, testPNGBase64, clientmodels.MimeTypePNG)
	requireImage(t, attrs[1].Value, base64.StdEncoding.EncodeToString([]byte(svg)), clientmodels.MimeTypeSVG)
	requireText(t, attrs[2].Value, notAnImage)
	requireText(t, attrs[3].Value, badBase64)
	requireText(t, attrs[4].Value, "data:application/pdf;base64,JVBERi0=")
	requireText(t, attrs[5].Value, "Vera")
}

func TestShowClaimImages_DownloadedImages(t *testing.T) {
	png, err := base64.StdEncoding.DecodeString(testPNGBase64)
	require.NoError(t, err)
	imageURL := "https://example.com/badge.png"
	payload := map[string]any{
		"image":     map[string]any{"id": imageURL, "type": "Image"},
		"targetUrl": imageURL,
		"other":     map[string]any{"id": "https://example.com/missing.png", "type": "Image"},
	}
	attrs := func() []clientmodels.Attribute {
		return []clientmodels.Attribute{
			textAttr([]any{"image", "id"}, imageURL),
			textAttr([]any{"image", "type"}, "Image"),
			textAttr([]any{"targetUrl"}, imageURL),
			textAttr([]any{"other", "id"}, "https://example.com/missing.png"),
		}
	}
	downloaded := map[string][]byte{imageURL: png}

	shown := ShowClaimImages(attrs(), payload, true, downloaded)
	requireImage(t, shown[0].Value, testPNGBase64, clientmodels.MimeTypePNG)
	requireText(t, shown[1].Value, "Image")
	requireText(t, shown[2].Value, imageURL)
	requireText(t, shown[3].Value, "https://example.com/missing.png")

	notBadge := ShowClaimImages(attrs(), payload, false, downloaded)
	requireText(t, notBadge[0].Value, imageURL)
}

// A disclosure may show an Image's id alone; the payload still says it is one.
func TestShowClaimImages_OnlyTheIdShown(t *testing.T) {
	payload := map[string]any{"image": map[string]any{"id": testImageDataURI, "type": "Image"}}
	attrs := ShowClaimImages([]clientmodels.Attribute{
		textAttr([]any{"image", "id"}, testImageDataURI),
	}, payload, true, nil)
	requireImage(t, attrs[0].Value, testPNGBase64, clientmodels.MimeTypePNG)
}

func TestShowClaimImages_KeepsTheRestOfTheAttribute(t *testing.T) {
	name := "Photo"
	hint := "portraitPhoto"
	requested := clientmodels.NewAttributeValue(testImageDataURI)
	value := clientmodels.NewAttributeValue(testImageDataURI)
	value.DisplayHint = &hint
	attrs := ShowClaimImages([]clientmodels.Attribute{
		{ClaimPath: []any{"photo"}, DisplayName: &name, Value: value, RequestedValue: requested},
		{ClaimPath: []any{"photo", "header"}},
	}, map[string]any{"photo": testImageDataURI}, false, nil)

	require.Equal(t, []any{"photo"}, attrs[0].ClaimPath, "the path is unchanged")
	require.Equal(t, &name, attrs[0].DisplayName)
	requireImage(t, attrs[0].Value, testPNGBase64, clientmodels.MimeTypePNG)
	require.Equal(t, &hint, attrs[0].Value.DisplayHint)
	requireImage(t, attrs[0].RequestedValue, testPNGBase64, clientmodels.MimeTypePNG)
	require.Nil(t, attrs[1].Value, "a header stays a header")
}

// imageHost serves the test PNG at every path, over TLS, padded with zero bytes
// to the size a path's "size" query asks for, and counts the requests per path.
func imageHost(t *testing.T) (*httptest.Server, map[string]int) {
	t.Helper()
	png, err := base64.StdEncoding.DecodeString(testPNGBase64)
	require.NoError(t, err)
	var mu sync.Mutex
	requests := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests[r.URL.Path]++
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/missing") {
			http.NotFound(w, r)
			return
		}
		body := png
		if size, err := strconv.Atoi(r.URL.Query().Get("size")); err == nil && size > len(png) {
			body = append(slices.Clone(png), make([]byte, size-len(png))...)
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func badgePayload(urls ...string) map[string]any {
	images := make([]any, len(urls))
	for i, url := range urls {
		images[i] = map[string]any{"id": url, "type": "Image"}
	}
	return map[string]any{"credentialSubject": map[string]any{"images": images}}
}

func newClaimImageCache(t *testing.T) filesystem.LogoManager {
	t.Helper()
	return filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()).Credentials().LogoManager()
}

func TestFetchClaimImages_CachesTheImagesOfAnOpenBadge(t *testing.T) {
	server, requests := imageHost(t)
	cache := newClaimImageCache(t)
	payload := badgePayload(server.URL+"/a.png", server.URL+"/b.png")

	require.Equal(t, 2, FetchClaimImages(context.Background(), cache, server.Client(), payload, true, false))
	cached := CachedClaimImages(cache, payload, true)
	require.Len(t, cached, 2)

	require.Equal(t, 0, FetchClaimImages(context.Background(), cache, server.Client(), payload, true, false),
		"a cached image is not downloaded again")
	require.Equal(t, map[string]int{"/a.png": 1, "/b.png": 1}, requests)
}

func TestFetchClaimImages_NothingOutsideAnOpenBadge(t *testing.T) {
	server, requests := imageHost(t)
	cache := newClaimImageCache(t)
	require.Equal(t, 0, FetchClaimImages(context.Background(), cache, server.Client(), badgePayload(server.URL+"/a.png"), false, false))
	require.Empty(t, requests)
}

func TestFetchClaimImages_AtMostTenImages(t *testing.T) {
	server, _ := imageHost(t)
	cache := newClaimImageCache(t)
	var urls []string
	for i := range 12 {
		urls = append(urls, server.URL+"/"+strconv.Itoa(i)+".png")
	}
	payload := badgePayload(urls...)

	require.Equal(t, 10, FetchClaimImages(context.Background(), cache, server.Client(), payload, true, false))
	cached := CachedClaimImages(cache, payload, true)
	require.Len(t, cached, 10)
	require.NotContains(t, cached, urls[10], "the images past the tenth stay text")
}

// The images of one credential together fit in 2 MB: the first that does not
// fit, and every one after it, stays text, also when it would fit on its own.
func TestFetchClaimImages_TwoMegabytesPerCredential(t *testing.T) {
	server, requests := imageHost(t)
	cache := newClaimImageCache(t)
	size := strconv.Itoa(3 << 19) // 1.5 MB
	first := server.URL + "/first.png?size=" + size
	second := server.URL + "/second.png?size=" + size
	small := server.URL + "/small.png"
	payload := badgePayload(first, second, small)

	require.Equal(t, 1, FetchClaimImages(context.Background(), cache, server.Client(), payload, true, false))
	require.Equal(t, 0, requests["/small.png"], "nothing past the image that did not fit is downloaded")
	cached := CachedClaimImages(cache, payload, true)
	require.Contains(t, cached, first)
	require.NotContains(t, cached, second)
	require.NotContains(t, cached, small)
}

// The budget holds when showing too, also for images another credential put in
// the shared cache.
func TestCachedClaimImages_TwoMegabytesPerCredential(t *testing.T) {
	cache := newClaimImageCache(t)
	big := make([]byte, 3<<19) // 1.5 MB
	require.NoError(t, cache.Save("https://example.com/a.png", big, "image/png"))
	require.NoError(t, cache.Save("https://example.com/b.png", big, "image/png"))

	cached := CachedClaimImages(cache, badgePayload("https://example.com/a.png", "https://example.com/b.png"), true)
	require.Equal(t, map[string][]byte{"https://example.com/a.png": big}, cached)
}

func TestFetchClaimImages_AFailingURLLeavesTheOthers(t *testing.T) {
	server, _ := imageHost(t)
	cache := newClaimImageCache(t)
	payload := badgePayload(server.URL+"/missing.png", server.URL+"/b.png")

	require.Equal(t, 1, FetchClaimImages(context.Background(), cache, server.Client(), payload, true, false))
	cached := CachedClaimImages(cache, payload, true)
	require.NotContains(t, cached, server.URL+"/missing.png")
	require.Contains(t, cached, server.URL+"/b.png")
}

func TestFetchClaimImages_DataURIsAreNotDownloaded(t *testing.T) {
	server, requests := imageHost(t)
	cache := newClaimImageCache(t)
	payload := badgePayload(testImageDataURI, server.URL+"/b.png")

	require.Equal(t, 1, FetchClaimImages(context.Background(), cache, server.Client(), payload, true, false))
	require.Equal(t, map[string]int{"/b.png": 1}, requests)
}

func TestFetchClaimImages_StopsWhenTheTimeIsUp(t *testing.T) {
	server, requests := imageHost(t)
	cache := newClaimImageCache(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.Equal(t, 0, FetchClaimImages(ctx, cache, server.Client(), badgePayload(server.URL+"/a.png"), true, false))
	require.Empty(t, requests)
}

func TestLeafPaths(t *testing.T) {
	payload := payloadFromJSON(t, `{
		"credentialSubject": {
			"name": "Vera",
			"achievement": {
				"image": {"type": "Image", "id": "https://example.com/a.png"},
				"alignment": [{"targetCode": "A"}, {"targetCode": "B"}],
				"tags": [],
				"extra": {}
			}
		}
	}`)
	cs := "credentialSubject"

	require.Equal(t, [][]any{{cs, "name"}}, LeafPaths(payload, []any{cs, "name"}), "a value is its own leaf")
	require.Equal(t, [][]any{
		{cs, "achievement", "image", "id"},
		{cs, "achievement", "image", "type"},
	}, LeafPaths(payload, []any{cs, "achievement", "image"}), "an object's values, keys sorted")
	require.Equal(t, [][]any{
		{cs, "achievement", "alignment", 0, "targetCode"},
		{cs, "achievement", "alignment", 1, "targetCode"},
	}, LeafPaths(payload, []any{cs, "achievement", "alignment"}))
	require.Equal(t, [][]any{{cs, "achievement", "alignment", float64(1), "targetCode"}},
		LeafPaths(payload, []any{cs, "achievement", "alignment", float64(1)}), "an index decoded from JSON")
	require.Equal(t, [][]any{{cs, "achievement", "tags"}}, LeafPaths(payload, []any{cs, "achievement", "tags"}), "an empty array is its own leaf")
	require.Equal(t, [][]any{{cs, "achievement", "extra"}}, LeafPaths(payload, []any{cs, "achievement", "extra"}))
	require.Nil(t, LeafPaths(payload, []any{cs, "missing"}))
	require.Nil(t, LeafPaths(payload, []any{cs, "achievement", "alignment", 5}))
	require.Nil(t, LeafPaths(payload, []any{cs, "name", "deeper"}))
}
