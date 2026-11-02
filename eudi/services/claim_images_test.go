package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
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
		images := findClaimImages(payload, openBadges)
		require.Equal(t, []claimImage{
			{Path: []any{"credentialSubject", "photo"}, Source: testImageDataURI},
			{Path: []any{"credentialSubject", "thumbnails", 0}, Source: testImageDataURI},
			{Path: []any{"loud"}, Source: "DATA:IMAGE/PNG;base64,AAAA"},
		}, images, "an image data URI is an image in any credential, whatever its case; a PDF is not")
		for _, image := range images {
			require.True(t, helpers.IsImageDataURI(image.Source))
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
	images := findClaimImages(payloadFromJSON(t, testBadgeJSON), true)
	require.Equal(t, []claimImage{{
		Path:   []any{"credentialSubject", "achievement", "image", "id"},
		Source: "https://pba.dev.eduwallet.nl/images/mbob/microcredentials/11br.001.01.png",
	}}, images, "the id leaf is the image; the caption and other URLs are not")
	require.False(t, helpers.IsImageDataURI(images[0].Source))
}

func TestFindClaimImages_ImageObjectOutsideOpenBadges(t *testing.T) {
	require.Empty(t, findClaimImages(payloadFromJSON(t, testBadgeJSON), false),
		"outside an Open Badges credential nothing says what an Image object means")
}

func TestFindClaimImages_OpenBadgesImageShapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		image string
		want  []claimImage
	}{
		{"type in an array", `{"id": "https://example.com/a.png", "type": ["Image"]}`,
			[]claimImage{{Path: []any{"image", "id"}, Source: "https://example.com/a.png"}}},
		{"id that is a data URI", `{"id": "` + testImageDataURI + `", "type": "Image"}`,
			[]claimImage{{Path: []any{"image", "id"}, Source: testImageDataURI}}},
		{"http URL, which the download refuses later", `{"id": "http://example.com/a.png", "type": "Image"}`,
			[]claimImage{{Path: []any{"image", "id"}, Source: "http://example.com/a.png"}}},
		{"no id", `{"type": "Image", "caption": "x"}`, nil},
		{"id that is not a string", `{"id": 5, "type": "Image"}`, nil},
		{"id that is no URL", `{"id": "urn:uuid:1234", "type": "Image"}`, nil},
		{"URL without a host", `{"id": "https:///a.png", "type": "Image"}`, nil},
		{"id that is a data URI of no image", `{"id": "data:text/plain,hello", "type": "Image"}`, nil},
		{"another type", `{"id": "https://example.com/a.png", "type": "Profile"}`, nil},
		{"no type", `{"id": "https://example.com/a.png"}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			images := findClaimImages(payloadFromJSON(t, `{"image": `+tc.image+`}`), true)
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
	require.Equal(t, []claimImage{
		{Path: []any{"evidence", 0, "image", "id"}, Source: "https://example.com/1.png"},
		{Path: []any{"evidence", 1, "image", "id"}, Source: "https://example.com/2.png"},
	}, findClaimImages(payload, true))
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
	for _, image := range findClaimImages(payload, true) {
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
	images := findClaimImages(payload, true)
	require.Len(t, images, 2)
	images[0].Path[len(images[0].Path)-1] = "changed"
	require.Equal(t, []any{"list", 1, "b", "id"}, images[1].Path)
}

func TestFindClaimImages_NoImages(t *testing.T) {
	require.Empty(t, findClaimImages(payloadFromJSON(t, `{"given_name": "Vera", "age": 30}`), true))
	require.Empty(t, findClaimImages(nil, true))
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
	attrs := showClaimImages([]clientmodels.Attribute{
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
			textAttr([]any{"other", "id"}, "https://example.com/missing.png"),
			textAttr([]any{"other", "type"}, "Image"),
			textAttr([]any{"targetUrl"}, imageURL),
		}
	}
	downloaded := map[string][]byte{imageURL: png}

	shown := showClaimImages(attrs(), payload, true, downloaded)
	requireImage(t, shown[0].Value, testPNGBase64, clientmodels.MimeTypePNG)
	requireText(t, shown[2].Value, "https://example.com/missing.png")
	requireText(t, shown[4].Value, imageURL)

	notBadge := showClaimImages(attrs(), payload, false, downloaded)
	require.Len(t, notBadge, 5, "outside an Open Badge nothing is an Image")
	requireText(t, notBadge[0].Value, imageURL)
}

// An Image object's id becomes its picture; its other fields stay text.
func TestShowClaimImages_ImageObject(t *testing.T) {
	payload := map[string]any{"image": map[string]any{"id": testImageDataURI, "type": "Image", "caption": "The badge"}}
	shown := showClaimImages([]clientmodels.Attribute{
		textAttr([]any{"image", "caption"}, "The badge"),
		textAttr([]any{"image", "id"}, testImageDataURI),
		textAttr([]any{"image", "type"}, "Image"),
	}, payload, true, nil)

	require.Len(t, shown, 3)
	requireText(t, shown[0].Value, "The badge")
	requireImage(t, shown[1].Value, testPNGBase64, clientmodels.MimeTypePNG)
	requireText(t, shown[2].Value, "Image")
}

// A disclosure may show an Image's id alone; the payload still says it is one.
func TestShowClaimImages_OnlyTheIdShown(t *testing.T) {
	payload := map[string]any{"image": map[string]any{"id": testImageDataURI, "type": "Image"}}
	attrs := showClaimImages([]clientmodels.Attribute{
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
	attrs := showClaimImages([]clientmodels.Attribute{
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
		_, _ = w.Write(png)
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

// claimImagesDocument is the document of a credential with this payload whose
// claim images are found as in an Open Badges credential when openBadges.
func claimImagesDocument(payload map[string]any, openBadges bool) CredentialDocument {
	return CredentialDocument{payload: payload, openBadges: openBadges}
}

// fetchBadgeImages fetches the claim images of a credential with this payload
// and returns how many it cached.
func fetchBadgeImages(ctx context.Context, cache filesystem.LogoManager, client *http.Client, payload map[string]any, openBadges bool) int {
	return claimImagesDocument(payload, openBadges).FetchImages(ctx, cache, cache, LogoFetcher{HTTPClient: client})
}

func newClaimImageCache(t *testing.T) filesystem.LogoManager {
	t.Helper()
	return filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()).Credentials().LogoManager()
}

func TestFetchClaimImages_CachesTheImagesOfAnOpenBadge(t *testing.T) {
	server, requests := imageHost(t)
	cache := newClaimImageCache(t)
	payload := badgePayload(server.URL+"/a.png", server.URL+"/b.png")

	require.Equal(t, 2, fetchBadgeImages(context.Background(), cache, server.Client(), payload, true))
	cached := claimImagesDocument(payload, true).cachedClaimImages(cache)
	require.Len(t, cached, 2)

	require.Equal(t, 0, fetchBadgeImages(context.Background(), cache, server.Client(), payload, true),
		"a cached image is not downloaded again")
	require.Equal(t, map[string]int{"/a.png": 1, "/b.png": 1}, requests)
}

func TestFetchClaimImages_NothingOutsideAnOpenBadge(t *testing.T) {
	server, requests := imageHost(t)
	cache := newClaimImageCache(t)
	require.Equal(t, 0, fetchBadgeImages(context.Background(), cache, server.Client(), badgePayload(server.URL+"/a.png"), false))
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

	require.Equal(t, 10, fetchBadgeImages(context.Background(), cache, server.Client(), payload, true))
	cached := claimImagesDocument(payload, true).cachedClaimImages(cache)
	require.Len(t, cached, 10)
	require.NotContains(t, cached, urls[10], "the images past the tenth stay text")
}

func TestFetchClaimImages_AFailingURLLeavesTheOthers(t *testing.T) {
	server, _ := imageHost(t)
	cache := newClaimImageCache(t)
	payload := badgePayload(server.URL+"/missing.png", server.URL+"/b.png")

	require.Equal(t, 1, fetchBadgeImages(context.Background(), cache, server.Client(), payload, true))
	cached := claimImagesDocument(payload, true).cachedClaimImages(cache)
	require.NotContains(t, cached, server.URL+"/missing.png")
	require.Contains(t, cached, server.URL+"/b.png")
}

func TestFetchClaimImages_DataURIsAreNotDownloaded(t *testing.T) {
	server, requests := imageHost(t)
	cache := newClaimImageCache(t)
	payload := badgePayload(testImageDataURI, server.URL+"/b.png")

	require.Equal(t, 1, fetchBadgeImages(context.Background(), cache, server.Client(), payload, true))
	require.Equal(t, map[string]int{"/b.png": 1}, requests)
}

func TestFetchClaimImages_StopsWhenTheTimeIsUp(t *testing.T) {
	server, requests := imageHost(t)
	cache := newClaimImageCache(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.Equal(t, 0, fetchBadgeImages(ctx, cache, server.Client(), badgePayload(server.URL+"/a.png"), true))
	require.Empty(t, requests)
}

// badgeDocument is an Open Badges credential with an Image in its
// credentialSubject, and Images elsewhere in the document: its own, its
// issuer's and its evidence's, the latter all from host.
func badgeDocument(host string) map[string]any {
	image := func(name string) map[string]any { return map[string]any{"id": host + "/" + name, "type": "Image"} }
	return map[string]any{
		"credentialSubject": map[string]any{"achievement": map[string]any{"image": image("subject.png")}},
		"image":             image("credential.png"),
		"issuer":            map[string]any{"id": "https://issuer.example", "image": image("issuer.png")},
		"evidence":          []any{map[string]any{"image": image("evidence.png")}},
	}
}

// Only the credentialSubject becomes attributes, so only its images are
// downloaded: the wallet does not contact hosts for images the user would not
// see.
func TestFetchClaimImages_OnlyTheCredentialSubjects(t *testing.T) {
	server, requests := imageHost(t)
	cache := newClaimImageCache(t)
	document := badgeDocument(server.URL)

	require.Equal(t, 1, fetchBadgeImages(context.Background(), cache, server.Client(), document, true))
	require.Equal(t, map[string]int{"/subject.png": 1}, requests)
	require.Equal(t, []string{server.URL + "/subject.png"}, slices.Collect(maps.Keys(claimImagesDocument(document, true).cachedClaimImages(cache))))
}

// The images outside the credentialSubject do not count towards its ten: ten
// images in it are all shown, also with others elsewhere.
func TestCachedClaimImages_TheBudgetIsTheCredentialSubjects(t *testing.T) {
	cache := newClaimImageCache(t)
	png, err := base64.StdEncoding.DecodeString(testPNGBase64)
	require.NoError(t, err)
	var subjectImages []any
	for i := range 10 {
		url := "https://example.com/" + strconv.Itoa(i) + ".png"
		require.NoError(t, cache.Save(url, png, clientmodels.MimeTypePNG))
		subjectImages = append(subjectImages, map[string]any{"id": url, "type": "Image"})
	}
	require.NoError(t, cache.Save("https://example.com/aaa-issuer.png", png, clientmodels.MimeTypePNG))
	document := map[string]any{
		"credentialSubject": map[string]any{"images": subjectImages},
		"aaa":               map[string]any{"image": map[string]any{"id": "https://example.com/aaa-issuer.png", "type": "Image"}},
	}

	cached := claimImagesDocument(document, true).cachedClaimImages(cache)
	require.Len(t, cached, 10)
	require.NotContains(t, cached, "https://example.com/aaa-issuer.png")
}

// A data URI is an image wherever it is, also outside the credentialSubject,
// where a verifier may ask for it: it needs no download. An Image there that
// is behind a URL is its URL.
func TestShowClaimImages_OutsideTheCredentialSubject(t *testing.T) {
	document := map[string]any{
		"credentialSubject": map[string]any{"name": "Vera"},
		"image":             testImageDataURI,
		"logo":              map[string]any{"id": "https://example.com/logo.png", "type": "Image"},
	}
	shown := showClaimImages([]clientmodels.Attribute{
		textAttr([]any{"image"}, testImageDataURI),
		textAttr([]any{"logo", "id"}, "https://example.com/logo.png"),
		textAttr([]any{"logo", "type"}, "Image"),
	}, document, true, nil)

	require.Len(t, shown, 3)
	requireImage(t, shown[0].Value, testPNGBase64, clientmodels.MimeTypePNG)
	requireText(t, shown[1].Value, "https://example.com/logo.png")
}
