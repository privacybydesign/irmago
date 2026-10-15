package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/stretchr/testify/require"
)

const testCardTemplate = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" onload="alert(1)">` +
	`<script>alert(2)</script><text>{{given_name}}</text></svg>`

func sriSha256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func solidPNG(t *testing.T, c color.NRGBA) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.SetNRGBA(x, y, c)
		}
	}
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	return buf.Bytes()
}

type cardAsset struct {
	contentType string
	body        []byte
}

func newCardArtServer(t *testing.T, assets map[string]cardAsset) (*httptest.Server, map[string]int) {
	t.Helper()
	requests := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests[r.URL.Path]++
		a, ok := assets[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if a.contentType != "" {
			w.Header().Set("Content-Type", a.contentType)
		} else {
			w.Header()["Content-Type"] = nil // suppress Go's sniffing
		}
		_, _ = w.Write(a.body)
	}))
	t.Cleanup(srv.Close)
	return srv, requests
}

func strPtr(s string) *string { return &s }

func newCardArtManager(t *testing.T) filesystem.LogoManager {
	return filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()).Credentials().LogoManager()
}

func TestFetchCardArt_SanitisesVerifiesAndLoads(t *testing.T) {
	bg := solidPNG(t, color.NRGBA{0, 82, 204, 255})
	srv, requests := newCardArtServer(t, map[string]cardAsset{
		"/card.svg": {"image/svg+xml", []byte(testCardTemplate)},
		"/bg.png":   {"image/png", bg},
	})
	displays := metadata.CredentialDisplays{{
		Display:         metadata.Display{Name: "Card", Locale: strPtr("en")},
		BackgroundColor: "#003366",
		TextColor:       "#ffffff",
		BackgroundImage: &metadata.RemoteImage{Uri: srv.URL + "/bg.png", Integrity: sriSha256(bg)},
		SvgTemplates: []metadata.SvgTemplateRef{{
			Uri: srv.URL + "/card.svg", Integrity: sriSha256([]byte(testCardTemplate)),
			Orientation: "landscape", ColorScheme: "light", Contrast: "normal",
		}},
	}}
	manager := newCardArtManager(t)

	require.Equal(t, 2, FetchCardArtIfMissing(context.Background(), manager, srv.Client(), displays, "en"))
	require.Equal(t, 0, FetchCardArtIfMissing(context.Background(), manager, srv.Client(), displays, "en"), "warm cache")
	require.Equal(t, map[string]int{"/card.svg": 1, "/bg.png": 1}, requests)

	got := BuildCredentialDisplay(manager, displays, "en", nil, "")
	require.NotNil(t, got)
	require.Equal(t, "#003366", got.BackgroundColor)
	require.Equal(t, "#ffffff", got.TextColor)
	require.NotNil(t, got.BackgroundImage)
	require.Equal(t, base64.StdEncoding.EncodeToString(bg), got.BackgroundImage.Base64)
	require.Equal(t, "image/png", *got.BackgroundImage.MimeType)
	require.Len(t, got.SvgTemplates, 1)
	tpl := got.SvgTemplates[0]
	require.Equal(t, "landscape", tpl.Orientation)
	require.Equal(t, "light", tpl.ColorScheme)
	require.Equal(t, "normal", tpl.Contrast)
	require.Contains(t, tpl.Svg, "{{given_name}}")
	require.NotContains(t, tpl.Svg, "script")
	require.NotContains(t, tpl.Svg, "onload")
}

func TestFetchCardArt_RejectsBadAssets(t *testing.T) {
	bigSvg := []byte(`<svg xmlns="http://www.w3.org/2000/svg">` + strings.Repeat(" ", maxSvgTemplateBytes) + `</svg>`)
	png := solidPNG(t, color.NRGBA{200, 0, 0, 255})
	srv, _ := newCardArtServer(t, map[string]cardAsset{
		"/mismatch.svg": {"image/svg+xml", []byte(testCardTemplate)},
		"/big.svg":      {"image/svg+xml", bigSvg},
		"/html.svg":     {"text/html", []byte(`<html><body>not svg</body></html>`)},
		"/notsvg.svg":   {"image/svg+xml", []byte(`<html><svg/></html>`)},
		"/svg-bg.png":   {"image/svg+xml", []byte(testCardTemplate)},
		"/big-bg.png":   {"image/png", bytes.Repeat([]byte{0}, maxBackgroundImageSize+1)},
		"/sniffed.png":  {"", png},
	})
	manager := newCardArtManager(t)
	fetch := func(d metadata.CredentialDisplay) int {
		return FetchCardArtIfMissing(context.Background(), manager, srv.Client(), metadata.CredentialDisplays{d}, "en")
	}
	template := func(path, integrity string) metadata.CredentialDisplay {
		return metadata.CredentialDisplay{SvgTemplates: []metadata.SvgTemplateRef{{Uri: srv.URL + path, Integrity: integrity}}}
	}
	background := func(path string) metadata.CredentialDisplay {
		return metadata.CredentialDisplay{BackgroundImage: &metadata.RemoteImage{Uri: srv.URL + path}}
	}

	require.Equal(t, 0, fetch(template("/mismatch.svg", sriSha256([]byte("something else")))), "integrity mismatch")
	require.Equal(t, 0, fetch(template("/mismatch.svg", "md5-abc")), "unsupported integrity algorithm")
	require.Equal(t, 0, fetch(template("/big.svg", "")), "over the 256 KiB template cap")
	require.Equal(t, 0, fetch(template("/html.svg", "")), "not an SVG")
	require.Equal(t, 0, fetch(template("/notsvg.svg", "")), "root is not <svg>")
	require.Equal(t, 0, fetch(template("/missing.svg", "")), "404")
	require.Equal(t, 0, fetch(background("/svg-bg.png")), "SVG background images are refused")
	require.Equal(t, 0, fetch(background("/big-bg.png")), "over the 2 MiB image cap")
	require.Equal(t, 1, fetch(background("/sniffed.png")), "a PNG without Content-Type is sniffed")
	require.Equal(t, 1, fetch(template("/mismatch.svg", "")), "absent integrity is accepted")

	data, mimeType, err := manager.Get(backgroundImageCacheKey(metadata.RemoteImage{Uri: srv.URL + "/sniffed.png"}))
	require.NoError(t, err)
	require.Equal(t, png, data)
	require.Equal(t, "image/png", mimeType)
}

// Templates, background image and colours follow the logo's locale fallback:
// the entry resolving for the locale first, any other locale's otherwise.
func TestBuildCredentialDisplay_LocaleFallback(t *testing.T) {
	enSvg := []byte(`<svg><text>en</text></svg>`)
	nlSvg := []byte(`<svg><text>nl</text></svg>`)
	srv, _ := newCardArtServer(t, map[string]cardAsset{
		"/en.svg": {"image/svg+xml", enSvg},
		"/nl.svg": {"image/svg+xml", nlSvg},
	})
	displays := metadata.CredentialDisplays{
		{
			Display:         metadata.Display{Name: "EN", Locale: strPtr("en-US")},
			BackgroundColor: "#111111",
			SvgTemplates:    []metadata.SvgTemplateRef{{Uri: srv.URL + "/en.svg"}},
		},
		{
			Display:      metadata.Display{Name: "NL", Locale: strPtr("nl")},
			SvgTemplates: []metadata.SvgTemplateRef{{Uri: srv.URL + "/nl.svg"}},
		},
		{Display: metadata.Display{Name: "DE", Locale: strPtr("de")}},
	}
	manager := newCardArtManager(t)

	// Only the nl template resolves for nl, so only it is fetched.
	require.Equal(t, 1, FetchCardArtIfMissing(context.Background(), manager, srv.Client(), displays, "nl"))
	nl := BuildCredentialDisplay(manager, displays, "nl", nil, "")
	require.Contains(t, nl.SvgTemplates[0].Svg, ">nl<")
	require.Equal(t, "#111111", nl.BackgroundColor, "colours fall back across locales")

	// en is not cached yet: the cached nl template stands in until it is.
	en := BuildCredentialDisplay(manager, displays, "en", nil, "")
	require.Contains(t, en.SvgTemplates[0].Svg, ">nl<")
	require.Equal(t, 1, FetchCardArtIfMissing(context.Background(), manager, srv.Client(), displays, "en"))
	en = BuildCredentialDisplay(manager, displays, "en", nil, "")
	require.Contains(t, en.SvgTemplates[0].Svg, ">en<")

	// de has no templates of its own and falls back too.
	de := BuildCredentialDisplay(manager, displays, "de", nil, "")
	require.Len(t, de.SvgTemplates, 1)
}

func TestBuildCredentialDisplay_NilWhenNothingKnown(t *testing.T) {
	displays := metadata.CredentialDisplays{{Display: metadata.Display{Name: "Plain"}}}
	require.Nil(t, BuildCredentialDisplay(newCardArtManager(t), displays, "en", nil, ""))
	require.Nil(t, BuildCredentialDisplay(nil, nil, "en", nil, ""))
}

func TestBuildCredentialDisplay_LogoTint(t *testing.T) {
	manager := newCardArtManager(t)
	logo := solidPNG(t, color.NRGBA{0, 82, 204, 255})
	require.NoError(t, manager.Save("https://x/logo.png", logo, "image/png"))
	uris := clientmodels.TranslatedString{"en": "https://x/logo.png"}

	img, key := LoadResolvedLogoWithKey(manager, uris, "en")
	require.Equal(t, "https://x/logo.png", key)
	got := BuildCredentialDisplay(manager, nil, "en", img, key)
	require.NotNil(t, got)
	require.Equal(t, "#0052CC", got.LogoTint)

	svgMime := "image/svg+xml"
	require.Equal(t, "", LogoTint("https://x/logo.svg", &clientmodels.Image{Base64: "PHN2Zy8+", MimeType: &svgMime}))
	require.Equal(t, "", LogoTint("", img))
}

func TestApplySvgIds(t *testing.T) {
	attrs := []clientmodels.Attribute{
		{ClaimPath: []any{"given_name"}},
		{ClaimPath: []any{"nationalities", 0}},
		{ClaimPath: []any{"nationalities", 1}},
		{ClaimPath: []any{"other"}},
	}
	ApplySvgIds(attrs, SvgIdsByClaimPath([]metadata.ClaimsDescription{
		{Path: metadata.ClaimsPathPointer{"given_name"}, SvgId: "given_name"},
		{Path: metadata.ClaimsPathPointer{"nationalities", nil}, SvgId: "nationality"},
		{Path: metadata.ClaimsPathPointer{"other"}},
	}))
	require.Equal(t, []string{"given_name", "nationality", "nationality", ""},
		slices.Collect(func(yield func(string) bool) {
			for _, a := range attrs {
				if !yield(a.SvgId) {
					return
				}
			}
		}))
}

// The storage round trip: what convertCredentialMetadata writes for a display,
// StoredCredentialDisplays reads back with its card-art fields intact.
func TestStoredCredentialDisplays_RoundTrip(t *testing.T) {
	in := metadata.CredentialDisplays{{
		Display:         metadata.Display{Name: "Card", Locale: strPtr("en")},
		Logo:            &metadata.RemoteImage{Uri: "https://x/logo.png", AltText: "logo"},
		BackgroundColor: "#000000",
		TextColor:       "#ffffff",
		BackgroundImage: &metadata.RemoteImage{Uri: "https://x/bg.png", AltText: "bg", Integrity: "sha256-b"},
		SvgTemplates:    []metadata.SvgTemplateRef{{Uri: "https://x/t.svg", Integrity: "sha256-t", Orientation: "portrait"}},
	}}
	out := StoredCredentialDisplays(slices.Collect(in.ToStorageModelIterator()))
	require.Equal(t, in, out)
}
