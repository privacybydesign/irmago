package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/eudi/svgsanitize"
	"github.com/privacybydesign/irmago/internal/logotint"
)

// Card art: the issuer-provided styling of a credential card beyond its logo —
// colours, a background image and SD-JWT VC SVG templates — plus the logo tint
// the wallet derives itself.
//
// Background images and SVG templates go through the logo pipeline: downloaded
// at the same points (offer, after issuance, the locale backfill sweep), cached
// in the credentials LogoManager, and resolved per locale with the same
// fallback. Unlike logos they are capped in size, MIME-checked, verified
// against their uri#integrity when the metadata gives one, and — for templates
// — sanitised before they are written, so the cache only ever holds content
// that is safe to hand to the app.

const (
	maxSvgTemplateBytes    = 256 << 10 // 256 KiB
	maxBackgroundImageSize = 2 << 20   // 2 MiB
	svgMimeType            = "image/svg+xml"
)

// svgTemplateCacheKey and backgroundImageCacheKey are the LogoManager keys of
// cached card art. The integrity hash is part of the key so a template the
// issuer has replaced (new hash) is fetched again rather than served stale,
// and the prefixes keep a sanitised template from colliding with a raw logo
// served from the same URL.
func svgTemplateCacheKey(ref metadata.SvgTemplateRef) string {
	return "svg-template|" + ref.Integrity + "|" + ref.Uri
}

func backgroundImageCacheKey(img metadata.RemoteImage) string {
	return "background-image|" + img.Integrity + "|" + img.Uri
}

// StoredCredentialDisplays converts the SD-JWT VC storage rows back into the
// published metadata shape the card-art helpers work on. Only the fields the
// card art needs are filled.
func StoredCredentialDisplays(rows []models.CredentialDisplay) metadata.CredentialDisplays {
	out := make(metadata.CredentialDisplays, 0, len(rows))
	for _, r := range rows {
		d := metadata.CredentialDisplay{
			BackgroundColor: r.BackgroundColor,
			TextColor:       r.TextColor,
		}
		d.Name = r.Name
		if r.Locale.Valid {
			locale := r.Locale.V
			d.Locale = &locale
		}
		if r.LogoURI != "" {
			d.Logo = &metadata.RemoteImage{Uri: r.LogoURI, AltText: r.LogoAltText}
		}
		if r.BackgroundImageURI != "" {
			d.BackgroundImage = &metadata.RemoteImage{
				Uri:       r.BackgroundImageURI,
				AltText:   r.BackgroundImageAltText,
				Integrity: r.BackgroundImageIntegrity.V,
			}
		}
		if len(r.SvgTemplates) > 0 && string(r.SvgTemplates) != "null" {
			if err := json.Unmarshal(r.SvgTemplates, &d.SvgTemplates); err != nil {
				eudi.Logger.Warnf("ignoring unreadable stored svg_templates: %v", err)
				d.SvgTemplates = nil
			}
		}
		out = append(out, d)
	}
	return out
}

// displaysByLanguage maps base language → the displays that satisfy has, in
// fallback-chain order: the entry resolved for locale first, then the others
// in sorted language order (mirroring LoadResolvedLogo's fallback).
func displaysByLanguage(displays metadata.CredentialDisplays, locale string, has func(metadata.CredentialDisplay) bool) []metadata.CredentialDisplay {
	indices := clientmodels.TranslatedString{}
	for i, d := range displays {
		if !has(d) {
			continue
		}
		lang := displayLanguageOf(d.Locale)
		if _, taken := indices[lang]; !taken {
			indices[lang] = strconv.Itoa(i)
		}
	}
	if len(indices) == 0 {
		return nil
	}
	var ordered []metadata.CredentialDisplay
	first := clientmodels.Resolve(indices, locale)
	if i, err := strconv.Atoi(first); err == nil {
		ordered = append(ordered, displays[i])
	}
	for _, lang := range slices.Sorted(maps.Keys(indices)) {
		if indices[lang] == first {
			continue
		}
		i, _ := strconv.Atoi(indices[lang])
		ordered = append(ordered, displays[i])
	}
	return ordered
}

func hasBackgroundImage(d metadata.CredentialDisplay) bool {
	return d.BackgroundImage != nil && d.BackgroundImage.Uri != ""
}

func hasSvgTemplates(d metadata.CredentialDisplay) bool {
	return len(d.SvgTemplates) > 0
}

func hasColors(d metadata.CredentialDisplay) bool {
	return d.BackgroundColor != "" || d.TextColor != ""
}

// FetchCardArtIfMissing downloads and caches the background image and SVG
// templates that resolve for the locale, skipping what is already cached.
// Returns the number of assets newly cached. Failures are logged and skipped.
func FetchCardArtIfMissing(ctx context.Context, manager filesystem.LogoManager, httpClient *http.Client, displays metadata.CredentialDisplays, locale string) int {
	if manager == nil {
		return 0
	}
	added := 0
	if resolved := displaysByLanguage(displays, locale, hasBackgroundImage); len(resolved) > 0 {
		added += fetchBackgroundImageIfMissing(ctx, manager, httpClient, *resolved[0].BackgroundImage)
	}
	if resolved := displaysByLanguage(displays, locale, hasSvgTemplates); len(resolved) > 0 {
		for _, ref := range resolved[0].SvgTemplates {
			if ctx.Err() != nil {
				return added
			}
			added += fetchSvgTemplateIfMissing(ctx, manager, httpClient, ref)
		}
	}
	return added
}

func fetchBackgroundImageIfMissing(ctx context.Context, manager filesystem.LogoManager, httpClient *http.Client, img metadata.RemoteImage) int {
	if img.Uri == "" {
		return 0
	}
	key := backgroundImageCacheKey(img)
	if exists, err := manager.Exists(key); err == nil && exists {
		return 0
	}
	data, mimeType, err := downloadCardAsset(ctx, httpClient, img.Uri, img.Integrity, maxBackgroundImageSize)
	if err != nil {
		eudi.Logger.Warnf("failed to download background image: %v", err)
		return 0
	}
	mimeType, ok := bitmapMimeType(mimeType, data)
	if !ok {
		eudi.Logger.Warnf("ignoring background image %q: not a PNG, JPEG, GIF or WebP image", img.Uri)
		return 0
	}
	if err := manager.Save(key, data, mimeType); err != nil {
		eudi.Logger.Warnf("failed to cache background image %q: %v", img.Uri, err)
		return 0
	}
	return 1
}

func fetchSvgTemplateIfMissing(ctx context.Context, manager filesystem.LogoManager, httpClient *http.Client, ref metadata.SvgTemplateRef) int {
	if ref.Uri == "" {
		return 0
	}
	key := svgTemplateCacheKey(ref)
	if exists, err := manager.Exists(key); err == nil && exists {
		return 0
	}
	data, mimeType, err := downloadCardAsset(ctx, httpClient, ref.Uri, ref.Integrity, maxSvgTemplateBytes)
	if err != nil {
		eudi.Logger.Warnf("failed to download svg template: %v", err)
		return 0
	}
	if !looksLikeSvg(mimeType, data) {
		eudi.Logger.Warnf("ignoring svg template %q: not an SVG document (Content-Type %q)", ref.Uri, mimeType)
		return 0
	}
	clean, err := svgsanitize.Sanitize(data)
	if err != nil {
		eudi.Logger.Warnf("ignoring svg template %q: %v", ref.Uri, err)
		return 0
	}
	if err := manager.Save(key, clean, svgMimeType); err != nil {
		eudi.Logger.Warnf("failed to cache svg template %q: %v", ref.Uri, err)
		return 0
	}
	return 1
}

// downloadCardAsset downloads uri with a size cap and, when integrity is
// non-empty, verifies the raw bytes against it. An absent integrity is
// accepted: the asset is still size-capped, type-checked and (for templates)
// sanitised.
func downloadCardAsset(ctx context.Context, httpClient *http.Client, uri, integrity string, maxBytes int64) ([]byte, string, error) {
	data, mimeType, err := helpers.DownloadRemoteAsset(ctx, httpClient, uri, maxBytes)
	if err != nil {
		return nil, "", err
	}
	if integrity != "" {
		if err := typemetadata.VerifyIntegrity(data, integrity); err != nil {
			return nil, "", fmt.Errorf("%s: %w", uri, err)
		}
	}
	return data, mimeType, nil
}

func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(contentType))
	}
	return mt
}

// looksLikeSvg accepts an SVG Content-Type, or — for servers that send a
// generic one — a body that opens an <svg element early on.
func looksLikeSvg(contentType string, data []byte) bool {
	if mediaType(contentType) == svgMimeType {
		return true
	}
	head := data[:min(len(data), 4096)]
	return bytes.Contains(head, []byte("<svg"))
}

var bitmapMimeTypes = map[string]struct{}{
	"image/png": {}, "image/jpeg": {}, "image/gif": {}, "image/webp": {},
}

// bitmapMimeType returns the bitmap MIME type of data: the Content-Type when
// it names one of the accepted types, else the sniffed type. SVG is refused —
// a background image is rendered as a plain picture, not run through the SVG
// sanitiser.
func bitmapMimeType(contentType string, data []byte) (string, bool) {
	if mt := mediaType(contentType); mt != "" {
		if _, ok := bitmapMimeTypes[mt]; ok {
			return mt, true
		}
	}
	sniffed := mediaType(http.DetectContentType(data))
	if _, ok := bitmapMimeTypes[sniffed]; ok {
		return sniffed, true
	}
	return "", false
}

// LoadResolvedLogoWithKey is LoadResolvedLogo that also returns the key of the
// logo it loaded (the cache key the logo tint is memoised under).
func LoadResolvedLogoWithKey(manager filesystem.LogoManager, uris clientmodels.TranslatedString, locale string) (*clientmodels.Image, string) {
	if key := clientmodels.Resolve(uris, locale); key != "" {
		if img := eudi.LoadLogoImage(manager, key); img != nil {
			return img, key
		}
	}
	for _, k := range slices.Sorted(maps.Keys(uris)) {
		if img := eudi.LoadLogoImage(manager, uris[k]); img != nil {
			return img, uris[k]
		}
	}
	return nil, ""
}

// LogoTint returns the "#RRGGBB" dominant colour of a loaded logo, memoised
// under key. "" for SVG or undecodable logos.
func LogoTint(key string, logo *clientmodels.Image) string {
	if logo == nil || key == "" {
		return ""
	}
	if logo.MimeType != nil && strings.Contains(*logo.MimeType, "svg") {
		return ""
	}
	return logotint.Shared.Get(key, func() []byte {
		data, err := base64.StdEncoding.DecodeString(logo.Base64)
		if err != nil {
			return nil
		}
		return data
	})
}

// BuildCredentialDisplay resolves a credential's card styling for the locale:
// colours, the cached background image and SVG templates, and the tint of the
// already-loaded logo (logoKey is the key LoadResolvedLogoWithKey returned).
// Returns nil when there is nothing to show.
func BuildCredentialDisplay(manager filesystem.LogoManager, displays metadata.CredentialDisplays, locale string, logo *clientmodels.Image, logoKey string) *clientmodels.CredentialDisplay {
	out := &clientmodels.CredentialDisplay{LogoTint: LogoTint(logoKey, logo)}

	// Colours resolve as a pair, from one entry, so a text colour is never
	// combined with another locale's background it was not chosen for.
	if resolved := displaysByLanguage(displays, locale, hasColors); len(resolved) > 0 {
		out.BackgroundColor = resolved[0].BackgroundColor
		out.TextColor = resolved[0].TextColor
	}

	if manager != nil {
		for _, d := range displaysByLanguage(displays, locale, hasBackgroundImage) {
			if img := eudi.LoadLogoImage(manager, backgroundImageCacheKey(*d.BackgroundImage)); img != nil {
				out.BackgroundImage = img
				break
			}
		}
		for _, d := range displaysByLanguage(displays, locale, hasSvgTemplates) {
			if templates := loadSvgTemplates(manager, d.SvgTemplates); len(templates) > 0 {
				out.SvgTemplates = templates
				break
			}
		}
	}

	if out.IsEmpty() {
		return nil
	}
	return out
}

func loadSvgTemplates(manager filesystem.LogoManager, refs []metadata.SvgTemplateRef) []clientmodels.SvgCardTemplate {
	var out []clientmodels.SvgCardTemplate
	for _, ref := range refs {
		key := svgTemplateCacheKey(ref)
		if exists, err := manager.Exists(key); err != nil || !exists {
			continue
		}
		data, _, err := manager.Get(key)
		if err != nil || len(data) == 0 {
			continue
		}
		out = append(out, clientmodels.SvgCardTemplate{
			Svg:         string(data),
			Orientation: ref.Orientation,
			ColorScheme: ref.ColorScheme,
			Contrast:    ref.Contrast,
		})
	}
	return out
}

// SvgIdsByClaimPath maps clientmodels.ClaimPathKey → svg_id over the claims
// that carry one.
func SvgIdsByClaimPath(claims []metadata.ClaimsDescription) map[string]string {
	out := map[string]string{}
	for _, c := range claims {
		if c.SvgId != "" && len(c.Path) > 0 {
			out[clientmodels.ClaimPathKey(c.Path)] = c.SvgId
		}
	}
	return out
}

// ApplySvgIds sets Attribute.SvgId on every attribute whose claim path (or its
// wildcard form, array indices replaced by null) has an svg_id.
func ApplySvgIds(attrs []clientmodels.Attribute, svgIds map[string]string) {
	if len(svgIds) == 0 {
		return
	}
	for i := range attrs {
		if id, ok := lookupDisplayName(svgIds, attrs[i].ClaimPath); ok {
			attrs[i].SvgId = id
		}
	}
}
