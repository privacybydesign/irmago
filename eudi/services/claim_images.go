package services

import (
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// ClaimImage is a claim the wallet shows as a picture rather than as text:
// the leaf that holds the image, and where the image is.
type ClaimImage struct {
	// Path is the claim path of the leaf that holds the image: a data URI
	// claim itself, or the `id` of an Open Badges Image object. That leaf
	// becomes the picture, so what is disclosed and logged keeps its path.
	Path []any

	// Source is the leaf's value: a data:image/ URI, or the URL of an image
	// to download.
	Source string

	// Object is the path of the Open Badges Image object the image is the id
	// of, nil for a data URI claim of its own. Shown whole, the object is one
	// attribute: its image.
	Object []any
}

// IsDataURI reports whether the image is in the claim itself, so it needs no
// download.
func (c ClaimImage) IsDataURI() bool {
	return isImageDataURI(c.Source)
}

// openBadgesImageType is the type an Open Badges 3.0 Image object has
// (Open Badges 3.0 B.1.13).
const openBadgesImageType = "Image"

// FindClaimImages returns the claim images in a processed SD-JWT VC or VCDM
// payload, in the order the credential list shows claims without metadata
// (object keys sorted, array elements in order). A data:image/ string is an
// image in any credential. An Open Badges Image object, `type` "Image" with a
// string `id` that is an image data URI or an http(s) URL, is one only in an
// Open Badges credential (vcdm.IsOpenBadgesCredential): elsewhere nothing says
// what the shape means.
//
// It reads the payload rather than the attributes, because a disclosure shows
// only the requested leaves: an Image's `id` can be requested without its
// `type`, and then the attributes alone cannot tell it from any other URL.
func FindClaimImages(payload map[string]any, openBadges bool) []ClaimImage {
	var images []ClaimImage
	var walk func(path []any, value any)
	walk = func(path []any, value any) {
		switch v := value.(type) {
		case string:
			if isImageDataURI(v) {
				images = append(images, ClaimImage{Path: path, Source: v})
			}
		case []any:
			for i, element := range v {
				walk(childPath(path, i), element)
			}
		case map[string]any:
			if openBadges {
				if source, ok := openBadgesImageSource(v); ok {
					images = append(images, ClaimImage{Path: childPath(path, "id"), Source: source, Object: slices.Clone(path)})
					// Its other fields, such as its caption, are text.
					return
				}
			}
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			for _, key := range keys {
				walk(childPath(path, key), v[key])
			}
		}
	}
	walk([]any{}, payload)
	return images
}

// openBadgesImageSource returns the image an Open Badges Image object points
// to, and whether the object is one. Its `type` must be "Image"; an array
// holding it is accepted too, as JSON-LD allows.
func openBadgesImageSource(object map[string]any) (string, bool) {
	isImage := false
	switch t := object["type"].(type) {
	case string:
		isImage = t == openBadgesImageType
	case []any:
		isImage = slices.Contains(t, any(openBadgesImageType))
	}
	if !isImage {
		return "", false
	}
	id, ok := object["id"].(string)
	if !ok || !(isImageDataURI(id) || isHTTPURL(id)) {
		return "", false
	}
	return id, true
}

// isImageDataURI reports whether s is a data URI of an image type. The scheme
// and the media type are case-insensitive (RFC 2397).
func isImageDataURI(s string) bool {
	return len(s) > len("data:image/") && strings.EqualFold(s[:len("data:image/")], "data:image/")
}

// isHTTPURL reports whether s is an http or https URL. Whether it may be
// downloaded is up to the download, which only accepts https.
func isHTTPURL(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://")
}

func childPath(path []any, segment any) []any {
	return append(slices.Clone(path), segment)
}

// ShowClaimImages turns the attributes that are claim images in payload
// (FindClaimImages) into base64_image values and returns the attributes. A
// data URI is decoded from the attribute itself; a URL takes its image from
// downloaded, which maps a URL to the bytes the wallet downloaded from it, and
// stays text when it has none there. An image whose bytes are no PNG, JPEG,
// GIF, WebP or SVG stays text too.
//
// An Open Badges Image object whose values are all among attrs becomes one
// attribute at the object's path, its image, with the object's caption as its
// description, rather than a section with an id and a type. That attribute is
// what the user discloses, and selecting an object discloses everything in it,
// so it is shown only when all of it would be sent. An Image whose id is shown
// without the rest, as when a verifier asks for the id alone, keeps its id
// attribute, which becomes the image.
//
// payload must be the credential's full processed payload, not a disclosure's
// view of it: a view may hold an Image's id without the type that makes it one.
func ShowClaimImages(
	attrs []clientmodels.Attribute,
	payload map[string]any,
	openBadges bool,
	downloaded map[string][]byte,
) []clientmodels.Attribute {
	images := FindClaimImages(payload, openBadges)
	if len(images) == 0 {
		return attrs
	}
	for _, image := range images {
		if image.Object != nil {
			attrs = collapseImageObject(attrs, payload, image, downloaded)
		}
	}
	isImage := make(map[string]struct{}, len(images))
	for _, image := range images {
		isImage[clientmodels.ClaimPathKey(image.Path)] = struct{}{}
	}
	for i := range attrs {
		if _, ok := isImage[clientmodels.ClaimPathKey(attrs[i].ClaimPath)]; !ok {
			continue
		}
		attrs[i].Value = claimImageValue(attrs[i].Value, downloaded)
		attrs[i].RequestedValue = claimImageValue(attrs[i].RequestedValue, downloaded)
	}
	return attrs
}

// collapseImageObject replaces the attributes of an Open Badges Image object,
// and the header of the object when attrs has one, by one attribute at the
// object's path that holds its image, at the place of the first of them. It
// leaves attrs as they are unless every value of the object is among them.
func collapseImageObject(attrs []clientmodels.Attribute, payload map[string]any, image ClaimImage, downloaded map[string][]byte) []clientmodels.Attribute {
	index := make(map[string]int, len(attrs))
	for i, attr := range attrs {
		index[clientmodels.ClaimPathKey(attr.ClaimPath)] = i
	}
	idIndex, ok := index[clientmodels.ClaimPathKey(image.Path)]
	if !ok {
		return attrs
	}
	replaced := map[int]struct{}{}
	for _, leaf := range LeafPaths(payload, image.Object) {
		i, ok := index[clientmodels.ClaimPathKey(leaf)]
		if !ok {
			return attrs
		}
		replaced[i] = struct{}{}
	}

	id := attrs[idIndex]
	collapsed := clientmodels.Attribute{
		ClaimPath:      slices.Clone(image.Object),
		Value:          claimImageValue(id.Value, downloaded),
		RequestedValue: claimImageValue(id.RequestedValue, downloaded),
		IntentToRetain: id.IntentToRetain,
	}
	// The issuer's name for the object, when its metadata gives one, names the
	// image; without it the app names it after its key, "image".
	if header, ok := index[clientmodels.ClaimPathKey(image.Object)]; ok && attrs[header].Value == nil {
		replaced[header] = struct{}{}
		collapsed.DisplayName = attrs[header].DisplayName
		collapsed.Description = attrs[header].Description
	}
	if object, ok := valueAtPath(payload, image.Object); ok {
		if caption, ok := object.(map[string]any)["caption"].(string); ok && caption != "" {
			collapsed.Description = &caption
		}
	}

	first := len(attrs)
	for i := range replaced {
		first = min(first, i)
	}
	result := make([]clientmodels.Attribute, 0, len(attrs)-len(replaced)+1)
	for i, attr := range attrs {
		if i == first {
			result = append(result, collapsed)
		}
		if _, ok := replaced[i]; !ok {
			result = append(result, attr)
		}
	}
	return result
}

// claimImageValue returns the base64_image value for a claim image's text
// value, or the value unchanged when its image is not available or not one
// the app can draw.
func claimImageValue(value *clientmodels.AttributeValue, downloaded map[string][]byte) *clientmodels.AttributeValue {
	if value == nil || value.Type != clientmodels.AttributeType_String || value.String == nil {
		return value
	}
	var data []byte
	if isImageDataURI(*value.String) {
		decoded, err := helpers.DecodeDataURI(*value.String)
		if err != nil {
			return value
		}
		data = decoded
	} else {
		data = downloaded[*value.String]
	}
	mimeType := clientmodels.ImageMimeType(data)
	if mimeType == "" {
		return value
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return &clientmodels.AttributeValue{
		Type:        clientmodels.AttributeType_Base64Image,
		Base64Image: &encoded,
		MimeType:    &mimeType,
		DisplayHint: value.DisplayHint,
	}
}

// payloadMap returns a processed SD-JWT payload as the map FindClaimImages
// reads, or nil for none.
func payloadMap(payload *sdjwt.ProcessedPayload) map[string]any {
	if payload == nil {
		return nil
	}
	return *payload
}

// The images behind a URL a credential shows at most: how many, and how many
// bytes together. Every image of a credential travels to the app with it in
// each credential list, so a credential must not be able to make that large.
const (
	maxClaimImagesPerCredential     = 10
	maxClaimImageBytesPerCredential = helpers.MaxImageSize
)

// remoteClaimImageURLs returns the URLs of the claim images that are behind a
// URL, in the order FindClaimImages finds them, each once, at most
// maxClaimImagesPerCredential of them. Data URIs are in the credential itself
// and need no URL.
func remoteClaimImageURLs(images []ClaimImage) []string {
	var urls []string
	for _, image := range images {
		if image.IsDataURI() || slices.Contains(urls, image.Source) {
			continue
		}
		if len(urls) == maxClaimImagesPerCredential {
			break
		}
		urls = append(urls, image.Source)
	}
	return urls
}

// CachedClaimImages returns, keyed by URL, the cached images of the claim
// images in payload that are behind a URL: those among the first
// maxClaimImagesPerCredential that are in manager, in order, as long as
// together they fit in maxClaimImageBytesPerCredential. What does not fit stays
// text, as an image that was never downloaded does. manager is the credential
// logo cache, which claim images share with credential logos.
func CachedClaimImages(manager filesystem.LogoManager, payload map[string]any, openBadges bool) map[string][]byte {
	images := map[string][]byte{}
	used := 0
	for _, url := range remoteClaimImageURLs(FindClaimImages(payload, openBadges)) {
		data, _, err := manager.Get(url)
		if err != nil {
			continue
		}
		if used+len(data) > maxClaimImageBytesPerCredential {
			break
		}
		used += len(data)
		images[url] = data
	}
	return images
}

// FetchClaimImages downloads into manager, the credential logo cache, the
// claim images in payload that are behind a URL and missing from it, under the
// limits CachedClaimImages shows them by, and returns how many it cached. Like
// a credential logo, an image already cached is not downloaded again. ctx
// bounds the time all downloads together may take.
func FetchClaimImages(
	ctx context.Context,
	manager filesystem.LogoManager,
	httpClient *http.Client,
	payload map[string]any,
	openBadges bool,
	allowInsecureHTTP bool,
) int {
	cached, _ := fetchClaimImages(ctx, manager, httpClient, payload, openBadges, allowInsecureHTTP)
	return cached
}

// fetchClaimImages is FetchClaimImages, also returning how many downloads it
// tried: none when every image it may show was cached already.
func fetchClaimImages(
	ctx context.Context,
	manager filesystem.LogoManager,
	httpClient *http.Client,
	payload map[string]any,
	openBadges bool,
	allowInsecureHTTP bool,
) (cached, tried int) {
	used := 0
	for _, url := range remoteClaimImageURLs(FindClaimImages(payload, openBadges)) {
		if ctx.Err() != nil {
			return cached, tried
		}
		if data, _, err := manager.Get(url); err == nil {
			used += len(data)
		} else {
			tried++
			data, mimeType, err := helpers.DownloadRemoteImage(ctx, httpClient, url, allowInsecureHTTP)
			if err != nil {
				eudi.Logger.Warnf("failed to download claim image from %q: %v", url, err)
				continue
			}
			if used+len(data) > maxClaimImageBytesPerCredential {
				return cached, tried
			}
			if err := manager.Save(url, data, mimeType); err != nil {
				eudi.Logger.Warnf("failed to cache claim image from %q: %v", url, err)
				continue
			}
			used += len(data)
			cached++
		}
		if used >= maxClaimImageBytesPerCredential {
			return cached, tried
		}
	}
	return cached, tried
}
