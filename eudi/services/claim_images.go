package services

import (
	"encoding/base64"
	"slices"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// claimImage is a claim the wallet shows as a picture rather than as text:
// the leaf that holds the image, and where the image is.
type claimImage struct {
	// Path is the claim path of the leaf that holds the image: a data URI
	// claim itself, or the `id` of an Open Badges Image object. That leaf
	// becomes the picture, so what is disclosed and logged keeps its path.
	Path []any

	// Source is the leaf's value: a data:image/ URI, or the URL of an image
	// to download.
	Source string
}

// openBadgesImageType is the type an Open Badges 3.0 Image object has
// (Open Badges 3.0 B.1.13).
const openBadgesImageType = "Image"

// findClaimImages returns the claim images in a processed SD-JWT VC or VCDM
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
func findClaimImages(payload map[string]any, openBadges bool) []claimImage {
	var images []claimImage
	var walk func(path []any, value any)
	walk = func(path []any, value any) {
		switch v := value.(type) {
		case string:
			if helpers.IsImageDataURI(v) {
				images = append(images, claimImage{Path: path, Source: v})
			}
		case []any:
			for i, element := range v {
				walk(childPath(path, i), element)
			}
		case map[string]any:
			if openBadges {
				if source, ok := openBadgesImageSource(v); ok {
					images = append(images, claimImage{Path: childPath(path, "id"), Source: source})
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
	if !ok || !helpers.IsImageURI(id) {
		return "", false
	}
	return id, true
}

func childPath(path []any, segment any) []any {
	return append(slices.Clone(path), segment)
}

// showClaimImages turns the attributes that are claim images in payload
// (findClaimImages) into base64_image values and returns the attributes. A
// data URI is decoded from the attribute itself; a URL takes its image from
// downloaded, which maps a URL to the bytes the wallet downloaded from it, and
// stays text when it has none there. An image whose bytes are no PNG, JPEG,
// GIF, WebP or SVG stays text too.
//
// payload must be the credential's full processed payload, not a disclosure's
// view of it: a view may hold an Image's id without the type that makes it one.
func showClaimImages(
	attrs []clientmodels.Attribute,
	payload map[string]any,
	openBadges bool,
	downloaded map[string][]byte,
) []clientmodels.Attribute {
	images := findClaimImages(payload, openBadges)
	if len(images) == 0 {
		return attrs
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

// claimImageValue returns the base64_image value for a claim image's text
// value, or the value unchanged when its image is not available or not one
// the app can draw.
func claimImageValue(value *clientmodels.AttributeValue, downloaded map[string][]byte) *clientmodels.AttributeValue {
	if value == nil || value.Type != clientmodels.AttributeType_String || value.String == nil {
		return value
	}
	var data []byte
	if helpers.IsImageDataURI(*value.String) {
		decoded, err := helpers.DecodeDataURI(*value.String)
		if err != nil {
			return value
		}
		data = decoded
	} else {
		data = downloaded[*value.String]
	}
	if clientmodels.ImageMimeType(data) == "" {
		return value
	}
	image := clientmodels.NewBase64ImageValue(base64.StdEncoding.EncodeToString(data))
	image.DisplayHint = value.DisplayHint
	return image
}

// payloadMap returns a processed SD-JWT payload as the map findClaimImages
// reads, or nil for none.
func payloadMap(payload *sdjwt.ProcessedPayload) map[string]any {
	if payload == nil {
		return nil
	}
	return *payload
}

// maxClaimImagesPerCredential is how many images behind a URL a credential
// shows at most. Every image of a credential travels to the app with it in
// each credential list, so a credential must not be able to make that large.
const maxClaimImagesPerCredential = 10

// remoteClaimImageURLs returns the URLs of the claim images that are behind a
// URL, in the order findClaimImages finds them, each once, at most
// maxClaimImagesPerCredential of them. Data URIs are in the credential itself
// and need no URL.
func remoteClaimImageURLs(images []claimImage) []string {
	var urls []string
	for _, image := range images {
		if helpers.IsImageDataURI(image.Source) || slices.Contains(urls, image.Source) {
			continue
		}
		if len(urls) == maxClaimImagesPerCredential {
			break
		}
		urls = append(urls, image.Source)
	}
	return urls
}

// downloadableClaimImageURLs returns the URLs of the claim images the wallet
// downloads for the credential, and shows from the credential logo cache: those
// of the Open Badges Image objects in its credentialSubject, as
// remoteClaimImageURLs selects them. Only the credentialSubject becomes the
// credential's attributes; an Image elsewhere in the document, such as the
// issuer's or the credential's own, is not downloaded, so the wallet does not
// contact the hosts an issuer names for images the user would not see. Only an
// Open Badges credential, always a VCDM one, has images behind a URL.
func (d CredentialDocument) downloadableClaimImageURLs() []string {
	subject, ok := d.payload[vcdm.CredentialSubjectKey]
	if !d.openBadges || !ok {
		return nil
	}
	return remoteClaimImageURLs(findClaimImages(map[string]any{vcdm.CredentialSubjectKey: subject}, true))
}

// cachedClaimImages returns, keyed by URL, the cached images of the claim
// images in the credentialSubject that are behind a URL
// (downloadableClaimImageURLs) that are in manager, the credential logo cache,
// which claim images share with credential logos.
func (d CredentialDocument) cachedClaimImages(manager filesystem.LogoManager) map[string][]byte {
	images := map[string][]byte{}
	for _, url := range d.downloadableClaimImageURLs() {
		if data, _, err := manager.Get(url); err == nil {
			images[url] = data
		}
	}
	return images
}
