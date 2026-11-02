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

// claimImage is a claim shown as a picture: the path of the claim, and its
// value, a data URI or the URL of an image to download.
type claimImage struct {
	Path   []any
	Source string
}

// openBadgesImageType is the `type` of an Open Badges 3.0 Image (B.1.13).
const openBadgesImageType = "Image"

// findClaimImages returns the claim images in a payload. A data:image/ string
// is an image in any credential. The `id` of an Open Badges Image object is an
// image only in an Open Badges credential.
//
// It reads the whole payload, not the attributes: a disclosure may show an
// Image's `id` without the `type` that makes it one.
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

// openBadgesImageSource returns the image URI of an Open Badges Image object,
// and whether the object is one. Its `type` may be "Image" or an array with it.
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

// showClaimImages turns the attributes that are claim images in payload into
// pictures. A URL takes its image from downloaded; without it, or when the
// bytes are no image the app can draw, the attribute stays text. payload is
// the credential's full payload (see findClaimImages).
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

// claimImageValue returns the picture for a claim image's value, or the value
// unchanged when there is none.
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

// payloadMap returns a processed SD-JWT payload as a map, nil for none.
func payloadMap(payload *sdjwt.ProcessedPayload) map[string]any {
	if payload == nil {
		return nil
	}
	return *payload
}

// maxClaimImagesPerCredential is how many images behind a URL a credential
// shows at most, since they travel to the app in every credential list.
const maxClaimImagesPerCredential = 10

// remoteClaimImageURLs returns the first maxClaimImagesPerCredential distinct
// URLs among images, skipping data URIs.
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
// downloads: those of the Open Badges Images in the credentialSubject. Only the
// credentialSubject is shown as attributes, so the wallet contacts no host for
// an image the user would not see.
func (d CredentialDocument) downloadableClaimImageURLs() []string {
	subject, ok := d.payload[vcdm.CredentialSubjectKey]
	if !d.openBadges || !ok {
		return nil
	}
	return remoteClaimImageURLs(findClaimImages(map[string]any{vcdm.CredentialSubjectKey: subject}, true))
}

// cachedClaimImages returns the downloadable claim images that are in manager,
// the credential logo cache, keyed by URL.
func (d CredentialDocument) cachedClaimImages(manager filesystem.LogoManager) map[string][]byte {
	images := map[string][]byte{}
	for _, url := range d.downloadableClaimImageURLs() {
		if data, _, err := manager.Get(url); err == nil {
			images[url] = data
		}
	}
	return images
}
