package services

import (
	"slices"
	"strings"
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
					images = append(images, ClaimImage{Path: childPath(path, "id"), Source: source})
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
