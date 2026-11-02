package clientmodels

import (
	"bytes"
	"encoding/base64"
	"strings"
)

// The image types the app can draw, by the MIME type the app is told.
const (
	MimeTypePNG  = "image/png"
	MimeTypeJPEG = "image/jpeg"
	MimeTypeGIF  = "image/gif"
	MimeTypeWebP = "image/webp"
	MimeTypeSVG  = "image/svg+xml"
)

// ImageMimeType returns the MIME type of a PNG, JPEG, GIF, WebP or SVG image,
// recognised from its content, or "" for anything else. A declared type is
// not trusted, since the app picks its renderer by this one.
func ImageMimeType(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		return MimeTypePNG
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return MimeTypeJPEG
	case bytes.HasPrefix(data, []byte("GIF87a")), bytes.HasPrefix(data, []byte("GIF89a")):
		return MimeTypeGIF
	case len(data) >= 12 && bytes.Equal(data[:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")):
		return MimeTypeWebP
	case isSVG(data):
		return MimeTypeSVG
	default:
		return ""
	}
}

// isSVG reports whether data is an XML document whose root element is <svg>:
// after an optional byte order mark, XML declaration, comments, processing
// instructions and doctype.
func isSVG(data []byte) bool {
	rest := bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF"))
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		var end []byte
		switch {
		case bytes.HasPrefix(rest, []byte("<?")):
			end = []byte("?>")
		case bytes.HasPrefix(rest, []byte("<!--")):
			end = []byte("-->")
		case bytes.HasPrefix(rest, []byte("<!")):
			end = []byte(">")
		default:
			if !bytes.HasPrefix(rest, []byte("<svg")) || len(rest) == len("<svg") {
				return false
			}
			next := rest[len("<svg")]
			return next == '>' || next == '/' || next == ' ' || next == '\t' || next == '\r' || next == '\n'
		}
		_, after, found := bytes.Cut(rest, end)
		if !found {
			return false
		}
		rest = after
	}
}

// base64SniffLength is how much of a base64 image is decoded to recognise its
// type: about 6 KB, a multiple of 4 so the prefix decodes on its own.
const base64SniffLength = 8192

// base64ImageMimeType is ImageMimeType for a base64 image, decoding only a
// prefix.
func base64ImageMimeType(encoded string) string {
	encoded = strings.TrimSpace(encoded)
	if len(encoded) > base64SniffLength {
		encoded = encoded[:base64SniffLength]
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return ImageMimeType(data)
}

// NewBase64ImageValue returns a base64_image value with its MIME type.
func NewBase64ImageValue(encoded string) *AttributeValue {
	value := &AttributeValue{Type: AttributeType_Base64Image, Base64Image: &encoded}
	value.SetImageMimeType()
	return value
}

// SetImageMimeType sets MimeType from the value's base64 image, or clears it
// when the image is not recognised.
func (v *AttributeValue) SetImageMimeType() {
	if v == nil || v.Base64Image == nil {
		return
	}
	if mimeType := base64ImageMimeType(*v.Base64Image); mimeType != "" {
		v.MimeType = &mimeType
	} else {
		v.MimeType = nil
	}
}
