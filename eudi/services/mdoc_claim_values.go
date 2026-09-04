package services

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// The resolved element values of an mdoc are cached as JSON for display and
// matching (models.CredentialBatch.ProcessedSdJwtPayload). JSON has fewer types
// than CBOR, and encoding/json flattens the difference silently: a byte string
// becomes a base64 text indistinguishable from any other string, and a tagged
// date becomes an object with a Number and a Content. Both used to reach the
// app as such -- an mDL portrait as a wall of base64 text where the SD-JWT and
// idemix paths would have shown an image, a birth date as a nested "Content"
// row. The functions here keep what the CBOR type said across that cache.

const (
	cborTagDateTimeString = 0    // RFC 3339 date-time text, tag 0
	cborTagFullDate       = 1004 // RFC 8943 full-date text, tag 1004
	mdocDataURIScheme     = "data:"
	mdocDataURIBase64     = ";base64,"
	mdocOctetStreamMIME   = "application/octet-stream"
)

// NormalizeMdocClaimValues rewrites, in place, the resolved element values of an
// mdoc into shapes that survive the JSON cache without losing the CBOR type:
//
//   - a byte string becomes a data URI, data:<mime>;base64,<payload>, with the
//     MIME type sniffed from the bytes (image/png, image/jpeg, image/jp2, ...)
//     and application/octet-stream when it is none the app can show;
//   - a tagged date (tag 0 date-time, tag 1004 full-date) becomes its text, the
//     string the issuer minted, so it displays and compares as a date rather
//     than as a tag object;
//   - a map keyed by any becomes a map keyed by string, which is what the JSON
//     encoder needs anyway.
//
// Arrays and maps are walked recursively. Run once, at parse time, before the
// values are marshalled; PromoteMdocDataURIs turns the data URIs back into
// image attribute values wherever the cached claims are rendered.
func NormalizeMdocClaimValues(resolved map[string]map[string]any) {
	for _, elements := range resolved {
		for element, value := range elements {
			elements[element] = normalizeMdocClaimValue(value)
		}
	}
}

func normalizeMdocClaimValue(value any) any {
	switch v := value.(type) {
	case []byte:
		return mdocBytesToDataURI(v)
	case cbor.Tag:
		if text, ok := v.Content.(string); ok && (v.Number == cborTagDateTimeString || v.Number == cborTagFullDate) {
			return text
		}
		return cbor.Tag{Number: v.Number, Content: normalizeMdocClaimValue(v.Content)}
	case []any:
		out := make([]any, len(v))
		for i, elem := range v {
			out[i] = normalizeMdocClaimValue(elem)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, elem := range v {
			out[k] = normalizeMdocClaimValue(elem)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for k, elem := range v {
			key, ok := k.(string)
			if !ok {
				key = stringifyMapKey(k)
			}
			out[key] = normalizeMdocClaimValue(elem)
		}
		return out
	default:
		return value
	}
}

// stringifyMapKey renders a non-string CBOR map key as text, the way the JSON
// cache would have had to anyway.
func stringifyMapKey(k any) string {
	return fmt.Sprint(k)
}

// mdocBytesToDataURI encodes a byte string element as a data URI whose MIME
// type says whether the bytes are an image the app can render.
func mdocBytesToDataURI(b []byte) string {
	mime := sniffMdocByteStringMIME(b)
	return mdocDataURIScheme + mime + mdocDataURIBase64 + base64.StdEncoding.EncodeToString(b)
}

// sniffMdocByteStringMIME names the content of a byte string element. ISO
// 18013-5 allows a portrait to be JPEG or JPEG 2000; PNG is what test issuers
// mint. net/http knows the first and the last; JPEG 2000 has to be matched by
// hand, both as a JP2 file (signature box) and as a bare codestream.
func sniffMdocByteStringMIME(b []byte) string {
	if hasPrefix(b, []byte{0x00, 0x00, 0x00, 0x0C, 'j', 'P', ' ', ' ', 0x0D, 0x0A, 0x87, 0x0A}) ||
		hasPrefix(b, []byte{0xFF, 0x4F, 0xFF, 0x51}) {
		return "image/jp2"
	}
	detected := http.DetectContentType(b)
	if strings.HasPrefix(detected, "image/") {
		// DetectContentType may append parameters; the app wants the bare type.
		if i := strings.IndexByte(detected, ';'); i >= 0 {
			detected = detected[:i]
		}
		return detected
	}
	return mdocOctetStreamMIME
}

func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// splitMdocDataURI returns the MIME type and base64 payload of a data URI that
// NormalizeMdocClaimValues produced, and false for any other string.
func splitMdocDataURI(s string) (mime, payload string, ok bool) {
	if !strings.HasPrefix(s, mdocDataURIScheme) {
		return "", "", false
	}
	rest := s[len(mdocDataURIScheme):]
	i := strings.Index(rest, mdocDataURIBase64)
	if i < 0 {
		return "", "", false
	}
	return rest[:i], rest[i+len(mdocDataURIBase64):], true
}

// PromoteMdocDataURIs rewrites, in place, the attribute values that carry a data
// URI from NormalizeMdocClaimValues: an image becomes a base64 image value the
// app renders as a picture; any other byte string becomes the bare base64 text
// the app showed before, so nothing is lost for content it cannot draw. Returns
// attrs for chaining.
func PromoteMdocDataURIs(attrs []clientmodels.Attribute) []clientmodels.Attribute {
	for i := range attrs {
		attrs[i].Value = promoteMdocDataURI(attrs[i].Value)
		attrs[i].RequestedValue = promoteMdocDataURI(attrs[i].RequestedValue)
	}
	return attrs
}

func promoteMdocDataURI(value *clientmodels.AttributeValue) *clientmodels.AttributeValue {
	if value == nil || value.Type != clientmodels.AttributeType_String || value.String == nil {
		return value
	}
	mime, payload, ok := splitMdocDataURI(*value.String)
	if !ok {
		return value
	}
	if strings.HasPrefix(mime, "image/") {
		return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Base64Image, Base64Image: &payload}
	}
	return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: &payload}
}

// MdocElementRef names one element of an mdoc: the [namespace, elementIdentifier]
// pair a DCQL claim path or a stored value lives at.
type MdocElementRef struct {
	Namespace string
	Element   string
}

// MdocElementRefFromPath reads the [namespace, elementIdentifier] prefix off a
// claim path. mdoc claim paths are exactly two components, but the paths the app
// echoes back from a permission screen may be deeper: FlattenClaimValue expands
// a structured element (a place of birth, driving privileges) into one row per
// leaf, and every row carries the full path it was reached by. Those rows all
// name the same element, which is disclosed whole -- an mdoc has no finer unit
// -- so the prefix is what matters. Returns false when the path has no such
// prefix.
func MdocElementRefFromPath(path []any) (MdocElementRef, bool) {
	if len(path) < 2 {
		return MdocElementRef{}, false
	}
	ns, ok := path[0].(string)
	if !ok {
		return MdocElementRef{}, false
	}
	el, ok := path[1].(string)
	if !ok {
		return MdocElementRef{}, false
	}
	return MdocElementRef{Namespace: ns, Element: el}, true
}

// BuildMdocAttributesForElements builds the attribute rows for the named elements
// of a stored mdoc: exactly the rows the credential list shows for them (same
// flattening of structured values, same display names and order, same image
// promotion), restricted to the elements asked for. This is what a permission
// screen and an activity log entry render for a disclosure, so a structured
// element looks the same there as on the card, and a date or portrait is a date
// or a picture in all three places.
//
// Elements the credential does not carry are skipped; the caller has already
// established which ones match.
func BuildMdocAttributesForElements(
	batch *models.CredentialBatch,
	resolved map[string]map[string]any,
	elements []MdocElementRef,
	locale string,
) []clientmodels.Attribute {
	display := ResolveBatchDisplay(batch, locale)

	topLevel := map[string]any{}
	for _, ref := range elements {
		nsMap, ok := resolved[ref.Namespace]
		if !ok {
			continue
		}
		value, ok := nsMap[ref.Element]
		if !ok {
			continue
		}
		sub, _ := topLevel[ref.Namespace].(map[string]any)
		if sub == nil {
			sub = map[string]any{}
			topLevel[ref.Namespace] = sub
		}
		sub[ref.Element] = value
	}

	attrs := []clientmodels.Attribute{}
	for _, namespace := range sortObjectKeys(topLevel, []any{}, display.ClaimOrder) {
		attrs = FlattenClaimValue(attrs, []any{namespace}, topLevel[namespace], display.ClaimNames, display.ClaimOrder)
	}
	return PromoteMdocDataURIs(attrs)
}

// UniqueMdocElementRefs reduces claim paths to the distinct elements they name,
// in first-seen order.
func UniqueMdocElementRefs(paths [][]any) []MdocElementRef {
	seen := map[MdocElementRef]struct{}{}
	refs := make([]MdocElementRef, 0, len(paths))
	for _, path := range paths {
		ref, ok := MdocElementRefFromPath(path)
		if !ok {
			continue
		}
		if _, dup := seen[ref]; dup {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}
