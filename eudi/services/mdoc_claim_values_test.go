package services

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// A one-pixel PNG, the portrait the mDL integration tests mint.
const testPortraitBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="

func testPortraitBytes(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(testPortraitBase64)
	require.NoError(t, err)
	return b
}

func TestNormalizeMdocClaimValuesTypesByteStringsAsImages(t *testing.T) {
	resolved := map[string]map[string]any{
		"org.iso.18013.5.1": {
			"portrait":        testPortraitBytes(t),
			"document_number": "X1234",
		},
	}

	NormalizeMdocClaimValues(resolved)

	require.Equal(t,
		"data:image/png;base64,"+testPortraitBase64,
		resolved["org.iso.18013.5.1"]["portrait"],
		"a byte string the wallet can draw is cached with its image type")
	require.Equal(t, "X1234", resolved["org.iso.18013.5.1"]["document_number"],
		"a text string is left alone")
}

func TestNormalizeMdocClaimValuesKeepsUnknownBytesAsOctetStream(t *testing.T) {
	resolved := map[string]map[string]any{
		"ns": {"biometric_template_face": []byte{0x01, 0x02, 0x03}},
	}

	NormalizeMdocClaimValues(resolved)

	require.Equal(t,
		"data:application/octet-stream;base64,AQID",
		resolved["ns"]["biometric_template_face"],
		"bytes that are not an image still say what they are")
}

func TestNormalizeMdocClaimValuesRecognisesJpeg2000(t *testing.T) {
	jp2 := []byte{0x00, 0x00, 0x00, 0x0C, 'j', 'P', ' ', ' ', 0x0D, 0x0A, 0x87, 0x0A, 0xFF}
	codestream := []byte{0xFF, 0x4F, 0xFF, 0x51, 0x00}

	require.Equal(t, "image/jp2", sniffMdocByteStringMIME(jp2), "JP2 signature box")
	require.Equal(t, "image/jp2", sniffMdocByteStringMIME(codestream), "bare J2K codestream")
}

func TestNormalizeMdocClaimValuesUnwrapsTaggedDates(t *testing.T) {
	resolved := map[string]map[string]any{
		"eu.europa.ec.eudi.pid.1": {
			"birth_date":    cbor.Tag{Number: 1004, Content: "1990-05-19"},
			"issuance_date": cbor.Tag{Number: 0, Content: "2026-09-04T10:00:00Z"},
			// A tag this package does not know keeps its shape, with its content
			// normalised.
			"other": cbor.Tag{Number: 42, Content: []byte{0x89, 'P', 'N', 'G'}},
		},
	}

	NormalizeMdocClaimValues(resolved)

	pid := resolved["eu.europa.ec.eudi.pid.1"]
	require.Equal(t, "1990-05-19", pid["birth_date"], "full-date (tag 1004) becomes its text")
	require.Equal(t, "2026-09-04T10:00:00Z", pid["issuance_date"], "date-time (tag 0) becomes its text")
	other, ok := pid["other"].(cbor.Tag)
	require.True(t, ok, "an unknown tag is kept as a tag")
	require.Equal(t, uint64(42), other.Number)
	require.IsType(t, "", other.Content, "but its byte-string content is normalised")
}

func TestNormalizeMdocClaimValuesWalksStructuredValues(t *testing.T) {
	resolved := map[string]map[string]any{
		"ns": {
			"place_of_birth": map[any]any{"country": "NL", "locality": "Amsterdam"},
			"nationality":    []any{"NL"},
			"driving_privileges": []any{
				map[any]any{"vehicle_category_code": "B", "issue_date": cbor.Tag{Number: 1004, Content: "2010-01-01"}},
			},
		},
	}

	NormalizeMdocClaimValues(resolved)

	require.Equal(t,
		map[string]any{"country": "NL", "locality": "Amsterdam"},
		resolved["ns"]["place_of_birth"],
		"a CBOR map keyed by any becomes a map keyed by string")
	require.Equal(t, []any{"NL"}, resolved["ns"]["nationality"])
	require.Equal(t,
		[]any{map[string]any{"vehicle_category_code": "B", "issue_date": "2010-01-01"}},
		resolved["ns"]["driving_privileges"],
		"normalisation reaches into arrays of maps")
}

func TestPromoteMdocDataURIs(t *testing.T) {
	image := "data:image/png;base64," + testPortraitBase64
	blob := "data:application/octet-stream;base64,AQID"
	plain := "X1234"
	attrs := []clientmodels.Attribute{
		{ClaimPath: []any{"ns", "portrait"}, Value: strPtrValue(image)},
		{ClaimPath: []any{"ns", "template"}, Value: strPtrValue(blob)},
		{ClaimPath: []any{"ns", "document_number"}, Value: strPtrValue(plain), RequestedValue: strPtrValue(plain)},
		{ClaimPath: []any{"ns", "portrait_again"}, Value: strPtrValue(image), RequestedValue: strPtrValue(image)},
		{ClaimPath: []any{"ns", "header"}},
	}

	PromoteMdocDataURIs(attrs)

	require.Equal(t, clientmodels.AttributeType_Base64Image, attrs[0].Value.Type)
	require.Equal(t, testPortraitBase64, *attrs[0].Value.Base64Image, "the image payload, without the data URI prefix")
	require.Nil(t, attrs[0].Value.String)

	require.Equal(t, clientmodels.AttributeType_String, attrs[1].Value.Type)
	require.Equal(t, "AQID", *attrs[1].Value.String, "bytes the app cannot draw show as the bare base64 text they showed before")

	require.Equal(t, plain, *attrs[2].Value.String, "a plain string is untouched")
	require.Equal(t, plain, *attrs[2].RequestedValue.String)

	require.Equal(t, clientmodels.AttributeType_Base64Image, attrs[3].RequestedValue.Type, "requested values are promoted too")

	require.Nil(t, attrs[4].Value, "a section header stays a header")
}

func TestMdocElementRefFromPath(t *testing.T) {
	ref, ok := MdocElementRefFromPath([]any{"ns", "el"})
	require.True(t, ok)
	require.Equal(t, MdocElementRef{Namespace: "ns", Element: "el"}, ref)

	ref, ok = MdocElementRefFromPath([]any{"ns", "el", "country"})
	require.True(t, ok, "a leaf path of a structured element names the element")
	require.Equal(t, MdocElementRef{Namespace: "ns", Element: "el"}, ref)

	_, ok = MdocElementRefFromPath([]any{"el"})
	require.False(t, ok, "a bare element has no namespace")

	_, ok = MdocElementRefFromPath([]any{"ns", 0})
	require.False(t, ok, "an element identifier is a string")
}

func TestUniqueMdocElementRefsReducesLeafPathsToElements(t *testing.T) {
	refs := UniqueMdocElementRefs([][]any{
		{"ns", "place_of_birth"},
		{"ns", "place_of_birth", "country"},
		{"ns", "place_of_birth", "locality"},
		{"ns", "nationality", 0},
		{"ns", "age_over_18"},
		{"bare"},
	})

	require.Equal(t, []MdocElementRef{
		{Namespace: "ns", Element: "place_of_birth"},
		{Namespace: "ns", Element: "nationality"},
		{Namespace: "ns", Element: "age_over_18"},
	}, refs, "one entry per element, first-seen order, paths without a namespace dropped")
}

func TestBuildMdocAttributesForElementsFlattensLikeTheCredentialList(t *testing.T) {
	resolved := map[string]map[string]any{
		"eu.europa.ec.av.1": {
			"age_over_18": true,
			"age_over_65": false,
			// Not requested below; must not appear.
			"age_over_21": true,
		},
		"org.iso.18013.5.1": {
			"portrait":       "data:image/png;base64," + testPortraitBase64,
			"place_of_birth": map[string]any{"country": "NL", "locality": "Amsterdam"},
		},
	}

	// The batch carries the same claims the list reads, so derived names resolve
	// exactly as they do there.
	payload, err := json.Marshal(resolved)
	require.NoError(t, err)
	batch := &models.CredentialBatch{Format: models.CredentialFormatMsoMdoc, ProcessedSdJwtPayload: datatypes.JSON(payload)}

	attrs := BuildMdocAttributesForElements(batch, resolved, []MdocElementRef{
		{Namespace: "eu.europa.ec.av.1", Element: "age_over_65"},
		{Namespace: "eu.europa.ec.av.1", Element: "age_over_18"},
		{Namespace: "org.iso.18013.5.1", Element: "portrait"},
		{Namespace: "org.iso.18013.5.1", Element: "place_of_birth"},
		{Namespace: "org.iso.18013.5.1", Element: "not_carried"},
	}, "en")

	paths := make([]string, len(attrs))
	for i, a := range attrs {
		paths[i] = clientmodels.ClaimPathKey(a.ClaimPath)
	}
	require.Equal(t, []string{
		// Namespaces and elements in the credential list's order (no metadata, so
		// alphabetical), not the request's order.
		clientmodels.ClaimPathKey([]any{"eu.europa.ec.av.1", "age_over_18"}),
		clientmodels.ClaimPathKey([]any{"eu.europa.ec.av.1", "age_over_65"}),
		// A structured element unfolds into a header row (named, like every mdoc
		// element the list shows, after itself when no metadata names it) and one
		// row per leaf.
		clientmodels.ClaimPathKey([]any{"org.iso.18013.5.1", "place_of_birth"}),
		clientmodels.ClaimPathKey([]any{"org.iso.18013.5.1", "place_of_birth", "country"}),
		clientmodels.ClaimPathKey([]any{"org.iso.18013.5.1", "place_of_birth", "locality"}),
		clientmodels.ClaimPathKey([]any{"org.iso.18013.5.1", "portrait"}),
	}, paths)

	require.Equal(t, "Age Over 18", *attrs[0].DisplayName, "a derived name where the metadata has none")
	require.Equal(t, true, *attrs[0].Value.Bool)
	require.Equal(t, false, *attrs[1].Value.Bool)
	require.Nil(t, attrs[2].Value, "the structured element itself is a section header")
	require.Equal(t, "place_of_birth", *attrs[2].DisplayName)
	require.Equal(t, "NL", *attrs[3].Value.String)
	require.Equal(t, clientmodels.AttributeType_Base64Image, attrs[5].Value.Type, "the portrait is a picture")
	require.Equal(t, testPortraitBase64, *attrs[5].Value.Base64Image)
}

func strPtrValue(s string) *clientmodels.AttributeValue {
	return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: &s}
}
