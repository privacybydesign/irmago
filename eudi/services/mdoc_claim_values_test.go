package services

import (
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/metadata"
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
	batch := &models.MdocBatch{Namespaces: models.MdocNamespaces(resolved)}

	attrs := BuildMdocAttributesForElements(batch, []MdocElementRef{
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

// ========== BuildMdocAttributesFromResolvedClaims ==========

func TestBuildMdocAttributesFromResolvedClaims_OrdersAndConvertsDisplayNames(t *testing.T) {
	claims := []metadata.ClaimsDescription{
		{
			Path: metadata.ClaimsPathPointer{"eu.europa.ec.av.1", "age_over_18"},
			Display: []metadata.Display{
				{Name: "Age Over 18", Locale: new(string)},
			},
		},
		{
			Path: metadata.ClaimsPathPointer{"eu.europa.ec.av.1", "age_over_21"},
			Display: []metadata.Display{
				// No locale set -- must fall back to DefaultFallbackLanguage,
				// not an empty-string key.
				{Name: "Age Over 21"},
			},
		},
	}
	*claims[0].Display[0].Locale = "en"

	resolved := map[string]map[string]any{
		"eu.europa.ec.av.1": {
			"age_over_21": false,
			"age_over_18": true,
		},
	}

	attrs := BuildMdocAttributesFromResolvedClaims(claims, resolved, "en")

	require.Len(t, attrs, 2)

	require.Equal(t, []any{"eu.europa.ec.av.1", "age_over_18"}, attrs[0].ClaimPath)
	require.NotNil(t, attrs[0].DisplayName)
	assert.Equal(t, "Age Over 18", *attrs[0].DisplayName)
	require.NotNil(t, attrs[0].Value)

	require.Equal(t, []any{"eu.europa.ec.av.1", "age_over_21"}, attrs[1].ClaimPath)
	require.NotNil(t, attrs[1].DisplayName)
	// No locale was set on this claim's display entry, so it was stored under
	// DefaultFallbackLanguage -- resolving for "en" (which equals the fallback
	// here) must still find it, not silently come back empty.
	assert.Equal(t, "Age Over 21", *attrs[1].DisplayName)
}

func TestBuildMdocAttributesFromResolvedClaims_NoMetadataStillEmitsValues(t *testing.T) {
	resolved := map[string]map[string]any{
		"eu.europa.ec.av.1": {
			"age_over_18": true,
			// Not an age_over_NN, so nothing derives a name for it: the value
			// still travels, unlabelled, exactly as before.
			"issuing_country": "NL",
		},
	}

	attrs := BuildMdocAttributesFromResolvedClaims(nil, resolved, "en")

	require.Len(t, attrs, 2)

	require.Equal(t, []any{"eu.europa.ec.av.1", "age_over_18"}, attrs[0].ClaimPath)
	require.NotNil(t, attrs[0].Value)
	// Derived from the element identifier, since no metadata named it.
	require.NotNil(t, attrs[0].DisplayName)
	assert.Equal(t, "Age Over 18", *attrs[0].DisplayName)

	require.Equal(t, []any{"eu.europa.ec.av.1", "issuing_country"}, attrs[1].ClaimPath)
	require.NotNil(t, attrs[1].Value)
	assert.Nil(t, attrs[1].DisplayName)
}

// A threshold the issuer never advertised is the case the derived name exists
// for: the EU reference issuer publishes thirteen age_over_NN claims and mints
// whatever it is asked for, so this arrives with a value and no metadata entry.
func TestBuildMdocAttributesFromResolvedClaims_DerivesUnadvertisedAgeOver(t *testing.T) {
	en := "en"
	claims := []metadata.ClaimsDescription{{
		Path:    metadata.ClaimsPathPointer{"eu.europa.ec.av.1", "age_over_18"},
		Display: []metadata.Display{{Name: "Age Over 18", Locale: &en}},
	}}
	resolved := map[string]map[string]any{
		"eu.europa.ec.av.1": {
			"age_over_18": true,
			"age_over_35": true,
		},
	}

	attrs := BuildMdocAttributesFromResolvedClaims(claims, resolved, "en")

	require.Len(t, attrs, 2)

	// Published metadata, unchanged.
	require.Equal(t, []any{"eu.europa.ec.av.1", "age_over_18"}, attrs[0].ClaimPath)
	require.NotNil(t, attrs[0].DisplayName)
	assert.Equal(t, "Age Over 18", *attrs[0].DisplayName)

	require.Equal(t, []any{"eu.europa.ec.av.1", "age_over_35"}, attrs[1].ClaimPath)
	require.NotNil(t, attrs[1].DisplayName)
	assert.Equal(t, "Age Over 35", *attrs[1].DisplayName)
}

// An issuer's own text wins over a derived name even when it is published under
// the namespace-less path shape, and even when it is in another language: the
// derived name is English only, so overriding a published nl label with it would
// make a Dutch wallet read worse, not better.
func TestBuildMdocAttributesFromResolvedClaims_PublishedBareElementNameWins(t *testing.T) {
	nl := "nl"
	claims := []metadata.ClaimsDescription{{
		Path:    metadata.ClaimsPathPointer{"age_over_18"},
		Display: []metadata.Display{{Name: "Ouder dan 18", Locale: &nl}},
	}}
	resolved := map[string]map[string]any{
		"eu.europa.ec.av.1": {"age_over_18": true},
	}

	attrs := BuildMdocAttributesFromResolvedClaims(claims, resolved, "nl")

	require.Len(t, attrs, 1)
	assert.Nil(t, attrs[0].DisplayName, "a bare-element publication is not overridden by the derived English name")
}

func TestDerivedMdocClaimName(t *testing.T) {
	for _, tc := range []struct {
		element string
		want    string
		ok      bool
	}{
		{element: "age_over_18", want: "Age Over 18", ok: true},
		{element: "age_over_9", want: "Age Over 9", ok: true},
		// NN is two digits, so 99 is the ceiling and 100 is past it.
		{element: "age_over_99", want: "Age Over 99", ok: true},
		{element: "age_over_00", want: "Age Over 00", ok: true},
		{element: "age_over_100", ok: false},
		{element: "age_over_120", ok: false},
		{element: "age_over_1234", ok: false},
		{element: "age_over_", ok: false},
		{element: "age_over_18a", ok: false},
		{element: "age_in_years", ok: false},
		{element: "issuing_country", ok: false},
		{element: "", ok: false},
	} {
		t.Run(tc.element, func(t *testing.T) {
			got, ok := DerivedMdocClaimName(tc.element)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}
