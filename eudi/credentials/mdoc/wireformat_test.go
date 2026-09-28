package mdoc

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"

	"github.com/privacybydesign/irmago/eudi/credentials/coseutil"
)

// Everything in this file is about bytes: the CBOR shape this package writes,
// the tag-24 and COSE encodings underneath it, the DeviceSigned container that
// carries them, and a credential from another implementation to check all of it
// against. Verification behaviour lives in verifier_test.go, issuance behaviour
// in issuer_test.go.

// ---------------------------------------------------------------------------
// Wire shape of a real DeviceResponse
// ---------------------------------------------------------------------------

// These tests pin the ISO 18013-5 wire shape of a real DeviceResponse at each
// position where a Go type could silently substitute its own encoding. They
// decode generically — into any, not into this package's structs — because a
// round trip through the same structs cannot detect a wrong shape: both sides
// simply agree on it. Every one of these assertions failed before the encoding
// was corrected, in each case because a []byte or a plain struct produced a
// byte-string or map wrapper no other implementation can read.

// buildWireDeviceResponse produces a fully populated DeviceResponse — issued,
// selectively disclosed, and device-signed — decoded generically.
func buildWireDeviceResponse(t *testing.T) (top map[any]any, namespace string) {
	t.Helper()

	_, _, _, presented, _, deviceAuthBytes, _, ns := buildHappyPathMDoc(t)

	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	require.NoError(t, err, "AttachDeviceSigned: %v", err)
	encoded, err := cbor.Marshal(NewDeviceResponse(*attached))
	require.NoError(t, err, "marshal DeviceResponse: %v", err)

	var generic any
	err = cbor.Unmarshal(encoded, &generic)
	require.NoError(t, err, "generic decode: %v", err)
	m, ok := generic.(map[any]any)
	require.True(t, ok, "DeviceResponse decoded as %T, want a CBOR map", generic)
	return m, ns
}

func wireDocument(t *testing.T, top map[any]any) map[any]any {
	t.Helper()
	docs, ok := top["documents"].([]any)
	require.True(t, ok, "documents decoded as %T, want an array", top["documents"])
	require.NotEmpty(t, docs, "documents array has no entries")
	doc, ok := docs[0].(map[any]any)
	require.True(t, ok, "document decoded as %T, want a CBOR map", docs[0])
	return doc
}

// TestWireIssuerAuthIsBareCoseSign1Array pins `IssuerAuth = COSE_Sign1`: the
// four-element array must sit inline. Encoded as a Go []byte it became a byte
// string wrapping the array, which is unreadable to anything that expects a
// COSE structure here (Multipaz does issuerSigned["issuerAuth"].asCoseSign1).
// The array must also be untagged — ISO uses RFC 8152's bare COSE_Sign1, while
// go-cose's Sign1Message writes the tag-18 COSE_Sign1_Tagged form.
func TestWireIssuerAuthIsBareCoseSign1Array(t *testing.T) {
	top, _ := buildWireDeviceResponse(t)
	doc := wireDocument(t, top)

	issuerSigned, ok := doc["issuerSigned"].(map[any]any)
	require.True(t, ok, "issuerSigned decoded as %T, want a CBOR map", doc["issuerSigned"])

	arr, ok := issuerSigned["issuerAuth"].([]any)
	require.True(t, ok, "issuerAuth decoded as %T, want a 4-element COSE_Sign1 array "+
		"(a []byte field here yields a byte string, a tagged message yields cbor.Tag)",
		issuerSigned["issuerAuth"])
	require.Len(t, arr, 4, "issuerAuth must be [protected, unprotected, payload, signature]")
	_, ok = arr[0].([]byte)
	require.True(t, ok, "issuerAuth[0] (protected headers) is %T, want a byte string", arr[0])
	_, ok = arr[1].(map[any]any)
	require.True(t, ok, "issuerAuth[1] (unprotected headers) is %T, want a map", arr[1])
	_, ok = arr[2].([]byte)
	require.True(t, ok, "issuerAuth[2] (payload) is %T, want a byte string", arr[2])
	_, ok = arr[3].([]byte)
	require.True(t, ok, "issuerAuth[3] (signature) is %T, want a byte string", arr[3])
}

// TestWireIssuerSignedItemsAreTag24 pins
// `IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)`: each namespace
// array element is the tag-24 value itself. Before Tag24Item carried its own
// marshaller, fxamacker/cbor encoded the one-field struct as
// {"EncodedItem": <bstr>} — a Go field name on the wire, and the tag-24 value
// buried one byte-string deeper than the spec allows.
func TestWireIssuerSignedItemsAreTag24(t *testing.T) {
	top, namespace := buildWireDeviceResponse(t)
	doc := wireDocument(t, top)

	issuerSigned := doc["issuerSigned"].(map[any]any)
	nameSpaces, ok := issuerSigned["nameSpaces"].(map[any]any)
	require.True(t, ok, "nameSpaces decoded as %T, want a CBOR map", issuerSigned["nameSpaces"])
	items, ok := nameSpaces[namespace].([]any)
	require.True(t, ok, "nameSpaces[%q] decoded as %T, want an array", namespace, nameSpaces[namespace])
	require.NotEmpty(t, items, "nameSpaces[%q] has no entries", namespace)

	for i, raw := range items {
		tag, ok := raw.(cbor.Tag)
		require.True(t, ok, "nameSpaces[%q][%d] is %T, want a tag-24 value "+
			"(a map here means the Go struct's field name leaked onto the wire)",
			namespace, i, raw)
		require.Equal(t, uint64(24), tag.Number, "nameSpaces[%q][%d] tag number", namespace, i)
		_, ok = tag.Content.([]byte)
		require.True(t, ok, "nameSpaces[%q][%d] tag content is %T, want a byte string", namespace, i, tag.Content)
	}
}

// TestWireDeviceSignedShape pins the two DeviceSigned positions:
// deviceNameSpaces is a tag-24 value (DeviceNameSpacesBytes), and
// deviceSignature is a bare COSE_Sign1 array with a detached (null) payload.
func TestWireDeviceSignedShape(t *testing.T) {
	top, _ := buildWireDeviceResponse(t)
	doc := wireDocument(t, top)

	deviceSigned, ok := doc["deviceSigned"].(map[any]any)
	require.True(t, ok, "deviceSigned decoded as %T, want a CBOR map", doc["deviceSigned"])

	tag, ok := deviceSigned["nameSpaces"].(cbor.Tag)
	require.True(t, ok, "deviceSigned.nameSpaces is %T, want a tag-24 value", deviceSigned["nameSpaces"])
	require.Equal(t, uint64(24), tag.Number, "deviceSigned.nameSpaces tag number")

	deviceAuth, ok := deviceSigned["deviceAuth"].(map[any]any)
	require.True(t, ok, "deviceAuth is %T, want a CBOR map", deviceSigned["deviceAuth"])
	arr, ok := deviceAuth["deviceSignature"].([]any)
	require.True(t, ok, "deviceSignature is %T, want a bare 4-element COSE_Sign1 array", deviceAuth["deviceSignature"])
	require.Len(t, arr, 4, "deviceSignature must have 4 elements")
	require.Nil(t, arr[2], "deviceSignature payload must be null (detached)")
}

// TestWireRoundTripsThroughGenericCBOR checks the fixed encoding is still
// readable back into this package's own types — that the shape was corrected
// rather than merely changed, and that Tag24Item.UnmarshalCBOR recovers the
// exact frozen bytes the digest is taken over.
func TestWireRoundTripsThroughGenericCBOR(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	require.NoError(t, err, "AttachDeviceSigned: %v", err)
	encoded, err := cbor.Marshal(NewDeviceResponse(*attached))
	require.NoError(t, err, "marshal: %v", err)

	var decoded DeviceResponse
	err = cbor.Unmarshal(encoded, &decoded)
	require.NoError(t, err, "decode DeviceResponse back into typed struct: %v", err)
	require.Len(t, decoded.Documents, 1, "want 1 document")

	original := presented.IssuerSigned.NameSpaces[namespace]
	roundTripped := decoded.Documents[0].IssuerSigned.NameSpaces[namespace]
	require.Len(t, roundTripped, len(original), "item count after round trip")
	for i := range original {
		require.Equal(t, original[i].EncodedItem, roundTripped[i].EncodedItem,
			"item %d's frozen bytes changed across the round trip — the digest would no longer match", i)
	}

	// A document that survived the real wire encoding must still verify.
	results, err := verifier.VerifyDeviceResponse(decoded, namespace, docType, transcript)
	require.NoError(t, err, "VerifyDeviceResponse: %v", err)
	require.Len(t, results, 1, "want 1 verification result")
	require.True(t, results[0].Valid, "re-decoded document did not verify: %s", results[0].Error)
	require.True(t, results[0].DeviceAuthValid, "re-decoded document's deviceAuth did not verify: %s", results[0].Error)
}

// ---------------------------------------------------------------------------
// Tag-24 helpers — wrap/unwrap round trip
// ---------------------------------------------------------------------------

// tag24TestPayload is a small fixture struct used only to exercise the
// tag24Wrap/tag24Unwrap round trip in isolation, without needing a real
// issuer/holder flow.
type tag24TestPayload struct {
	Foo string `cbor:"foo"`
	Bar uint64 `cbor:"bar"`
}

// TestTag24WrapUnwrapRoundTrip confirms tag24Unwrap is the exact inverse
// of tag24Wrap: wrapping a value then unwrapping it generically must
// return the original fields unchanged, and the wire bytes in between
// must actually carry a CBOR tag 24 (not just an opaque byte string).
func TestTag24WrapUnwrapRoundTrip(t *testing.T) {
	original := tag24TestPayload{Foo: "hello", Bar: 42}

	wrapped, err := tag24Wrap(original)
	require.NoError(t, err, "tag24Wrap: %v", err)

	var rawTag cbor.RawTag
	err = cbor.Unmarshal(wrapped, &rawTag)
	require.NoError(t, err, "expected wrapped bytes to decode as a CBOR tag: %v", err)
	require.Equal(t, uint64(24), rawTag.Number, "expected tag number 24")

	got, err := tag24Unwrap[tag24TestPayload](wrapped)
	require.NoError(t, err, "tag24Unwrap: %v", err)
	require.Equal(t, original, got, "round trip mismatch")
}

// TestTag24WrapWithModeUsesGivenEncMode confirms tag24WrapWithMode's inner
// payload is actually encoded with the EncMode passed in, rather than
// falling back to cbor.Marshal's default mode. Uses tdateEncMode's
// RFC3339 tag-0 encoding as the observable difference: the default mode
// would encode time.Time as a bare epoch integer with no tag at all.
func TestTag24WrapWithModeUsesGivenEncMode(t *testing.T) {
	type withTime struct {
		When time.Time `cbor:"when"`
	}
	payload := withTime{When: time.Date(2025, 6, 20, 8, 45, 29, 0, time.UTC)}

	wrapped, err := tag24WrapWithMode(payload, tdateEncMode)
	require.NoError(t, err, "tag24WrapWithMode: %v", err)

	inner := unwrapTag24Generic(t, wrapped)
	var raw map[string]cbor.RawMessage
	err = cbor.Unmarshal(inner, &raw)
	require.NoError(t, err, "decode inner generic: %v", err)
	whenRaw, ok := raw["when"]
	require.True(t, ok, "when field missing from decoded payload")
	require.NotEmpty(t, whenRaw, "when field is empty")
	require.Equal(t, byte(0xc0), whenRaw[0],
		"expected tag-0 (RFC3339) encoding for when — tdateEncMode was not applied")
}

// ---------------------------------------------------------------------------
// COSE key and validityInfo encoding inside the MSO
// ---------------------------------------------------------------------------

// TestCOSEKeyUsesIntegerMapKeys decodes the real MSO bytes produced by
// the issuer and checks — at the raw CBOR level — that deviceKeyInfo's
// map keys are CBOR integers (major type 0/1), not text strings, and that
// they are exactly the four labels 1/-1/-2/-3 and no others.
//
// The count is as load-bearing as the types. deviceKey is covered by the
// signed MSO digest, so any extra label changes what the issuer signs:
// cose.NewKeyFromPublic, for one, also sets Algorithm and would emit label 3.
// coseKeyFromECDSA builds the key label by label to avoid exactly that.
func TestCOSEKeyUsesIntegerMapKeys(t *testing.T) {
	issuer, deviceSigner, _, _, _, _, _, _ := buildHappyPathMDoc(t)
	_ = deviceSigner

	// Re-issue directly so we have the raw MSO payload bytes in hand.
	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"
	newHolder, _ := GenerateDeviceSigner()
	mdoc, err := issuer.Issue(docType, namespace, map[string]any{"age_over_18": true}, newHolder.PublicKey())
	require.NoError(t, err, "Issue: %v", err)

	// Decode COSE_Sign1 → MSO payload, then decode the MSO into a generic
	// map so we can inspect deviceKeyInfo.deviceKey's key types directly,
	// bypassing our own (possibly-wrong) struct tags.
	var raw map[string]cbor.RawMessage
	// issuerAuth is itself a COSE_Sign1; the payload field inside it is
	// the MSO. Easiest robust check: decode issuerAuth generically.
	var coseGeneric []any
	err = cbor.Unmarshal(mdoc.IssuerSigned.IssuerAuth, &coseGeneric)
	require.NoError(t, err, "decode cose generic: %v", err)
	require.GreaterOrEqual(t, len(coseGeneric), 3, "expected COSE_Sign1 array with >=3 elements")
	msoPayload, ok := coseGeneric[2].([]byte)
	require.True(t, ok, "payload element wrong type: %T", coseGeneric[2])

	// msoPayload is Tag24-wrapped (MobileSecurityObjectBytes = #6.24(bstr
	// .cbor MobileSecurityObject)) — unwrap that layer before decoding the
	// MSO map itself.
	msoInner := unwrapTag24Generic(t, msoPayload)
	err = cbor.Unmarshal(msoInner, &raw)
	require.NoError(t, err, "decode mso generic: %v", err)

	deviceKeyInfoRaw, ok := raw["deviceKeyInfo"]
	require.True(t, ok, "deviceKeyInfo missing from MSO")
	var dkiGeneric map[string]cbor.RawMessage
	err = cbor.Unmarshal(deviceKeyInfoRaw, &dkiGeneric)
	require.NoError(t, err, "decode deviceKeyInfo generic: %v", err)
	deviceKeyRaw, ok := dkiGeneric["deviceKey"]
	require.True(t, ok, "deviceKey missing from deviceKeyInfo")

	// Decode deviceKey as map[any]any to see actual key types.
	var keyMap map[any]any
	err = cbor.Unmarshal(deviceKeyRaw, &keyMap)
	require.NoError(t, err, "decode deviceKey as generic map: %v", err)

	for k := range keyMap {
		switch v := k.(type) {
		case int64:
			// negative keys decode as int64
		case uint64:
			// positive keys decode as uint64
			_ = v
		default:
			require.Fail(t, "unexpected deviceKey map key type",
				"key %v has type %T, want int64/uint64 (the label must be a CBOR integer, not a text string)", k, k)
		}
	}

	// Sanity: the four expected keys (1, -1, -2, -3) must exist.
	// Positive key (1) decodes as uint64; negative keys decode as int64.
	want := []int64{1, -1, -2, -3}
	for _, w := range want {
		found := false
		for k := range keyMap {
			switch kv := k.(type) {
			case int64:
				if kv == w {
					found = true
				}
			case uint64:
				if w >= 0 && kv == uint64(w) {
					found = true
				}
			}
			if found {
				break
			}
		}
		require.True(t, found, "deviceKey missing expected key %d (saw keys: %v)", w, keysOf(keyMap))
	}

	require.Len(t, keyMap, len(want),
		"deviceKey carries %d labels, want exactly %v — an extra label changes the signed MSO bytes (saw: %v)",
		len(keyMap), want, keysOf(keyMap))
}

// TestValidityInfoUsesRFC3339Tag decodes the real MSO bytes generically
// and confirms signed/validFrom/validUntil are encoded as CBOR tag 0
// (RFC3339 date-time string), matching the exact encoding shown in the
// spec's own worked example (`"signed": 0("2025-06-20T08:45:29Z")`) —
// not a bare Unix epoch integer, which is what this program produced
// before this fix and would not match a spec-conformant decoder's
// expectations for a real interop scenario.
func TestValidityInfoUsesRFC3339Tag(t *testing.T) {
	issuer, err := NewTestIssuer()
	require.NoError(t, err, "NewTestIssuer: %v", err)
	deviceSigner, _ := GenerateDeviceSigner()
	mdoc, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{"age_over_18": true}, deviceSigner.PublicKey())
	require.NoError(t, err, "Issue: %v", err)

	// Decode issuerAuth -> MSO payload bytes generically, without going
	// through our own MSO struct (which would just decode successfully
	// either way) — inspect the raw CBOR tag on the wire instead.
	var coseGeneric []any
	err = cbor.Unmarshal(mdoc.IssuerSigned.IssuerAuth, &coseGeneric)
	require.NoError(t, err, "decode cose generic: %v", err)
	msoPayload, ok := coseGeneric[2].([]byte)
	require.True(t, ok, "payload element wrong type: %T", coseGeneric[2])

	// msoPayload is Tag24-wrapped — unwrap that layer before decoding the
	// MSO map itself.
	msoInner := unwrapTag24Generic(t, msoPayload)
	var raw map[string]cbor.RawMessage
	err = cbor.Unmarshal(msoInner, &raw)
	require.NoError(t, err, "decode mso generic: %v", err)
	validityRaw, ok := raw["validityInfo"]
	require.True(t, ok, "validityInfo missing from MSO")

	var viGeneric map[string]cbor.RawMessage
	err = cbor.Unmarshal(validityRaw, &viGeneric)
	require.NoError(t, err, "decode validityInfo generic: %v", err)

	for _, field := range []string{"signed", "validFrom", "validUntil"} {
		fieldRaw, ok := viGeneric[field]
		require.True(t, ok, "validityInfo.%s missing", field)
		// A CBOR tag-0 value's first byte is 0xc0 (major type 6, tag 0).
		require.NotEmpty(t, fieldRaw, "validityInfo.%s is empty", field)
		require.Equal(t, byte(0xc0), fieldRaw[0],
			"validityInfo.%s is not tag-0 encoded — expected RFC3339 string per spec example", field)
	}
}

// ---------------------------------------------------------------------------
// The DeviceSigned container: assembly and encoding
// ---------------------------------------------------------------------------

// TestAttachDeviceSignedRoundTrips confirms AttachDeviceSigned populates
// MDoc.DeviceSigned with the exact deviceAuth bytes passed in, plus an
// empty (Tag24-wrapped) deviceNameSpaces map.
func TestAttachDeviceSignedRoundTrips(t *testing.T) {
	_, _, _, presented, _, deviceAuthBytes, _, _ := buildHappyPathMDoc(t)

	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	require.NoError(t, err, "AttachDeviceSigned: %v", err)
	require.NotNil(t, attached.DeviceSigned, "expected DeviceSigned to be populated")

	gotDeviceAuth := []byte(attached.DeviceSigned.DeviceAuth.DeviceSignature)
	require.Equal(t, deviceAuthBytes, gotDeviceAuth, "deviceAuth bytes mismatch")

	emptyNS, err := tag24Unwrap[map[string]any](attached.DeviceSigned.NameSpaces)
	require.NoError(t, err, "unwrap deviceNameSpaces: %v", err)
	require.Empty(t, emptyNS, "expected empty deviceNameSpaces")

	// The original mdoc passed to AttachDeviceSigned must be untouched —
	// it returns a copy, not a mutation.
	require.Nil(t, presented.DeviceSigned, "expected original mdoc to be unmodified, but DeviceSigned is set")
}

// TestDeviceSignedOmittedWhenNilPresentWhenAttached confirms the
// `deviceSigned,omitempty` tag on MDoc actually does something: a
// presented-but-not-yet-device-signed mdoc must encode with no
// "deviceSigned" key at all (not a null placeholder), and gains one only
// after AttachDeviceSigned — matching real ISO 18013-5, where deviceSigned
// simply doesn't exist until presentation time.
func TestDeviceSignedOmittedWhenNilPresentWhenAttached(t *testing.T) {
	_, _, _, presented, _, deviceAuthBytes, _, _ := buildHappyPathMDoc(t)

	beforeCBOR, err := cbor.Marshal(presented)
	require.NoError(t, err, "marshal presented mdoc: %v", err)
	var beforeGeneric map[string]cbor.RawMessage
	err = cbor.Unmarshal(beforeCBOR, &beforeGeneric)
	require.NoError(t, err, "decode presented mdoc generic: %v", err)
	_, present := beforeGeneric["deviceSigned"]
	require.False(t, present, "expected no deviceSigned key before AttachDeviceSigned, but found one")

	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	require.NoError(t, err, "AttachDeviceSigned: %v", err)
	afterCBOR, err := cbor.Marshal(attached)
	require.NoError(t, err, "marshal attached mdoc: %v", err)
	var afterGeneric map[string]cbor.RawMessage
	err = cbor.Unmarshal(afterCBOR, &afterGeneric)
	require.NoError(t, err, "decode attached mdoc generic: %v", err)
	_, present = afterGeneric["deviceSigned"]
	require.True(t, present, "expected deviceSigned key after AttachDeviceSigned, found none")
}

// TestDeviceAuthSignatureEncodesInline confirms DeviceAuth.DeviceSignature
// is embedded as real structured CBOR (here: go-cose's Sign1Message marshals
// with CBOR tag 18, COSE_Sign1_Tagged per RFC 9052) rather than re-encoded
// as an opaque byte string wrapping the same bytes — the latter is what a
// plain []byte field would produce instead of cbor.RawMessage, and would
// not match real ISO 18013-5's inline embedding of deviceSignature.
func TestDeviceAuthSignatureEncodesInline(t *testing.T) {
	_, _, _, presented, _, deviceAuthBytes, _, _ := buildHappyPathMDoc(t)
	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	require.NoError(t, err, "AttachDeviceSigned: %v", err)

	encoded, err := cbor.Marshal(attached.DeviceSigned.DeviceAuth)
	require.NoError(t, err, "marshal DeviceAuth: %v", err)

	var generic map[string]any
	err = cbor.Unmarshal(encoded, &generic)
	require.NoError(t, err, "decode DeviceAuth generic: %v", err)
	_, isBytes := generic["deviceSignature"].([]byte)
	require.False(t, isBytes, "deviceSignature encoded as an opaque byte string, not inline structured CBOR")
}

// TestDeviceAuthPayloadIsDetached confirms the transmitted deviceAuth
// COSE_Sign1 has payload = null (detached content), matching the exact
// wire format shown in the spec's deviceSignature example:
//
//	"deviceSignature": [ h'a10126', {}, null, h'...' ]
//
// Detached payload means the actual DeviceAuthentication bytes are signed
// but never sent — the verifier reassembles them from what it does have
// (its own session transcript, the requested docType, and the transmitted
// deviceNameSpaces) and supplies them before verifying (see
// VerifyWithDeviceAuth).
func TestDeviceAuthPayloadIsDetached(t *testing.T) {
	deviceSigner, err := GenerateDeviceSigner()
	require.NoError(t, err, "GenerateDeviceSigner: %v", err)
	transcript := SessionTranscript{
		DeviceEngagementBytes: []byte("test-engagement"),
		EReaderKeyBytes:       []byte("test-reader-key"),
		Handover:              "test-handover",
	}
	deviceAuthBytes, err := deviceSigner.SignDeviceAuth("eu.europa.ec.av.1", transcript)
	require.NoError(t, err, "SignDeviceAuth: %v", err)

	var arr []any
	err = cbor.Unmarshal(deviceAuthBytes, &arr)
	require.NoError(t, err, "decode deviceAuth generic: %v", err)
	require.Len(t, arr, 4, "expected 4-element COSE_Sign1 array")
	require.Nil(t, arr[2], "expected detached payload (nil/null)")
}

// TestNewDeviceResponseSupportsMultipleDocuments confirms a DeviceResponse
// bundling more than one document verifies each one independently — two
// distinct holders' credentials from the same issuer, both correctly
// attached and signed, must both come back valid.
func TestNewDeviceResponseSupportsMultipleDocuments(t *testing.T) {
	issuer, err := NewTestIssuer()
	require.NoError(t, err, "NewTestIssuer: %v", err)

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"
	transcript := SessionTranscript{
		DeviceEngagementBytes: []byte("test-engagement"),
		EReaderKeyBytes:       []byte("test-reader-key"),
		Handover:              "test-handover",
	}

	buildDoc := func(claims map[string]any, reveal []string) MDoc {
		deviceSigner, err := GenerateDeviceSigner()
		require.NoError(t, err, "GenerateDeviceSigner: %v", err)
		credential, err := issuer.Issue(docType, namespace, claims, deviceSigner.PublicKey())
		require.NoError(t, err, "Issue: %v", err)
		presented, err := SelectiveDisclose(credential, namespace, reveal)
		require.NoError(t, err, "SelectiveDisclose: %v", err)
		deviceAuthBytes, err := deviceSigner.SignDeviceAuth(docType, transcript)
		require.NoError(t, err, "SignDeviceAuth: %v", err)
		attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
		require.NoError(t, err, "AttachDeviceSigned: %v", err)
		return *attached
	}

	doc1 := buildDoc(map[string]any{"age_over_18": true}, []string{"age_over_18"})
	doc2 := buildDoc(map[string]any{"age_over_18": true, "age_over_21": false}, []string{"age_over_18", "age_over_21"})

	resp := NewDeviceResponse(doc1, doc2)
	require.Len(t, resp.Documents, 2, "expected 2 documents in DeviceResponse")

	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})
	results, err := verifier.VerifyDeviceResponse(resp, namespace, docType, transcript)
	require.NoError(t, err, "VerifyDeviceResponse: %v", err)
	require.Len(t, results, 2, "expected 2 results")

	for i, result := range results {
		require.True(t, result.Valid, "document %d: expected valid, got error: %s", i, result.Error)
		require.True(t, result.DeviceAuthValid, "document %d: expected valid deviceAuth, got error: %s", i, result.Error)
	}
	require.Len(t, results[0].Attributes, 1, "document 0: expected 1 disclosed attribute: %v", results[0].Attributes)
	require.Len(t, results[1].Attributes, 2, "document 1: expected 2 disclosed attributes: %v", results[1].Attributes)
}

// ---------------------------------------------------------------------------
// Cross-implementation vector
// ---------------------------------------------------------------------------

// Cross-implementation test vector. Everything else in this package checks our
// encoding against our own decoding, which cannot catch a shape both sides agree
// on but no third party can read; these tests check it against bytes this
// codebase did not produce.
//
// foreignEudiMdocHex is a real mDL issued by the EUDI reference stack, taken from
// multipaz's NonCanonicalIssuerOrderingTest (multipaz-longfellow, commonTest).
// Two properties make it worth pinning:
//
//   - Its single age_over_18 IssuerSignedItem is encoded in the order
//     random, digestID, elementValue, elementIdentifier. No Go struct emits that
//     order, so any code path that rebuilds the item instead of preserving the
//     issuer's bytes produces a different digest. That is a live bug in multipaz
//     itself: its data-class path re-encodes, the SHA-256 no longer matches the
//     MSO, and the Longfellow prover fails its consistency check with
//     MDOC_PROVER_GENERAL_FAILURE.
//   - It is signed by a real EUDI document signer, so it exercises our COSE_Sign1
//     reading against a signature we did not generate.
//
// docType org.iso.18013.5.1.mDL, validity 2026-04-22T07:34:51Z ..
// 2026-07-21T07:34:51Z. The validity window and the trust chain are deliberately
// NOT asserted here: the vector is expired and its IACA root is not one we trust,
// which is right for these tests — they are about encoding and signature
// handling, and Verify()'s own tests cover chain and validity policy.
const foreignEudiMdocHex = "" +
	"a367646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c6973737565725369676e6564a26a6e61" +
	"6d65537061636573a1716f72672e69736f2e31383031332e352e3181d8185864a46672616e646f6d58203cbe2b0aa012" +
	"12848ec8b76bb5be5ddc6934e2833a6bab79bc19d97a132f0586686469676573744944086c656c656d656e7456616c75" +
	"65647472756571656c656d656e744964656e7469666965726b6167655f6f7665725f31386a6973737565724175746884" +
	"43a10126a118215902e3308202df30820285a00302010202147f7968853983300992fd85ffab886aa11c89079e300a06" +
	"082a8648ce3d040302305c311e301c06035504030c1550494420497373756572204341202d205554203032312d302b06" +
	"0355040a0c24455544492057616c6c6574205265666572656e636520496d706c656d656e746174696f6e310b30090603" +
	"55040613025554301e170d3235303431303134333735325a170d3236303730343134333735315a305231143012060355" +
	"04030c0b504944204453202d203031312d302b060355040a0c24455544492057616c6c6574205265666572656e636520" +
	"496d706c656d656e746174696f6e310b30090603550406130255543059301306072a8648ce3d020106082a8648ce3d03" +
	"010703420004bb580016a8fcded14b37cfca5a8f254f581466ad16c28b95f6b3d1af9726d0cadc13ba67199de8fd0642" +
	"df020965a17e6dbfe36059f0df82dff4eacfb9b55e25a382012d30820129301f0603551d2304183016801462c7944728" +
	"bd0fa21620a79ac2499444f101d3c7301b0603551d110414301282106973737565722e65756469772e64657630160603" +
	"551d250101ff040c300a06082b8102020000010230430603551d1f043c303a3038a036a034863268747470733a2f2f70" +
	"726570726f642e706b692e65756469772e6465762f63726c2f7069645f43415f55545f30322e63726c301d0603551d0e" +
	"04160414aa5fe8a71910958cb4965693a0f6c313f9b211c1300e0603551d0f0101ff040403020780305d0603551d1204" +
	"563054865268747470733a2f2f6769746875622e636f6d2f65752d6469676974616c2d6964656e746974792d77616c6c" +
	"65742f6172636869746563747572652d616e642d7265666572656e63652d6672616d65776f726b300a06082a8648ce3d" +
	"0403020348003045022100d255483b2a4f722419c2965a049eb9b90339d8b9fd413d6f5185fd7e5f41115a022069e6de" +
	"ad1e1f17c0584fb2dcce1cca29bc10ff1b09acd110148264a7ea4bbc1a5903ecd8185903e7a766737461747573a26b73" +
	"74617475735f6c697374a26369647819185163757269786868747470733a2f2f6973737565722e65756469772e646576" +
	"2f746f6b656e5f7374617475735f6c6973742f46432f6f72672e69736f2e31383031332e352e312e6d444c2f61383031" +
	"653265662d666431302d343262642d386232352d6238326166623433383366306f6964656e7469666965725f6c697374" +
	"a2626964643632323563757269786668747470733a2f2f6973737565722e65756469772e6465762f6964656e74696669" +
	"65725f6c6973742f46432f6f72672e69736f2e31383031332e352e312e6d444c2f61383031653265662d666431302d34" +
	"3262642d386232352d62383261666234333833663067646f6354797065756f72672e69736f2e31383031332e352e312e" +
	"6d444c6776657273696f6e63312e306c76616c6964697479496e666fa3667369676e6564c074323032362d30342d3232" +
	"5430373a33343a35315a6976616c696446726f6dc074323032362d30342d32325430373a33343a35315a6a76616c6964" +
	"556e74696cc074323032362d30372d32315430373a33343a35315a6c76616c756544696765737473a1716f72672e6973" +
	"6f2e31383031332e352e31ac00582046b0ab1cf4fef9e767e2c728e58d2b1b3f93dbda81ba2b4dfccd374f10adc99601" +
	"5820fb9a93e9027b9ec48a51e5049900590dcef06713e736bc267785f0bd69c7e9c9025820a7903fc05f9ce1c70c0b26" +
	"9075327322d2c8c373a70fb71dfff6f8409a7e3122035820bcd9bcb368a64dd0ce08594766e2edd4667d0ab7bfde13c0" +
	"0f7b88db47e3364904582063b7795874a855798b362927af030655e7721786155a52c940e524fc7ded81610558202536" +
	"96193d43fbe53043e5ec3641534d6dc64c486da6a1ae9f10d28549d0e32a065820ba359c3647e32f4ca225948c0b95f4" +
	"a6281ad2c170a27a4fd0d09b8285a3e0cb075820b131ba6033a6449e9bb6d8166839d076b8676f787f7e6dbabfccc986" +
	"4ed1352f0858207bd809ea1ec20f25e3b4d3d9aa301aa5b4883430de2fa4790c4d55102e6ff7c109582083bd13070141" +
	"1402a2f082311ed9345cee17e1113a86b5df31d2441f15af7cbd0a5820a02cf53624cbb7b632ff583eb1b01fb9c9e616" +
	"a748acef1ac693d7468fe16d580b5820dbce4ef87c7b3c07fc04faaeb3696ec3772324ef01ebb1f93a90bcbf55cccd43" +
	"6d6465766963654b6579496e666fa1696465766963654b6579a401022001215820221ba0d434ad5ca47614d4975d16e5" +
	"e0187475bb4e39eda4f1103948bfe3aebd2258202e36f15556bc9abb7669bcda8f4c21244f17dde2b5df01df21b0e571" +
	"4a60922f6f646967657374416c676f726974686d675348412d3235365840e9fca6ab7698721a6208ebf3619da15bc2e0" +
	"b2700ad81ad00ba840a608cfac229518a800aa3749adc287c62fdda6c05c6e6a3e174421b03923d366d7514d2f5d6c64" +
	"65766963655369676e6564a26a6e616d65537061636573d81841a06a64657669636541757468a16f6465766963655369" +
	"676e61747572658443a10126a0f65840f5a35cc53287d0e1ca0d1f69c6e335cc2ee311fdd41c11daed48280c42a0938a" +
	"cbf6d9c714f81d2d7113092a852a5b3fe5d672aff688411338ec361d237e067f"

func foreignEudiMdoc(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(foreignEudiMdocHex)
	require.NoError(t, err, "decode vector hex: %v", err)
	return b
}

// foreignIssuerAuth decodes the vector's issuerAuth, which also asserts that our
// COSE reading accepts the bare (untagged) COSE_Sign1 array ISO 18013-5
// specifies at this position.
func foreignIssuerAuth(t *testing.T, m *MDoc) *cose.Sign1Message {
	t.Helper()
	msg, err := coseutil.DecodeSign1(m.IssuerSigned.IssuerAuth)
	require.NoError(t, err, "decode foreign issuerAuth as COSE_Sign1: %v", err)
	return msg
}

// TestInteropForeignEudiCredentialDecodes is the baseline: our types must be able
// to read a conformant third-party credential at all.
func TestInteropForeignEudiCredentialDecodes(t *testing.T) {
	var m MDoc
	err := cbor.Unmarshal(foreignEudiMdoc(t), &m)
	require.NoError(t, err, "our decoder rejected a real EUDI-issued mDL: %v", err)

	require.Equal(t, "org.iso.18013.5.1.mDL", m.DocType, "docType")
	items, ok := m.IssuerSigned.NameSpaces["org.iso.18013.5.1"]
	require.True(t, ok, "namespace org.iso.18013.5.1 missing: %v", m.IssuerSigned.NameSpaces)
	require.NotEmpty(t, items, "namespace org.iso.18013.5.1 empty")

	msg := foreignIssuerAuth(t, &m)
	mso, err := tag24Unwrap[MSO](msg.Payload)
	require.NoError(t, err, "unwrap foreign MSO: %v", err)
	require.Equal(t, m.DocType, mso.DocType, "MSO docType != envelope docType")
	require.Equal(t, "SHA-256", mso.DigestAlgorithm, "digestAlgorithm")
}

// TestInteropForeignEudiIssuerSignatureVerifies checks our COSE_Sign1 handling
// against a signature produced by another implementation: go-cose rebuilds the
// Sig_structure from the headers and payload as we decoded them, so a wrong
// reading of any of those three fails here.
func TestInteropForeignEudiIssuerSignatureVerifies(t *testing.T) {
	var m MDoc
	err := cbor.Unmarshal(foreignEudiMdoc(t), &m)
	require.NoError(t, err, "decode vector: %v", err)
	msg := foreignIssuerAuth(t, &m)

	rawChain, exists := msg.Headers.Unprotected[int64(33)]
	require.True(t, exists, "no x5chain in the vector's issuerAuth header 33")
	chain, ok := rawChain.([]any)
	if !ok {
		single, isSingle := rawChain.([]byte)
		require.True(t, isSingle, "x5chain has type %T", rawChain)
		chain = []any{single}
	}
	der, ok := chain[0].([]byte)
	require.True(t, ok, "x5chain[0] has type %T", chain[0])
	dsCert, err := x509.ParseCertificate(der)
	require.NoError(t, err, "parse the vector's document signer certificate: %v", err)

	verifier, err := cose.NewVerifier(cose.AlgorithmES256, dsCert.PublicKey)
	require.NoError(t, err, "create verifier from the foreign DS cert: %v", err)
	err = msg.Verify(nil, verifier)
	require.NoError(t, err, "a real EUDI issuer signature did not verify through our COSE path: %v", err)
}

// TestInteropForeignEudiIssuerSignedItemKeyOrderPreserved pins the property the
// vector was chosen for. The issuer wrote random first; a Go struct would write
// digestID first. Checking the bytes rather than the decoded value is the point —
// the decoded IssuerSignedItem is identical either way, and only the encoding
// differs, which is precisely what the digest is taken over.
func TestInteropForeignEudiIssuerSignedItemKeyOrderPreserved(t *testing.T) {
	var m MDoc
	err := cbor.Unmarshal(foreignEudiMdoc(t), &m)
	require.NoError(t, err, "decode vector: %v", err)

	items := m.IssuerSigned.NameSpaces["org.iso.18013.5.1"]
	var rawTag cbor.RawTag
	err = cbor.Unmarshal(items[0].EncodedItem, &rawTag)
	require.NoError(t, err, "decode tag 24: %v", err)
	var inner []byte
	err = cbor.Unmarshal(rawTag.Content, &inner)
	require.NoError(t, err, "unwrap tag 24 byte string: %v", err)

	// a4 = map(4), 66 = tstr(6), then "random" as the first key.
	wantPrefix := append([]byte{0xa4, 0x66}, []byte("random")...)
	got := inner
	if len(got) > 16 {
		got = got[:16]
	}
	require.True(t, bytes.HasPrefix(inner, wantPrefix),
		"IssuerSignedItem does not start with the issuer's own first key:\n got  %x\n want prefix %x", got, wantPrefix)
}

// TestInteropForeignEudiDigestsSurviveReEncoding is the regression test for the
// failure mode multipaz has. It runs the credential through the full path a stored
// credential takes on our side — decode, re-encode (as
// services.credential_format_parser_mdoc does), decode again — and then checks the
// digests with verifyNamespaceDigests, the same function Verify uses in
// production, rather than a hash reimplemented in the test.
func TestInteropForeignEudiDigestsSurviveReEncoding(t *testing.T) {
	var original MDoc
	err := cbor.Unmarshal(foreignEudiMdoc(t), &original)
	require.NoError(t, err, "decode vector: %v", err)
	mso, err := tag24Unwrap[MSO](foreignIssuerAuth(t, &original).Payload)
	require.NoError(t, err, "unwrap foreign MSO: %v", err)

	reencoded, err := cbor.Marshal(MDoc{DocType: original.DocType, IssuerSigned: original.IssuerSigned})
	require.NoError(t, err, "re-encode: %v", err)
	var roundTripped MDoc
	err = cbor.Unmarshal(reencoded, &roundTripped)
	require.NoError(t, err, "decode our own re-encoding: %v", err)

	require.NotEmpty(t, roundTripped.IssuerSigned.NameSpaces, "no namespaces survived the round trip")
	for ns, items := range roundTripped.IssuerSigned.NameSpaces {
		values, err := verifyNamespaceDigests(items, mso.ValueDigests[ns], sha256Digest)
		require.NoError(t, err, "digest check failed for namespace %s after a round trip through our types "+
			"(the issuer's IssuerSignedItem bytes were not preserved): %v", ns, err)
		require.NotEmpty(t, values, "namespace %s produced no verified values", ns)
	}

	// The issuer's signature is over these bytes, so they must come back unchanged.
	require.Equal(t, original.IssuerSigned.IssuerAuth, roundTripped.IssuerSigned.IssuerAuth,
		"issuerAuth bytes changed across the round trip — the issuer signature would no longer verify")
}
