package mdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

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
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	encoded, err := cbor.Marshal(NewDeviceResponse(*attached))
	if err != nil {
		t.Fatalf("marshal DeviceResponse: %v", err)
	}

	var generic any
	if err := cbor.Unmarshal(encoded, &generic); err != nil {
		t.Fatalf("generic decode: %v", err)
	}
	m, ok := generic.(map[any]any)
	if !ok {
		t.Fatalf("DeviceResponse decoded as %T, want a CBOR map", generic)
	}
	return m, ns
}

func wireDocument(t *testing.T, top map[any]any) map[any]any {
	t.Helper()
	docs, ok := top["documents"].([]any)
	if !ok || len(docs) == 0 {
		t.Fatalf("documents decoded as %T with no entries", top["documents"])
	}
	doc, ok := docs[0].(map[any]any)
	if !ok {
		t.Fatalf("document decoded as %T, want a CBOR map", docs[0])
	}
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
	if !ok {
		t.Fatalf("issuerSigned decoded as %T, want a CBOR map", doc["issuerSigned"])
	}

	arr, ok := issuerSigned["issuerAuth"].([]any)
	if !ok {
		t.Fatalf("issuerAuth decoded as %T, want a 4-element COSE_Sign1 array "+
			"(a []byte field here yields a byte string, a tagged message yields cbor.Tag)",
			issuerSigned["issuerAuth"])
	}
	if len(arr) != 4 {
		t.Fatalf("issuerAuth has %d elements, want 4 [protected, unprotected, payload, signature]", len(arr))
	}
	if _, ok := arr[0].([]byte); !ok {
		t.Errorf("issuerAuth[0] (protected headers) is %T, want a byte string", arr[0])
	}
	if _, ok := arr[1].(map[any]any); !ok {
		t.Errorf("issuerAuth[1] (unprotected headers) is %T, want a map", arr[1])
	}
	if _, ok := arr[2].([]byte); !ok {
		t.Errorf("issuerAuth[2] (payload) is %T, want a byte string", arr[2])
	}
	if _, ok := arr[3].([]byte); !ok {
		t.Errorf("issuerAuth[3] (signature) is %T, want a byte string", arr[3])
	}
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
	if !ok {
		t.Fatalf("nameSpaces decoded as %T, want a CBOR map", issuerSigned["nameSpaces"])
	}
	items, ok := nameSpaces[namespace].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("nameSpaces[%q] decoded as %T with no entries", namespace, nameSpaces[namespace])
	}

	for i, raw := range items {
		tag, ok := raw.(cbor.Tag)
		if !ok {
			t.Fatalf("nameSpaces[%q][%d] is %T, want a tag-24 value "+
				"(a map here means the Go struct's field name leaked onto the wire)",
				namespace, i, raw)
		}
		if tag.Number != 24 {
			t.Errorf("nameSpaces[%q][%d] has tag %d, want 24", namespace, i, tag.Number)
		}
		if _, ok := tag.Content.([]byte); !ok {
			t.Errorf("nameSpaces[%q][%d] tag content is %T, want a byte string", namespace, i, tag.Content)
		}
	}
}

// TestWireDeviceSignedShape pins the two DeviceSigned positions:
// deviceNameSpaces is a tag-24 value (DeviceNameSpacesBytes), and
// deviceSignature is a bare COSE_Sign1 array with a detached (null) payload.
func TestWireDeviceSignedShape(t *testing.T) {
	top, _ := buildWireDeviceResponse(t)
	doc := wireDocument(t, top)

	deviceSigned, ok := doc["deviceSigned"].(map[any]any)
	if !ok {
		t.Fatalf("deviceSigned decoded as %T, want a CBOR map", doc["deviceSigned"])
	}

	tag, ok := deviceSigned["nameSpaces"].(cbor.Tag)
	if !ok {
		t.Fatalf("deviceSigned.nameSpaces is %T, want a tag-24 value", deviceSigned["nameSpaces"])
	}
	if tag.Number != 24 {
		t.Errorf("deviceSigned.nameSpaces has tag %d, want 24", tag.Number)
	}

	deviceAuth, ok := deviceSigned["deviceAuth"].(map[any]any)
	if !ok {
		t.Fatalf("deviceAuth is %T, want a CBOR map", deviceSigned["deviceAuth"])
	}
	arr, ok := deviceAuth["deviceSignature"].([]any)
	if !ok {
		t.Fatalf("deviceSignature is %T, want a bare 4-element COSE_Sign1 array", deviceAuth["deviceSignature"])
	}
	if len(arr) != 4 {
		t.Fatalf("deviceSignature has %d elements, want 4", len(arr))
	}
	if arr[2] != nil {
		t.Errorf("deviceSignature payload is %v, want null (detached)", arr[2])
	}
}

// TestWireRoundTripsThroughGenericCBOR checks the fixed encoding is still
// readable back into this package's own types — that the shape was corrected
// rather than merely changed, and that Tag24Item.UnmarshalCBOR recovers the
// exact frozen bytes the digest is taken over.
func TestWireRoundTripsThroughGenericCBOR(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	encoded, err := cbor.Marshal(NewDeviceResponse(*attached))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded DeviceResponse
	if err := cbor.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode DeviceResponse back into typed struct: %v", err)
	}
	if len(decoded.Documents) != 1 {
		t.Fatalf("got %d documents, want 1", len(decoded.Documents))
	}

	original := presented.IssuerSigned.NameSpaces[namespace]
	roundTripped := decoded.Documents[0].IssuerSigned.NameSpaces[namespace]
	if len(roundTripped) != len(original) {
		t.Fatalf("got %d items after round trip, want %d", len(roundTripped), len(original))
	}
	for i := range original {
		if string(roundTripped[i].EncodedItem) != string(original[i].EncodedItem) {
			t.Errorf("item %d's frozen bytes changed across the round trip — the digest would no longer match", i)
		}
	}

	// A document that survived the real wire encoding must still verify.
	results, err := verifier.VerifyDeviceResponse(decoded, namespace, docType, transcript)
	if err != nil {
		t.Fatalf("VerifyDeviceResponse: %v", err)
	}
	if len(results) != 1 || !results[0].Valid || !results[0].DeviceAuthValid {
		t.Fatalf("re-decoded document did not verify: valid=%v deviceAuth=%v err=%q",
			results[0].Valid, results[0].DeviceAuthValid, results[0].Error)
	}
}

// TestVerifierAcceptsTaggedCoseSign1 pins the deliberate asymmetry in
// decodeCoseSign1: this package writes the bare array ISO 18013-5 specifies,
// but must keep reading the tag-18 form, since implementations differ on it and
// the tag carries no security meaning (it is outside Sig_structure).
func TestVerifierAcceptsTaggedCoseSign1(t *testing.T) {
	_, _, verifier, presented, _, _, _, namespace := buildHappyPathMDoc(t)

	// Re-serialize the same issuerAuth in the tagged form by prefixing tag 18.
	untagged := presented.IssuerSigned.IssuerAuth
	tagged := append([]byte{0xd2}, untagged...)

	retagged := *presented
	retagged.IssuerSigned.IssuerAuth = cbor.RawMessage(tagged)

	result := verifier.Verify(&retagged, namespace)
	if !result.Valid {
		t.Fatalf("tagged COSE_Sign1 was rejected, but the tag is not security-relevant: %s", result.Error)
	}
}
