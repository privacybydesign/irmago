package mdoc

import (
	"crypto/x509"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestAttachDeviceSignedRoundTrips confirms AttachDeviceSigned populates
// MDoc.DeviceSigned with the exact deviceAuth bytes passed in, plus an
// empty (Tag24-wrapped) deviceNameSpaces map.
func TestAttachDeviceSignedRoundTrips(t *testing.T) {
	_, _, _, presented, _, deviceAuthBytes, _, _ := buildHappyPathMDoc(t)

	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	if attached.DeviceSigned == nil {
		t.Fatalf("expected DeviceSigned to be populated, got nil")
	}

	gotDeviceAuth := []byte(attached.DeviceSigned.DeviceAuth.DeviceSignature)
	if string(gotDeviceAuth) != string(deviceAuthBytes) {
		t.Fatalf("deviceAuth bytes mismatch: got %x, want %x", gotDeviceAuth, deviceAuthBytes)
	}

	emptyNS, err := tag24Unwrap[map[string]any](attached.DeviceSigned.NameSpaces)
	if err != nil {
		t.Fatalf("unwrap deviceNameSpaces: %v", err)
	}
	if len(emptyNS) != 0 {
		t.Fatalf("expected empty deviceNameSpaces, got %v", emptyNS)
	}

	// The original mdoc passed to AttachDeviceSigned must be untouched —
	// it returns a copy, not a mutation.
	if presented.DeviceSigned != nil {
		t.Fatalf("expected original mdoc to be unmodified, but DeviceSigned is set")
	}
}

// TestVerifyDeviceResponseSucceeds runs the full flow through the real
// DeviceResponse container instead of calling VerifyWithDeviceAuth
// directly, confirming the container-based path produces the same result.
func TestVerifyDeviceResponseSucceeds(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := NewDeviceResponse(*attached)

	results, err := verifier.VerifyDeviceResponse(resp, namespace, docType, transcript)
	if err != nil {
		t.Fatalf("VerifyDeviceResponse: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Valid {
		t.Fatalf("expected valid result, got error: %s", results[0].Error)
	}
	if !results[0].DeviceAuthValid {
		t.Fatalf("expected valid deviceAuth, got error: %s", results[0].Error)
	}
}

// TestVerifyDeviceResponseRejectsMissingDeviceSigned confirms a document
// without DeviceSigned attached is rejected with a descriptive error,
// rather than panicking on a nil dereference.
func TestVerifyDeviceResponseRejectsMissingDeviceSigned(t *testing.T) {
	_, _, verifier, presented, transcript, _, docType, namespace := buildHappyPathMDoc(t)

	resp := NewDeviceResponse(*presented) // never attached DeviceSigned

	_, err := verifier.VerifyDeviceResponse(resp, namespace, docType, transcript)
	if err == nil {
		t.Fatalf("expected error for document missing DeviceSigned, got none")
	}
}

// TestNewDeviceResponseSupportsMultipleDocuments confirms a DeviceResponse
// bundling more than one document verifies each one independently — two
// distinct holders' credentials from the same issuer, both correctly
// attached and signed, must both come back valid.
func TestNewDeviceResponseSupportsMultipleDocuments(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"
	transcript := SessionTranscript{
		DeviceEngagementBytes: []byte("test-engagement"),
		EReaderKeyBytes:       []byte("test-reader-key"),
		Handover:              "test-handover",
	}

	buildDoc := func(claims map[string]any, reveal []string) MDoc {
		holder, err := NewHolder()
		if err != nil {
			t.Fatalf("NewHolder: %v", err)
		}
		credential, err := issuer.Issue(docType, namespace, claims, holder.PublicKey())
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		presented, err := SelectiveDisclose(credential, namespace, reveal)
		if err != nil {
			t.Fatalf("SelectiveDisclose: %v", err)
		}
		deviceAuthBytes, err := holder.SignDeviceAuth(docType, transcript)
		if err != nil {
			t.Fatalf("SignDeviceAuth: %v", err)
		}
		attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
		if err != nil {
			t.Fatalf("AttachDeviceSigned: %v", err)
		}
		return *attached
	}

	doc1 := buildDoc(map[string]any{"age_over_18": true}, []string{"age_over_18"})
	doc2 := buildDoc(map[string]any{"age_over_18": true, "age_over_21": false}, []string{"age_over_18", "age_over_21"})

	resp := NewDeviceResponse(doc1, doc2)
	if len(resp.Documents) != 2 {
		t.Fatalf("expected 2 documents in DeviceResponse, got %d", len(resp.Documents))
	}

	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})
	results, err := verifier.VerifyDeviceResponse(resp, namespace, docType, transcript)
	if err != nil {
		t.Fatalf("VerifyDeviceResponse: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for i, result := range results {
		if !result.Valid {
			t.Fatalf("document %d: expected valid, got error: %s", i, result.Error)
		}
		if !result.DeviceAuthValid {
			t.Fatalf("document %d: expected valid deviceAuth, got error: %s", i, result.Error)
		}
	}
	if len(results[0].Attributes) != 1 {
		t.Fatalf("document 0: expected 1 disclosed attribute, got %d: %v", len(results[0].Attributes), results[0].Attributes)
	}
	if len(results[1].Attributes) != 2 {
		t.Fatalf("document 1: expected 2 disclosed attributes, got %d: %v", len(results[1].Attributes), results[1].Attributes)
	}
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
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}

	encoded, err := cbor.Marshal(attached.DeviceSigned.DeviceAuth)
	if err != nil {
		t.Fatalf("marshal DeviceAuth: %v", err)
	}

	var generic map[string]any
	if err := cbor.Unmarshal(encoded, &generic); err != nil {
		t.Fatalf("decode DeviceAuth generic: %v", err)
	}
	if _, isBytes := generic["deviceSignature"].([]byte); isBytes {
		t.Fatalf("deviceSignature encoded as an opaque byte string, not inline structured CBOR")
	}
}
