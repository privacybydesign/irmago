package mdoc

import (
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// FULL HAPPY-PATH FLOW — dumps real mdoc CBOR bytes
// ============================================================

// TestFullIssuanceFlow_ProducesValidMDoc runs issuance → selective
// disclosure → deviceAuth → verification end to end, then prints the
// actual CBOR-encoded mdoc bytes (hex) so they can be independently
// inspected — e.g. pasted into https://cbor.me or decoded with any
// other CBOR/COSE tool to confirm this program produces spec-shaped
// output, not just output that satisfies its own verifier.
func TestFullIssuanceFlow_ProducesValidMDoc(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	// Dump the actual presented mdoc as CBOR bytes.
	mdocCBOR, err := cbor.Marshal(presented)
	if err != nil {
		t.Fatalf("marshal presented mdoc: %v", err)
	}
	t.Logf("presented mdoc CBOR (%d bytes):\n%s", len(mdocCBOR), hex.EncodeToString(mdocCBOR))

	// Dump the raw issuerAuth COSE_Sign1 bytes separately too — this is
	// the part a real verifier/relying-party library would decode first.
	t.Logf("issuerAuth COSE_Sign1 (%d bytes):\n%s",
		len(presented.IssuerSigned.IssuerAuth),
		hex.EncodeToString(presented.IssuerSigned.IssuerAuth))

	t.Logf("deviceAuth COSE_Sign1 (%d bytes):\n%s",
		len(deviceAuthBytes),
		hex.EncodeToString(deviceAuthBytes))

	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)

	if !result.Valid {
		t.Fatalf("expected valid mdoc, got error: %s", result.Error)
	}
	if !result.DeviceAuthValid {
		t.Fatalf("expected valid deviceAuth, got error: %s", result.Error)
	}
	if len(result.Attributes) != 1 {
		t.Fatalf("expected exactly 1 disclosed attribute, got %d: %v", len(result.Attributes), result.Attributes)
	}
	got, ok := result.Attributes["age_over_18"]
	if !ok {
		t.Fatalf("expected age_over_18 in disclosed attributes, got %v", result.Attributes)
	}
	if got != true {
		t.Fatalf("expected age_over_18 = true, got %v", got)
	}

	// age_over_16 / age_over_21 were withheld — must NOT be present.
	if _, present := result.Attributes["age_over_16"]; present {
		t.Fatalf("age_over_16 should have been withheld, but was disclosed")
	}
	if _, present := result.Attributes["age_over_21"]; present {
		t.Fatalf("age_over_21 should have been withheld, but was disclosed")
	}
}
