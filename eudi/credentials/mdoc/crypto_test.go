package mdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// COSE KEY ENCODING — proves the keyasint fix actually works
// ============================================================

// TestCOSEKeyUsesIntegerMapKeys decodes the real MSO bytes produced by
// the issuer and checks — at the raw CBOR level — that deviceKeyInfo's
// map keys are CBOR integers (major type 0/1), not text strings. This
// is the concrete regression test for the COSEKey struct-tag fix.
func TestCOSEKeyUsesIntegerMapKeys(t *testing.T) {
	issuer, holder, _, _, _, _, _, _ := buildHappyPathMDoc(t)
	_ = issuer
	_ = holder

	// Re-issue directly so we have the raw MSO payload bytes in hand.
	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"
	newHolder, _ := NewHolder()
	mdoc, err := issuer.Issue(docType, namespace, map[string]any{"age_over_18": true}, newHolder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Decode COSE_Sign1 → MSO payload, then decode the MSO into a generic
	// map so we can inspect deviceKeyInfo.deviceKey's key types directly,
	// bypassing our own (possibly-wrong) struct tags.
	var raw map[string]cbor.RawMessage
	// issuerAuth is itself a COSE_Sign1; the payload field inside it is
	// the MSO. Easiest robust check: decode issuerAuth generically.
	var coseGeneric []any
	if err := cbor.Unmarshal(mdoc.IssuerSigned.IssuerAuth, &coseGeneric); err != nil {
		t.Fatalf("decode cose generic: %v", err)
	}
	if len(coseGeneric) < 3 {
		t.Fatalf("expected COSE_Sign1 array with >=3 elements, got %d", len(coseGeneric))
	}
	msoPayload, ok := coseGeneric[2].([]byte)
	if !ok {
		t.Fatalf("payload element wrong type: %T", coseGeneric[2])
	}

	if err := cbor.Unmarshal(msoPayload, &raw); err != nil {
		t.Fatalf("decode mso generic: %v", err)
	}

	deviceKeyInfoRaw, ok := raw["deviceKeyInfo"]
	if !ok {
		t.Fatalf("deviceKeyInfo missing from MSO")
	}
	var dkiGeneric map[string]cbor.RawMessage
	if err := cbor.Unmarshal(deviceKeyInfoRaw, &dkiGeneric); err != nil {
		t.Fatalf("decode deviceKeyInfo generic: %v", err)
	}
	deviceKeyRaw, ok := dkiGeneric["deviceKey"]
	if !ok {
		t.Fatalf("deviceKey missing from deviceKeyInfo")
	}

	// Decode deviceKey as map[any]any to see actual key types.
	var keyMap map[any]any
	if err := cbor.Unmarshal(deviceKeyRaw, &keyMap); err != nil {
		t.Fatalf("decode deviceKey as generic map: %v", err)
	}

	for k := range keyMap {
		switch v := k.(type) {
		case int64:
			// negative keys decode as int64
		case uint64:
			// positive keys decode as uint64
			_ = v
		default:
			t.Fatalf("deviceKey map key %v has type %T, want int64/uint64 (COSEKey struct tags missing ',keyasint')", k, k)
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
		if !found {
			t.Fatalf("deviceKey missing expected key %d (saw keys: %v)", w, keysOf(keyMap))
		}
	}
}

// ============================================================
// SPEC ALIGNMENT (AV Blueprint Annex A §A.11 worked example)
// ============================================================

// TestValidityInfoUsesRFC3339Tag decodes the real MSO bytes generically
// and confirms signed/validFrom/validUntil are encoded as CBOR tag 0
// (RFC3339 date-time string), matching the exact encoding shown in the
// spec's own worked example (`"signed": 0("2025-06-20T08:45:29Z")`) —
// not a bare Unix epoch integer, which is what this program produced
// before this fix and would not match a spec-conformant decoder's
// expectations for a real interop scenario.
func TestValidityInfoUsesRFC3339Tag(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, _ := NewHolder()
	mdoc, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Decode issuerAuth -> MSO payload bytes generically, without going
	// through our own MSO struct (which would just decode successfully
	// either way) — inspect the raw CBOR tag on the wire instead.
	var coseGeneric []any
	if err := cbor.Unmarshal(mdoc.IssuerSigned.IssuerAuth, &coseGeneric); err != nil {
		t.Fatalf("decode cose generic: %v", err)
	}
	msoPayload, ok := coseGeneric[2].([]byte)
	if !ok {
		t.Fatalf("payload element wrong type: %T", coseGeneric[2])
	}

	var raw map[string]cbor.RawMessage
	if err := cbor.Unmarshal(msoPayload, &raw); err != nil {
		t.Fatalf("decode mso generic: %v", err)
	}
	validityRaw, ok := raw["validityInfo"]
	if !ok {
		t.Fatalf("validityInfo missing from MSO")
	}

	var viGeneric map[string]cbor.RawMessage
	if err := cbor.Unmarshal(validityRaw, &viGeneric); err != nil {
		t.Fatalf("decode validityInfo generic: %v", err)
	}

	for _, field := range []string{"signed", "validFrom", "validUntil"} {
		fieldRaw, ok := viGeneric[field]
		if !ok {
			t.Fatalf("validityInfo.%s missing", field)
		}
		// A CBOR tag-0 value's first byte is 0xc0 (major type 6, tag 0).
		if len(fieldRaw) == 0 || fieldRaw[0] != 0xc0 {
			t.Fatalf("validityInfo.%s is not tag-0 encoded (first byte: %#x) — expected RFC3339 string per spec example", field, fieldRaw[0])
		}
	}
}
