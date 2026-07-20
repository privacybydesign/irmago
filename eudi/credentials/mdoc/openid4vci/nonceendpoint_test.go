package openid4vci

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestNewNonceResponseShape confirms NewNonceResponse's JSON output
// matches [OID4VCI] §7's Nonce Endpoint response shape — a bare
// {"c_nonce": "..."} object, nothing else.
func TestNewNonceResponseShape(t *testing.T) {
	resp := NewNonceResponse("abc123")

	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal nonce response: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode nonce response generic: %v", err)
	}

	want := map[string]any{"c_nonce": "abc123"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nonce response shape mismatch:\ngot:  %v\nwant: %v", got, want)
	}
}

// TestNewCNonceIsRandomAndOpaque confirms NewCNonce produces distinct,
// non-empty values across calls, rather than a fixed or predictable one.
func TestNewCNonceIsRandomAndOpaque(t *testing.T) {
	a, err := NewCNonce()
	if err != nil {
		t.Fatalf("NewCNonce: %v", err)
	}
	b, err := NewCNonce()
	if err != nil {
		t.Fatalf("NewCNonce: %v", err)
	}
	if a == "" || b == "" {
		t.Fatalf("expected non-empty nonces, got %q and %q", a, b)
	}
	if a == b {
		t.Fatalf("expected two distinct c_nonces, got the same value twice: %q", a)
	}
}
