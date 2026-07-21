package openid4vci

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
)

// TestNewCredentialOfferMatchesBlueprintWorkedExample confirms
// NewCredentialOffer's JSON output matches the exact shape shown in the
// AV Blueprint's Annex A §A.10 worked example for a Proof of Age
// credential offer.
func TestNewCredentialOfferMatchesBlueprintWorkedExample(t *testing.T) {
	txCode := TxCode{
		Length:      4,
		InputMode:   "numeric",
		Description: "Please provide the one-time code sent via e-mail",
	}
	offer := NewCredentialOffer("https://credential-issuer.example.com", "oaKazRN8I0IbtZ0C7JuMn5", txCode)

	encoded, err := json.Marshal(offer)
	if err != nil {
		t.Fatalf("marshal offer: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode offer generic: %v", err)
	}

	const want = `{
		"credential_issuer": "https://credential-issuer.example.com",
		"credential_configuration_ids": ["proof_of_age"],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
				"tx_code": {
					"length": 4,
					"input_mode": "numeric",
					"description": "Please provide the one-time code sent via e-mail"
				}
			}
		}
	}`
	var wantGeneric map[string]any
	if err := json.Unmarshal([]byte(want), &wantGeneric); err != nil {
		t.Fatalf("decode want generic: %v", err)
	}

	if !reflect.DeepEqual(got, wantGeneric) {
		t.Fatalf("offer shape mismatch:\ngot:  %s\nwant: %s", encoded, want)
	}
}

// TestCredentialOfferRoundTrips confirms a JSON-marshaled offer, as a
// wallet would receive it, decodes back to the exact grant
// NewCredentialOffer was given.
func TestCredentialOfferRoundTrips(t *testing.T) {
	txCode := TxCode{Length: 4, InputMode: "numeric", Description: "test code"}
	offer := NewCredentialOffer("https://issuer.example.com", "some-code-123", txCode)

	encoded, err := json.Marshal(offer)
	if err != nil {
		t.Fatalf("marshal offer: %v", err)
	}

	var decoded CredentialOffer
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal offer: %v", err)
	}

	grant, err := decoded.PreAuthorizedGrant()
	if err != nil {
		t.Fatalf("PreAuthorizedGrant: %v", err)
	}
	if grant.PreAuthorizedCode != "some-code-123" {
		t.Fatalf("expected pre-authorized_code %q, got %q", "some-code-123", grant.PreAuthorizedCode)
	}
	if !reflect.DeepEqual(grant.TxCode, txCode) {
		t.Fatalf("expected tx_code %+v, got %+v", txCode, grant.TxCode)
	}
}

// TestPreAuthorizedGrantRejectsMissingCode confirms PreAuthorizedGrant
// errors on a zero-value offer instead of silently returning an empty
// grant.
func TestPreAuthorizedGrantRejectsMissingCode(t *testing.T) {
	var offer CredentialOffer
	if _, err := offer.PreAuthorizedGrant(); err == nil {
		t.Fatalf("expected error for offer with no pre-authorized_code, got none")
	}
}

// TestNewPreAuthorizedCodeIsRandomAndOpaque confirms NewPreAuthorizedCode
// produces distinct, non-empty values across calls, rather than a fixed
// or predictable one.
func TestNewPreAuthorizedCodeIsRandomAndOpaque(t *testing.T) {
	a, err := NewPreAuthorizedCode()
	if err != nil {
		t.Fatalf("NewPreAuthorizedCode: %v", err)
	}
	b, err := NewPreAuthorizedCode()
	if err != nil {
		t.Fatalf("NewPreAuthorizedCode: %v", err)
	}
	if a == "" || b == "" {
		t.Fatalf("expected non-empty codes, got %q and %q", a, b)
	}
	if a == b {
		t.Fatalf("expected two distinct pre-authorized_codes, got the same value twice: %q", a)
	}
}

// TestNewTxCodeGeneratesCorrectLengthNumericCode confirms NewTxCode
// produces a code matching its own declared length/input_mode, and that
// every digit is numeric (input_mode: "numeric").
func TestNewTxCodeGeneratesCorrectLengthNumericCode(t *testing.T) {
	code, meta, err := NewTxCode(4, "Please provide the one-time code sent via e-mail")
	if err != nil {
		t.Fatalf("NewTxCode: %v", err)
	}
	if len(code) != 4 {
		t.Fatalf("expected code of length 4, got %q (length %d)", code, len(code))
	}
	if _, err := strconv.Atoi(code); err != nil {
		t.Fatalf("expected numeric code, got %q: %v", code, err)
	}
	if meta.Length != 4 || meta.InputMode != "numeric" {
		t.Fatalf("unexpected tx_code metadata: %+v", meta)
	}
}

// TestNewTxCodeRejectsNonPositiveLength confirms NewTxCode errors on a
// zero or negative length instead of returning a malformed code.
func TestNewTxCodeRejectsNonPositiveLength(t *testing.T) {
	if _, _, err := NewTxCode(0, "desc"); err == nil {
		t.Fatalf("expected error for zero length, got none")
	}
	if _, _, err := NewTxCode(-1, "desc"); err == nil {
		t.Fatalf("expected error for negative length, got none")
	}
}
