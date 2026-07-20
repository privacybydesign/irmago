package openid4vp

import (
	"net/url"
	"testing"

	"mdoc"
)

// TestDirectPostFormRoundTrips confirms NewDirectPostForm + ParseDirectPostForm
// is a faithful round trip: both the DeviceResponse and the state value
// come back out exactly as they went in, and the DeviceResponse still
// verifies correctly.
func TestDirectPostFormRoundTrips(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	attached, err := mdoc.AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := mdoc.NewDeviceResponse(*attached)

	queryId := "proof_of_age"
	wantState := "af0ifjsldkj"
	body, err := NewDirectPostForm(queryId, wantState, resp)
	if err != nil {
		t.Fatalf("NewDirectPostForm: %v", err)
	}

	gotResp, gotState, err := ParseDirectPostForm(body, queryId)
	if err != nil {
		t.Fatalf("ParseDirectPostForm: %v", err)
	}
	if gotState != wantState {
		t.Fatalf("expected state %q, got %q", wantState, gotState)
	}

	results, err := verifier.VerifyDeviceResponse(gotResp, namespace, docType, transcript)
	if err != nil {
		t.Fatalf("VerifyDeviceResponse: %v", err)
	}
	if len(results) != 1 || !results[0].Valid || !results[0].DeviceAuthValid {
		t.Fatalf("expected valid result, got %+v", results)
	}
}

// TestDirectPostFormShape confirms the body is a real
// application/x-www-form-urlencoded string with both vp_token and state
// as separate fields — not vp_token's JSON dumped raw, matching
// eudi/openid4vp/response.go's createAuthorizationResponseHttpRequest shape.
func TestDirectPostFormShape(t *testing.T) {
	_, _, _, presented, _, deviceAuthBytes, _, _ := buildHappyPathMDoc(t)
	attached, err := mdoc.AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := mdoc.NewDeviceResponse(*attached)

	body, err := NewDirectPostForm("proof_of_age", "af0ifjsldkj", resp)
	if err != nil {
		t.Fatalf("NewDirectPostForm: %v", err)
	}

	values, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("body is not valid application/x-www-form-urlencoded: %v", err)
	}
	if values.Get("vp_token") == "" {
		t.Fatalf("expected a non-empty vp_token field, got none")
	}
	if values.Get("state") != "af0ifjsldkj" {
		t.Fatalf("expected state field %q, got %q", "af0ifjsldkj", values.Get("state"))
	}
}

// TestDirectPostFormPreservesEmptyState confirms an empty state round-trips
// as empty, rather than being conflated with "field absent" or erroring.
func TestDirectPostFormPreservesEmptyState(t *testing.T) {
	_, _, _, presented, _, deviceAuthBytes, _, _ := buildHappyPathMDoc(t)
	attached, err := mdoc.AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := mdoc.NewDeviceResponse(*attached)

	body, err := NewDirectPostForm("proof_of_age", "", resp)
	if err != nil {
		t.Fatalf("NewDirectPostForm: %v", err)
	}
	_, gotState, err := ParseDirectPostForm(body, "proof_of_age")
	if err != nil {
		t.Fatalf("ParseDirectPostForm: %v", err)
	}
	if gotState != "" {
		t.Fatalf("expected empty state, got %q", gotState)
	}
}

// TestDirectPostFormRejectsMissingVPToken confirms a malformed body with
// no vp_token field errors out instead of returning a zero-value
// DeviceResponse silently.
func TestDirectPostFormRejectsMissingVPToken(t *testing.T) {
	body := "state=af0ifjsldkj"
	if _, _, err := ParseDirectPostForm(body, "proof_of_age"); err == nil {
		t.Fatalf("expected error for body missing vp_token, got none")
	}
}
