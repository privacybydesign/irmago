package openid4vp

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestNewAuthorizationRequestShape confirms NewAuthorizationRequest's
// JSON output carries all the fields a real OpenID4VP Authorization
// Request needs, with response_mode fixed to "direct_post".
func TestNewAuthorizationRequestShape(t *testing.T) {
	dcqlQuery := NewDCQLQuery("proof_of_age", "eu.europa.ec.av.1", "eu.europa.ec.av.1", []string{"age_over_18"})
	req := NewAuthorizationRequest("redirect_uri:https://verifier.example.com/response", "https://verifier.example.com/response", "n-0S6_WzA2Mj", "some-state", dcqlQuery)

	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode request generic: %v", err)
	}

	if got["client_id"] != "redirect_uri:https://verifier.example.com/response" {
		t.Fatalf("unexpected client_id: %v", got["client_id"])
	}
	if got["response_uri"] != "https://verifier.example.com/response" {
		t.Fatalf("unexpected response_uri: %v", got["response_uri"])
	}
	if got["nonce"] != "n-0S6_WzA2Mj" {
		t.Fatalf("unexpected nonce: %v", got["nonce"])
	}
	if got["state"] != "some-state" {
		t.Fatalf("unexpected state: %v", got["state"])
	}
	if got["response_mode"] != "direct_post" {
		t.Fatalf("expected response_mode %q, got %v", "direct_post", got["response_mode"])
	}
	if _, ok := got["dcql_query"]; !ok {
		t.Fatalf("expected a dcql_query field, got none")
	}
}

// TestAuthorizationRequestRoundTrips confirms a request built by
// NewAuthorizationRequest decodes back — as a wallet receiving it over
// the wire would — to the exact same DCQL query, session-binding values,
// and state it was built with.
func TestAuthorizationRequestRoundTrips(t *testing.T) {
	dcqlQuery := NewDCQLQuery("proof_of_age", "eu.europa.ec.av.1", "eu.europa.ec.av.1", []string{"age_over_18"})
	req := NewAuthorizationRequest("client-1", "https://verifier.example.com/response", "nonce-1", "state-1", dcqlQuery)

	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var received AuthorizationRequest
	if err := json.Unmarshal(encoded, &received); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	if received.ClientId != req.ClientId || received.ResponseUri != req.ResponseUri ||
		received.Nonce != req.Nonce || received.State != req.State {
		t.Fatalf("round-tripped session-binding values don't match:\ngot:  %+v\nwant: %+v", received, req)
	}
	if !reflect.DeepEqual(received.DcqlQuery, dcqlQuery) {
		t.Fatalf("round-tripped dcql_query doesn't match:\ngot:  %+v\nwant: %+v", received.DcqlQuery, dcqlQuery)
	}

	ns, attrs, err := received.DcqlQuery.RequestedAttributes("eu.europa.ec.av.1")
	if err != nil {
		t.Fatalf("RequestedAttributes: %v", err)
	}
	if ns != "eu.europa.ec.av.1" || len(attrs) != 1 || attrs[0] != "age_over_18" {
		t.Fatalf("unexpected requested attributes: ns=%q attrs=%v", ns, attrs)
	}
}

// TestAuthorizationRequestSessionTranscriptMatchesDirectCall confirms
// AuthorizationRequest.SessionTranscript produces the exact same
// SessionTranscript as calling NewOpenID4VPSessionTranscript directly
// with the request's own ClientId/Nonce/ResponseUri.
func TestAuthorizationRequestSessionTranscriptMatchesDirectCall(t *testing.T) {
	dcqlQuery := NewDCQLQuery("proof_of_age", "eu.europa.ec.av.1", "eu.europa.ec.av.1", []string{"age_over_18"})
	req := NewAuthorizationRequest("client-1", "https://verifier.example.com/response", "nonce-1", "state-1", dcqlQuery)

	got, err := req.SessionTranscript()
	if err != nil {
		t.Fatalf("SessionTranscript: %v", err)
	}
	want, err := NewOpenID4VPSessionTranscript(req.ClientId, req.Nonce, req.ResponseUri)
	if err != nil {
		t.Fatalf("NewOpenID4VPSessionTranscript: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SessionTranscript mismatch:\ngot:  %+v\nwant: %+v", got, want)
	}
}
