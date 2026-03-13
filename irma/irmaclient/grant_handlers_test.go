package irmaclient

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/privacybydesign/irmago/eudi/oauth2"
)

// mockRoundTripper implements http.RoundTripper for testing
type mockRoundTripper struct {
	statusCode int
	respBody   []byte
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(bytes.NewReader(m.respBody)),
		Header:     make(http.Header),
	}
	return resp, nil
}

func TestPushAuthorizationRequest_Success(t *testing.T) {
	expectedRequestUri := "urn:example:request_uri"
	parResp := oauth2.PushedAuthorizationResponse{
		RequestUri: expectedRequestUri,
		ExpiresIn:  60,
	}
	respBody, _ := json.Marshal(parResp)

	client := &http.Client{
		Transport: &mockRoundTripper{
			statusCode: http.StatusCreated,
			respBody:   respBody,
		},
	}

	handler := &AuthorizationCodeFlowHandler{httpClient: client}
	payload := url.Values{}
	payload.Add("foo", "bar")

	result, err := handler.pushAuthorizationRequest("https://example.com/par", payload)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result.RequestUri != expectedRequestUri {
		t.Errorf("expected RequestUri %s, got %s", expectedRequestUri, result.RequestUri)
	}
}

func TestPushAuthorizationRequest_ErrorStatusWithErrorResponse(t *testing.T) {
	errDesc := "invalid request"
	errUri := "https://example.com/error"
	errResp := oauth2.ErrorResponse{
		Error:            "invalid_request",
		ErrorDescription: &errDesc,
		ErrorUri:         &errUri,
	}
	respBody, _ := json.Marshal(errResp)

	client := &http.Client{
		Transport: &mockRoundTripper{
			statusCode: http.StatusBadRequest,
			respBody:   respBody,
		},
	}

	handler := &AuthorizationCodeFlowHandler{httpClient: client}
	payload := url.Values{}
	payload.Add("foo", "bar")

	_, err := handler.pushAuthorizationRequest("https://example.com/par", payload)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "invalid_request") || !contains(err.Error(), errDesc) || !contains(err.Error(), errUri) {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPushAuthorizationRequest_ErrorStatusWithInvalidJSON(t *testing.T) {
	client := &http.Client{
		Transport: &mockRoundTripper{
			statusCode: http.StatusBadRequest,
			respBody:   []byte("not json"),
		},
	}

	handler := &AuthorizationCodeFlowHandler{httpClient: client}
	payload := url.Values{}
	payload.Add("foo", "bar")

	_, err := handler.pushAuthorizationRequest("https://example.com/par", payload)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "pushed authorization request returned status code") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPushAuthorizationRequest_SuccessWithInvalidJSON(t *testing.T) {
	client := &http.Client{
		Transport: &mockRoundTripper{
			statusCode: http.StatusCreated,
			respBody:   []byte("not json"),
		},
	}

	handler := &AuthorizationCodeFlowHandler{httpClient: client}
	payload := url.Values{}
	payload.Add("foo", "bar")

	_, err := handler.pushAuthorizationRequest("https://example.com/par", payload)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "failed to decode pushed authorization response") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// Helper to check if substring is in string
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
