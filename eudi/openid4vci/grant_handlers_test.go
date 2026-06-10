package openid4vci

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
	if !contains(err.Error(), "failed to decode Pushed Authorization Request error response") {
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
	if !contains(err.Error(), "failed to decode Pushed Authorization Response") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// Helper to check if substring is in string
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

func TestVerifyAuthorizationState(t *testing.T) {
	expected := "the-expected-state"
	matching := expected
	mismatch := "some-other-state"
	empty := ""

	tests := []struct {
		name     string
		returned *string
		wantErr  bool
	}{
		{name: "matching state → ok", returned: &matching, wantErr: false},
		{name: "different state → error", returned: &mismatch, wantErr: true},
		{name: "missing state fails closed → error", returned: nil, wantErr: true},
		{name: "empty state vs non-empty expected → error", returned: &empty, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyAuthorizationState(expected, tc.returned)
			if tc.wantErr {
				if err == nil {
					t.Errorf("verifyAuthorizationState(%q, %v) = nil, want error", expected, tc.returned)
				}
			} else if err != nil {
				t.Errorf("verifyAuthorizationState(%q, %v) = %v, want nil", expected, tc.returned, err)
			}
		})
	}
}

func TestParseAuthorizationCallback(t *testing.T) {
	ptr := func(s string) *string { return &s }

	tests := []struct {
		name        string
		callbackURL *string
		wantCode    string
		wantState   string
		wantErr     bool
	}{
		{
			name:        "code and state",
			callbackURL: ptr("https://open.yivi.app/-/auth-callback?code=abc123&state=xyz789"),
			wantCode:    "abc123",
			wantState:   "xyz789",
		},
		{
			name:        "code without state yields empty state (caller fails closed)",
			callbackURL: ptr("https://open.yivi.app/-/auth-callback?code=abc123"),
			wantCode:    "abc123",
			wantState:   "",
		},
		{
			name:        "error response with description",
			callbackURL: ptr("https://open.yivi.app/-/auth-callback?error=access_denied&error_description=nope&state=xyz789"),
			wantErr:     true,
		},
		{
			name:        "error response without description",
			callbackURL: ptr("https://open.yivi.app/-/auth-callback?error=server_error"),
			wantErr:     true,
		},
		{
			name:        "neither code nor error",
			callbackURL: ptr("https://open.yivi.app/-/auth-callback?state=xyz789"),
			wantErr:     true,
		},
		{name: "nil URL", callbackURL: nil, wantErr: true},
		{name: "empty URL", callbackURL: ptr(""), wantErr: true},
		{name: "unparseable URL", callbackURL: ptr("http://foo\x00bar"), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, state, err := parseAuthorizationCallback(tc.callbackURL)
			if tc.wantErr {
				if err == nil {
					t.Errorf("parseAuthorizationCallback(%v) = (%q, %q, nil), want error", tc.callbackURL, code, state)
				}
				return
			}
			if err != nil {
				t.Errorf("parseAuthorizationCallback(%v) returned unexpected error: %v", tc.callbackURL, err)
			}
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if state != tc.wantState {
				t.Errorf("state = %q, want %q", state, tc.wantState)
			}
		})
	}
}

func TestShouldRetryTxCode(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		txCodeRequired bool
		want           bool
	}{
		{
			name:           "invalid_grant with tx_code required → retry",
			err:            &oauth2.TokenError{StatusCode: 400, ErrorCode: "invalid_grant"},
			txCodeRequired: true,
			want:           true,
		},
		{
			name:           "invalid_request with tx_code required → retry",
			err:            &oauth2.TokenError{StatusCode: 400, ErrorCode: "invalid_request"},
			txCodeRequired: true,
			want:           true,
		},
		{
			name:           "invalid_grant without tx_code required → no retry",
			err:            &oauth2.TokenError{StatusCode: 400, ErrorCode: "invalid_grant"},
			txCodeRequired: false,
			want:           false,
		},
		{
			name:           "invalid_request without tx_code required → no retry",
			err:            &oauth2.TokenError{StatusCode: 400, ErrorCode: "invalid_request"},
			txCodeRequired: false,
			want:           false,
		},
		{
			name:           "invalid_client → no retry",
			err:            &oauth2.TokenError{StatusCode: 401, ErrorCode: "invalid_client"},
			txCodeRequired: true,
			want:           false,
		},
		{
			name:           "server_error → no retry",
			err:            &oauth2.TokenError{StatusCode: 500, ErrorCode: "server_error"},
			txCodeRequired: true,
			want:           false,
		},
		{
			name:           "unsupported_grant_type → no retry",
			err:            &oauth2.TokenError{StatusCode: 400, ErrorCode: "unsupported_grant_type"},
			txCodeRequired: true,
			want:           false,
		},
		{
			name:           "non-TokenError (network error) → no retry",
			err:            errors.New("connection refused"),
			txCodeRequired: true,
			want:           false,
		},
		{
			name:           "wrapped TokenError still triggers retry",
			err:            fmt.Errorf("token request failed: %w", &oauth2.TokenError{StatusCode: 400, ErrorCode: "invalid_grant"}),
			txCodeRequired: true,
			want:           true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRetryTxCode(tc.err, tc.txCodeRequired)
			if got != tc.want {
				t.Errorf("shouldRetryTxCode(%v, %v) = %v, want %v", tc.err, tc.txCodeRequired, got, tc.want)
			}
		})
	}
}
