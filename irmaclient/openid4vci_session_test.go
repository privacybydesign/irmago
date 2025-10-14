package irmaclient

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/stretchr/testify/require"
)

func Test_openid4vciSession_requestCredentials(t *testing.T) {
	// Initialize test http server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken := r.Header.Get("Authorization")

		switch authToken {
		case "Bearer valid_token::deferred_response":
			// Simulate deferred credential response (not supported yet)
			w.WriteHeader(http.StatusAccepted)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"transaction_id": "12345",
				"interval": 5,
				"notification_id": "notif-67890"
				}`))
		case "Bearer unauthorized_token::no_error":
			// Simulate unauthorized without error details
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
		case "Bearer unauthorized_token::with_error":
			// Simulate unauthorized with error details
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="The access token expired"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "Bearer forbidden_token::missing_scope_with_error":
			// Simulate forbidden with error details
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", error_description="The request requires higher privileges", scope="yivi.read"`)
			w.WriteHeader(http.StatusForbidden)
		case "Bearer invalid_request":
			// Simulate bad request with error details
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{
				"error": "invalid_request",
				"error_description": "The request is invalid (missing field XYZ)"
				}`))
		case "Bearer valid_token::unencrypted":
			// Simulate successful credential response (unencrypted)
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"credentials": [
					{"credential": "cred1"},
					{"credential": "cred2"}
				]
				}`))
		}
	}))
	defer ts.Close()

	// Initialize the session
	mockStorageClient := &MockSdJwtVcStorageClient{}
	session := &openid4vciSession{
		credentialOffer: &openid4vci.CredentialOffer{},
		credentialIssuerMetadata: &openid4vci.CredentialIssuerMetadata{
			CredentialEndpoint: ts.URL,
		},
		httpClient:    ts.Client(),
		storageClient: mockStorageClient,
		handler:       NewMockSessionHandler(t),
	}

	type args struct {
		accessToken string
	}
	tests := []struct {
		name                string
		s                   *openid4vciSession
		args                args
		wantErr             bool
		expectedErr         string
		expectedCredentials []sdjwtvc.SdJwtVc
	}{
		{
			name: "test deferred credential response not supported yet",
			s:    session,
			args: args{
				accessToken: "valid_token::deferred_response",
			},
			wantErr:     true,
			expectedErr: "wallet does not accept deferred credential responses",
		},
		{
			name: "test unauthorized token, no error in header",
			s:    session,
			args: args{
				accessToken: "unauthorized_token::no_error",
			},
			wantErr:     true,
			expectedErr: "credential request unauthorized",
		},
		{
			name: "test unauthorized token, with error in header",
			s:    session,
			args: args{
				accessToken: "unauthorized_token::with_error",
			},
			wantErr:     true,
			expectedErr: "credential request failed with error invalid_token: The access token expired",
		},
		{
			name: "test forbidden token (missing scope), with error in header",
			s:    session,
			args: args{
				accessToken: "forbidden_token::missing_scope_with_error",
			},
			wantErr:     true,
			expectedErr: "credential request failed with error insufficient_scope: The request requires higher privileges (required scope: yivi.read)",
		},
		{
			name: "test bad request (invalid request)",
			s:    session,
			args: args{
				accessToken: "invalid_request",
			},
			wantErr:     true,
			expectedErr: "credential request failed with error invalid_request: The request is invalid (missing field XYZ)",
		},
		{
			name: "test successful credential request",
			s:    session,
			args: args{
				accessToken: "valid_token::unencrypted",
			},
			wantErr:             false,
			expectedCredentials: []sdjwtvc.SdJwtVc{"cred1", "cred2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.s.requestCredentials(tt.args.accessToken)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				} else {
					// Validate that credentials were stored
					require.ElementsMatch(t, tt.expectedCredentials, mockStorageClient.sdjwts)
				}
			}
		})
	}
}
