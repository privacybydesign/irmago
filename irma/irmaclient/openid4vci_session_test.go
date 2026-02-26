package irmaclient

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/stretchr/testify/require"
)

func Test_openid4vciSession_requestCredential_checksFail(t *testing.T) {
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	tests := []struct {
		name        string
		accessToken string
		testOptions CredentialRequestTestOptions
		expectedErr string
	}{
		{
			name:        "nonce is required (NonceEndpoint is available), but no nonce was passed",
			accessToken: "not-checked",
			expectedErr: "credential request requires nonce but none was provided",
		},
		{
			name:        "credential configuration not supported",
			accessToken: "not-checked",
			testOptions: NonceNotRequired | CredentialConfigurationWithUnsupportedFeature,
			expectedErr: `credential configuration "credential-config-1" is not supported: unsupported credential format "jwt_vc_json"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize environment
			session, _, ts := setupTestEnvironment(t, tt.testOptions, credEndpointHandler)
			defer ts.Close()

			err := session.requestCredential("credential-config-1", nil, tt.accessToken)

			if err == nil {
				t.Errorf("Expected error, got nil")
			} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
				t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
			}
		})
	}
}

func Test_openid4vciSession_requestCredential_errorResponses(t *testing.T) {
	var nonce = "test-nonce"

	// Initialize test http server
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}
	})

	session, _, ts := setupTestEnvironment(t, 0, credEndpointHandler)
	defer ts.Close()

	tests := []struct {
		name        string
		s           *openid4vciSession
		accessToken string
		nonce       *string
		expectedErr string
	}{
		{
			name:        "test deferred credential response not supported yet",
			s:           session,
			accessToken: "valid_token::deferred_response",
			nonce:       &nonce,
			expectedErr: "wallet does not accept deferred credential responses",
		},
		{
			name:        "test unauthorized token, no error in header",
			s:           session,
			accessToken: "unauthorized_token::no_error",
			nonce:       &nonce,
			expectedErr: "credential request unauthorized",
		},
		{
			name:        "test unauthorized token, with error in header",
			s:           session,
			accessToken: "unauthorized_token::with_error",
			nonce:       &nonce,
			expectedErr: "credential request failed with error invalid_token: The access token expired",
		},
		{
			name:        "test forbidden token (missing scope), with error in header",
			s:           session,
			accessToken: "forbidden_token::missing_scope_with_error",
			nonce:       &nonce,
			expectedErr: "credential request failed with error insufficient_scope: The request requires higher privileges (required scope: yivi.read)",
		},
		{
			name:        "test bad request (invalid request)",
			s:           session,
			accessToken: "invalid_request",
			nonce:       &nonce,
			expectedErr: "credential request failed with error invalid_request: The request is invalid (missing field XYZ)",
		},
		// TODO:
		// add test for failed response; nonce needs refresh;  also on higher level (requestCredentials, where nonce is retrieved)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.s.requestCredential("credential-config-1", tt.nonce, tt.accessToken)

			if err == nil {
				t.Errorf("Expected error, got nil")
			} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
				t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
			}
		})
	}
}

func Test_openid4vciSession_requestCredential_succesResponses(t *testing.T) {
	var nonce = "test-nonce"

	// Initialize test environment
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken := r.Header.Get("Authorization")

		switch authToken {
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
	})

	session, mockStorageClient, ts := setupTestEnvironment(t, NonceNotRequired, credEndpointHandler)
	defer ts.Close()

	tests := []struct {
		name                string
		s                   *openid4vciSession
		accessToken         string
		expectedErr         string
		expectedCredentials []sdjwtvc.SdJwtVcKb
	}{
		{
			name:                "test successful credential request - unencrypted - no keybinding",
			s:                   session,
			accessToken:         "valid_token::unencrypted",
			expectedCredentials: []sdjwtvc.SdJwtVcKb{"cred1", "cred2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.s.requestCredential("credential-config-1", &nonce, tt.accessToken)

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			} else {
				// Validate that credentials were stored
				require.ElementsMatch(t, tt.expectedCredentials, mockStorageClient.sdjwts)
			}
		})
	}
}

type CredentialRequestTestOptions uint

const (
	NonceNotRequired                              CredentialRequestTestOptions = 1
	CredentialConfigurationWithUnsupportedFeature CredentialRequestTestOptions = 2
)

func setupTestEnvironment(t *testing.T, opts CredentialRequestTestOptions, credEndpointHandler http.Handler) (
	*openid4vciSession,
	*MockSdJwtVcStorageClient,
	*httptest.Server,
) {
	ts := httptest.NewServer(credEndpointHandler)

	credentialConfig := &openid4vci.CredentialConfiguration{
		Format: openid4vci.CredentialFormatIdentifier_SdJwtVc,
	}

	if opts&CredentialConfigurationWithUnsupportedFeature == CredentialConfigurationWithUnsupportedFeature {
		// Configure unsupported format to force 'unsupported'
		credentialConfig.Format = openid4vci.CredentialFormatIdentifier_W3CVC
	}

	mockStorageClient := &MockSdJwtVcStorageClient{}
	session := &openid4vciSession{
		credentialOffer: &openid4vci.CredentialOffer{
			CredentialConfigurationIds: []string{"credential-config-1"},
		},
		credentialIssuerMetadata: &openid4vci.CredentialIssuerMetadata{
			CredentialEndpoint: ts.URL,
			NonceEndpoint:      "https://nonce-endpoint",
			CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfiguration{
				"credential-config-1": *credentialConfig,
			},
		},
		httpClient:     ts.Client(),
		storageClient:  mockStorageClient,
		handler:        NewMockSessionHandler(t),
		keyBinder:      nil,
		issuerSettings: openid4vciSessionIssuerSettings{},
	}

	if opts&NonceNotRequired == NonceNotRequired {
		session.credentialIssuerMetadata.NonceEndpoint = ""
	}

	return session, mockStorageClient, ts
}
