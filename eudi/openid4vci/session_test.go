package openid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func Test_openid4vciSession_obtainCredential_checksFail(t *testing.T) {
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
			expectedErr: `credential configuration "credential-config-1" is not supported: unsupported credential format "jwt_vc_json-ld"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize environment
			session, ts := setupTestEnvironment(t, tt.testOptions, credEndpointHandler)
			defer ts.Close()

			_, err := session.obtainCredential("credential-config-1", nil, tt.accessToken)

			if err == nil {
				t.Errorf("Expected error, got nil")
			} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
				t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
			}
		})
	}
}

func Test_openid4vciSession_obtainCredential_errorResponses(t *testing.T) {
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

	s, ts := setupTestEnvironment(t, 0, credEndpointHandler)
	defer ts.Close()

	tests := []struct {
		name        string
		s           *session
		accessToken string
		nonce       *string
		expectedErr string
	}{
		{
			name:        "test deferred credential response not supported yet",
			s:           s,
			accessToken: "valid_token::deferred_response",
			nonce:       &nonce,
			expectedErr: "wallet does not accept deferred credential responses for now",
		},
		{
			name:        "test unauthorized token, no error in header",
			s:           s,
			accessToken: "unauthorized_token::no_error",
			nonce:       &nonce,
			expectedErr: "credential request unauthorized",
		},
		{
			name:        "test unauthorized token, with error in header",
			s:           s,
			accessToken: "unauthorized_token::with_error",
			nonce:       &nonce,
			expectedErr: "credential request failed with error \"invalid_token\": The access token expired",
		},
		{
			name:        "test forbidden token (missing scope), with error in header",
			s:           s,
			accessToken: "forbidden_token::missing_scope_with_error",
			nonce:       &nonce,
			expectedErr: "credential request failed with error \"insufficient_scope\": The request requires higher privileges (required scope: yivi.read)",
		},
		{
			name:        "test bad request (invalid request)",
			s:           s,
			accessToken: "invalid_request",
			nonce:       &nonce,
			expectedErr: "credential request failed with error \"invalid_request\": The request is invalid (missing field XYZ)",
		},
		// TODO:
		// add test for failed response; nonce needs refresh;  also on higher level (requestCredentials, where nonce is retrieved)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.s.obtainCredential("credential-config-1", tt.nonce, tt.accessToken)

			if err == nil {
				t.Errorf("Expected error, got nil")
			} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
				t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
			}
		})
	}
}

func Test_openid4vciSession_obtainCredential_successResponses(t *testing.T) {
	// Build a real SD-JWT VC using the same test key + cert chain used in client_test.go
	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	certChain, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	require.NoError(t, err)

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderJwkKey, err := jwk.Import(holderKey)
	require.NoError(t, err)

	testCredential, err := createTestSdJwtVcWithHolderKey(
		"test.credential.type",
		"https://test-issuer.example.com",
		map[string]string{"name": "Test User"},
		certChain,
		holderJwkKey,
	)
	require.NoError(t, err)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: string(testCredential)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired, credEndpointHandler)
	defer ts.Close()

	sess.holderVerifier = sdjwtvc.NewHolderVerificationProcessor(
		sdjwtvc.CreateDefaultVerificationContext(chain),
	)

	fetched, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Equal(t, "credential-config-1", fetched.credentialConfigurationId)
	require.Len(t, fetched.verifiedSdJwtVcs, 1)
	require.False(t, fetched.requireCryptographicKeyBinding)
}

type CredentialRequestTestOptions uint

const (
	NonceNotRequired                              CredentialRequestTestOptions = 1
	CredentialConfigurationWithUnsupportedFeature CredentialRequestTestOptions = 2
	CredentialConfigurationWithW3CVC              CredentialRequestTestOptions = 4
)

func setupTestEnvironment(t *testing.T, opts CredentialRequestTestOptions, credEndpointHandler http.Handler) (
	*session,
	*httptest.Server,
) {
	tempDir := t.TempDir()
	ts := httptest.NewServer(credEndpointHandler)

	scope := "test-scope"
	credentialConfig := &metadata.CredentialConfiguration{
		Format: metadata.CredentialFormatIdentifier_SdJwtVc,
		Scope:  &scope,
	}

	if opts&CredentialConfigurationWithUnsupportedFeature == CredentialConfigurationWithUnsupportedFeature {
		// Configure unsupported format to force 'unsupported'
		credentialConfig.Format = metadata.CredentialFormatIdentifier_W3CVCLD
	}

	if opts&CredentialConfigurationWithW3CVC == CredentialConfigurationWithW3CVC {
		credentialConfig.Format = metadata.CredentialFormatIdentifier_W3CVC
		credentialConfig.CredentialDefinition = &metadata.W3CCredentialDefinition{
			Type: []string{"VerifiableCredential"},
		}
	}

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	eudiStorage, err := storage.NewStorage(aesKey, ":memory:", tempDir)
	require.NoError(t, err)

	session := &session{
		storage: eudiStorage,
		credentialOffer: &CredentialOffer{
			CredentialConfigurationIds: []string{"credential-config-1"},
		},
		credentialIssuerMetadata: &metadata.CredentialIssuerMetadata{
			CredentialEndpoint: ts.URL,
			NonceEndpoint:      "https://nonce-endpoint",
			CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{
				"credential-config-1": *credentialConfig,
			},
		},
		httpClient:     ts.Client(),
		handler:        newMockSessionHandler(t),
		issuerSettings: openid4vciSessionIssuerSettings{},
	}

	if opts&NonceNotRequired == NonceNotRequired {
		session.credentialIssuerMetadata.NonceEndpoint = ""
	}

	return session, ts
}

func Test_openid4vciSession_obtainCredential_jwtVcJsonAdapterNotImplemented(t *testing.T) {
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: "header.payload.signature"}},
		})
		w.Write(resp)
	})

	session, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	_, err := session.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT header JSON")
}

func Test_openid4vciSession_obtainCredential_jwtVcJsonStrictModeRequiresKeyMaterial(t *testing.T) {
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustMakeTestJWT(t,
				map[string]any{"alg": "ES256", "typ": "JWT"},
				map[string]any{"iss": "https://issuer.example.com", "sub": "did:example:alice"},
			)}},
		})
		w.Write(resp)
	})

	session, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	conf, err := eudi.NewConfiguration(session.storage)
	require.NoError(t, err)
	conf.EnableStrictJwtVcJsonVerification()
	session.issuerSettings.strictJwtVcJsonVerification = conf.StrictJwtVcJsonVerificationEnabled()

	_, err = session.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: missing JWT key material (x5c)")
}

func Test_openid4vciSession_obtainCredential_jwtVcJsonStrictModeHonorsTemporalClockSkew(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	createSession := func(expiryOffset time.Duration) (*session, *httptest.Server) {
		credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
			payload := map[string]any{
				"iss": "https://issuer.example.com",
				"sub": "did:example:alice",
				"exp": time.Now().Add(expiryOffset).Unix(),
			}

			resp, _ := json.Marshal(CredentialResponse{
				Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
			})
			w.Write(resp)
		})

		s, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
		s.issuerSettings.strictJwtVcJsonVerification = true
		s.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
		return s, ts
	}

	t.Run("accepts credential expired within skew", func(t *testing.T) {
		s, ts := createSession(-2 * time.Minute)
		defer ts.Close()

		s.issuerSettings.jwtVcJsonTemporalClockSkew = 5 * time.Minute
		fetched, err := s.obtainCredential("credential-config-1", nil, "test-token")
		require.NoError(t, err)
		require.NotNil(t, fetched)
		require.Len(t, fetched.vcdmEnvelopes, 1)
	})

	t.Run("rejects credential expired outside skew", func(t *testing.T) {
		s, ts := createSession(-3 * time.Minute)
		defer ts.Close()

		s.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute
		_, err := s.obtainCredential("credential-config-1", nil, "test-token")
		require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: credential is expired")
	})
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModePersistsAndLists(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)
	issuedAt := time.Now().Unix()

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"iat": issuedAt,
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	config.CredentialMetadata = &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Display: metadata.Display{Name: "Email Credential", Locale: new("en")}},
		},
	}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 2 * time.Minute

	fetched, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Empty(t, fetched.verifiedSdJwtVcs)
	require.Len(t, fetched.vcdmEnvelopes, 1)

	err = sess.storeCredentials([]*fetchedCredential{fetched})
	require.NoError(t, err)

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Len(t, stored, 1)

	cred := stored[0]
	require.Equal(t, "EmailCredential", cred.CredentialId)
	require.Equal(t, "https://issuer.example.com", cred.Issuer.Id)
	require.Equal(t, issuedAt, *cred.IssuanceDate)
	require.Contains(t, cred.CredentialInstanceIds, clientmodels.CredentialFormat("jwt_vc_json"))
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeUntrustedChainNotPersisted(t *testing.T) {
	trustedRootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, trustedRootPem)

	// Build a different CA/leaf pair not present in the trusted root set.
	_, untrustedRoot, untrustedLeaf, untrustedLeafPriv := mustCreateTrustedRootAndLeaf(t)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{untrustedLeaf, untrustedRoot}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, untrustedLeafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 2 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT x5c certificate is not trusted")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeIssuerHostnameMismatchNotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://wrong-issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT x5c certificate is not trusted")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeMissingTrustConfigurationNotPersisted(t *testing.T) {
	_, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: missing JWT trust configuration")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidIssuerURINotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "not-a-uri",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid issuer URI for JWT x5c validation")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeRejectsHmacAlgWithX5cNotPersisted(t *testing.T) {
	rootPem, root, leaf, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "HS256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustMakeTestJWT(t, header, payload)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT alg \"HS256\" is not allowed with x5c")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeRejectsAlgNoneNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "none", "typ": "JWT"}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustMakeTestJWT(t, header, payload)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT alg \"none\" is not allowed")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeRejectsUnsupportedAsymmetricAlgWithX5cNotPersisted(t *testing.T) {
	rootPem, _, leaf, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256K", "typ": "JWT", "x5c": []any{leaf}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustMakeTestJWT(t, header, payload)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT alg \"ES256K\" is not allowed with x5c")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidCompactJWTNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: "only-two.parts"}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid compact JWT format")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidHeaderEncodingNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: "%.payload.sig"}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT header encoding")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidHeaderJSONNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	invalidHeaderJSON := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://issuer.example.com"}`))

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: fmt.Sprintf("%s.%s.sig", invalidHeaderJSON, payload)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT header JSON")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeMissingAlgHeaderNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	headerWithoutAlg := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://issuer.example.com"}`))

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: fmt.Sprintf("%s.%s.sig", headerWithoutAlg, payload)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: missing JWT alg header")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeMissingIssuerClaimNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payloadWithoutIssuer := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"did:example:alice"}`))

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: fmt.Sprintf("%s.%s.sig", header, payloadWithoutIssuer)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: missing issuer claim \"iss\"")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidPayloadEncodingNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: fmt.Sprintf("%s.%%.sig", header)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT payload encoding")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidPayloadJSONNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	invalidPayloadJSON := base64.RawURLEncoding.EncodeToString([]byte("not-json"))

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: fmt.Sprintf("%s.%s.sig", header, invalidPayloadJSON)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT payload JSON")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidSignatureNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{mustLeafX5cB64FromPemChain(t, testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)}}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
		"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
	}

	valid := mustSignTestJWT(t, header, payload)
	parts := strings.Split(valid, ".")
	require.Len(t, parts, 3)
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.NotEmpty(t, sigBytes)
	sigBytes[len(sigBytes)-1] ^= 0x01
	parts[2] = base64.RawURLEncoding.EncodeToString(sigBytes)
	invalid := strings.Join(parts, ".")

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: invalid}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err = sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT signature")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidX5cChainOrderNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	leaf, parent, leafPriv := mustCreateX5cLeafAndParent(t)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{parent, leaf}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT x5c chain")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeMissingX5cNotPersisted(t *testing.T) {
	rootPem, _, _, _ := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT"}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustMakeTestJWT(t, header, payload)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: missing JWT key material (x5c)")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidX5cHeaderNotPersisted(t *testing.T) {
	rootPem, _, _, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT x5c header")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeMalformedX5cHeaderNotPersisted(t *testing.T) {
	rootPem, _, _, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": "not-an-array"}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: missing JWT key material (x5c)")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidTemporalClaimExpNotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": "not-a-number",
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		payloadJSON, err := json.Marshal(payload)
		require.NoError(t, err)
		protected := jwsHeadersFromMap(header)
		signed, err := jws.Sign(payloadJSON, jws.WithKey(jwa.ES256(), leafPriv, jws.WithProtectedHeaders(protected)))
		require.NoError(t, err)

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: string(signed)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claim \"exp\"")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidTemporalClaimIatNotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"iat": "not-a-number",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		payloadJSON, err := json.Marshal(payload)
		require.NoError(t, err)
		protected := jwsHeadersFromMap(header)
		signed, err := jws.Sign(payloadJSON, jws.WithKey(jwa.ES256(), leafPriv, jws.WithProtectedHeaders(protected)))
		require.NoError(t, err)

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: string(signed)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claim \"iat\"")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeInvalidTemporalClaimNbfNotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"nbf": "not-a-number",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		payloadJSON, err := json.Marshal(payload)
		require.NoError(t, err)
		protected := jwsHeadersFromMap(header)
		signed, err := jws.Sign(payloadJSON, jws.WithKey(jwa.ES256(), leafPriv, jws.WithProtectedHeaders(protected)))
		require.NoError(t, err)

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: string(signed)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claim \"nbf\"")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeNegativeTemporalClockSkewNotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = -1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal clock skew: must be non-negative")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeExpiredOutsideSkewNotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(-3 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: credential is expired")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeNotYetValidOutsideSkewNotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"nbf": time.Now().Add(3 * time.Minute).Unix(),
			"exp": time.Now().Add(10 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: credential is not yet valid")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeIssuedAtInFutureOutsideSkewNotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"iat": time.Now().Add(3 * time.Minute).Unix(),
			"exp": time.Now().Add(15 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: iat is in the future")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeExpBeforeNbfNotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": time.Now().Add(1 * time.Minute).Unix(),
			"nbf": time.Now().Add(3 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: exp is before nbf")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCStrictModeExpBeforeIatNotPersisted(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"iat": time.Now().Add(3 * time.Minute).Unix(),
			"exp": time.Now().Add(1 * time.Minute).Unix(),
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)}},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	sess.issuerSettings.strictJwtVcJsonVerification = true
	sess.issuerSettings.jwtVcJsonX509VerificationContext = &conf.Issuers
	sess.issuerSettings.jwtVcJsonTemporalClockSkew = 1 * time.Minute

	_, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: exp is before iat")

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Empty(t, stored)
}

func Test_openid4vciSession_storeCredentials_W3CVCSucceeds(t *testing.T) {
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT"}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"vc":  map[string]any{"type": []any{"VerifiableCredential"}},
		}
		resp, _ := json.Marshal(CredentialResponse{Credentials: []CredentialInstance{{Credential: mustMakeTestJWT(t, header, payload)}}})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	fetched, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Empty(t, fetched.verifiedSdJwtVcs)
	require.Len(t, fetched.vcdmEnvelopes, 1)

	err = sess.storeCredentials([]*fetchedCredential{fetched})
	require.NoError(t, err)
}

func Test_openid4vciSession_storeCredentials_W3CVCPersistsAndLists(t *testing.T) {
	issuedAt := time.Now().Unix()

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT"}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"iat": issuedAt,
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}
		resp, _ := json.Marshal(CredentialResponse{Credentials: []CredentialInstance{{Credential: mustMakeTestJWT(t, header, payload)}}})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	// Provide enough metadata so the retrieved list can expose expected display information.
	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	config.CredentialMetadata = &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Display: metadata.Display{Name: "Email Credential", Locale: new("en")}},
		},
	}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	fetched, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Empty(t, fetched.verifiedSdJwtVcs)
	require.Len(t, fetched.vcdmEnvelopes, 1)

	err = sess.storeCredentials([]*fetchedCredential{fetched})
	require.NoError(t, err)

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Len(t, stored, 1)

	cred := stored[0]
	require.Equal(t, "EmailCredential", cred.CredentialId)
	require.Equal(t, "https://issuer.example.com", cred.Issuer.Id)
	require.Equal(t, "Email Credential", cred.Name["en"])
	require.Equal(t, issuedAt, *cred.IssuanceDate)
	require.Contains(t, cred.CredentialInstanceIds, clientmodels.CredentialFormat("jwt_vc_json"))
	require.Contains(t, cred.BatchInstanceCountsRemaining, clientmodels.CredentialFormat("jwt_vc_json"))
}

func Test_openid4vciSession_storeCredentials_W3CVCWithoutIatPersistsAndLists(t *testing.T) {
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT"}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}
		resp, _ := json.Marshal(CredentialResponse{Credentials: []CredentialInstance{{Credential: mustMakeTestJWT(t, header, payload)}}})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	config.CredentialMetadata = &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Display: metadata.Display{Name: "Email Credential", Locale: new("en")}},
		},
	}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	fetched, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Empty(t, fetched.verifiedSdJwtVcs)
	require.Len(t, fetched.vcdmEnvelopes, 1)

	err = sess.storeCredentials([]*fetchedCredential{fetched})
	require.NoError(t, err)

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Len(t, stored, 1)

	cred := stored[0]
	require.Equal(t, "EmailCredential", cred.CredentialId)
	require.Nil(t, cred.IssuanceDate)
	require.Contains(t, cred.CredentialInstanceIds, clientmodels.CredentialFormat("jwt_vc_json"))
}

func Test_openid4vciSession_storeCredentials_W3CVCFallbackIdAndExpiryPersistsAndLists(t *testing.T) {
	expiry := time.Now().Add(2 * time.Hour).Unix()

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		header := map[string]any{"alg": "ES256", "typ": "JWT"}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"exp": expiry,
			"vc":  map[string]any{"type": []any{"VerifiableCredential"}},
		}
		resp, _ := json.Marshal(CredentialResponse{Credentials: []CredentialInstance{{Credential: mustMakeTestJWT(t, header, payload)}}})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	// Keep only generic type to force fallback CredentialId == credential_configuration_id.
	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential"}}
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	fetched, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Empty(t, fetched.verifiedSdJwtVcs)
	require.Len(t, fetched.vcdmEnvelopes, 1)

	err = sess.storeCredentials([]*fetchedCredential{fetched})
	require.NoError(t, err)

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Len(t, stored, 1)

	cred := stored[0]
	require.Equal(t, "credential-config-1", cred.CredentialId)
	require.NotNil(t, cred.ExpiryDate)
	require.Equal(t, expiry, *cred.ExpiryDate)
	require.Contains(t, cred.CredentialInstanceIds, clientmodels.CredentialFormat("jwt_vc_json"))
	require.Nil(t, cred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat("jwt_vc_json")])
}

func Test_openid4vciSession_storeCredentials_W3CVCBatchPersistsAndLists(t *testing.T) {
	issuedAt := time.Now().Unix()

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		header := map[string]any{"alg": "ES256", "typ": "JWT"}
		payloadA := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"iat": issuedAt,
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}
		payloadB := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:bob",
			"iat": issuedAt,
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{
				{Credential: mustMakeTestJWT(t, header, payloadA)},
				{Credential: mustMakeTestJWT(t, header, payloadB)},
			},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	config.CredentialMetadata = &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Display: metadata.Display{Name: "Email Credential", Locale: new("en")}},
		},
	}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	fetched, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Empty(t, fetched.verifiedSdJwtVcs)
	require.Len(t, fetched.vcdmEnvelopes, 2)

	err = sess.storeCredentials([]*fetchedCredential{fetched})
	require.NoError(t, err)

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Len(t, stored, 1)

	cred := stored[0]
	require.Equal(t, "EmailCredential", cred.CredentialId)
	require.Equal(t, issuedAt, *cred.IssuanceDate)
	require.Contains(t, cred.CredentialInstanceIds, clientmodels.CredentialFormat("jwt_vc_json"))

	remaining, ok := cred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat("jwt_vc_json")]
	require.True(t, ok)
	require.NotNil(t, remaining)
	require.Equal(t, uint(2), *remaining)
}

func Test_openid4vciSession_storeCredentials_W3CVCBatchWithoutIatPersistsAndLists(t *testing.T) {
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		header := map[string]any{"alg": "ES256", "typ": "JWT"}
		payloadA := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}
		payloadB := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:bob",
			"vc":  map[string]any{"type": []any{"VerifiableCredential", "EmailCredential"}},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{
				{Credential: mustMakeTestJWT(t, header, payloadA)},
				{Credential: mustMakeTestJWT(t, header, payloadB)},
			},
		})
		w.Write(resp)
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	config := sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CredentialDefinition = &metadata.W3CCredentialDefinition{Type: []string{"VerifiableCredential", "EmailCredential"}}
	config.CredentialMetadata = &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Display: metadata.Display{Name: "Email Credential", Locale: new("en")}},
		},
	}
	sess.credentialIssuerMetadata.CredentialIssuer = "https://issuer.example.com"
	sess.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config

	fetched, err := sess.obtainCredential("credential-config-1", nil, "test-token")
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Empty(t, fetched.verifiedSdJwtVcs)
	require.Len(t, fetched.vcdmEnvelopes, 2)

	err = sess.storeCredentials([]*fetchedCredential{fetched})
	require.NoError(t, err)

	credentialService := services.NewCredentialService(sess.storage)
	stored, err := credentialService.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Len(t, stored, 1)

	cred := stored[0]
	require.Equal(t, "EmailCredential", cred.CredentialId)
	require.Nil(t, cred.IssuanceDate)
	require.Contains(t, cred.CredentialInstanceIds, clientmodels.CredentialFormat("jwt_vc_json"))

	remaining, ok := cred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat("jwt_vc_json")]
	require.True(t, ok)
	require.NotNil(t, remaining)
	require.Equal(t, uint(2), *remaining)
}

func Test_openid4vciSession_configureIssuerSettings_credentialRequestEncryption(t *testing.T) {
	ecPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encKey, err := jwk.Import(ecPrivateKey)
	require.NoError(t, err)
	require.NoError(t, encKey.Set(jwk.AlgorithmKey, jwa.ECDH_ES()))
	require.NoError(t, encKey.Set(jwk.KeyUsageKey, "enc"))

	// Same key but without "enc" usage, to test the "no suitable key" error path
	keyWithoutUsage, err := jwk.Import(ecPrivateKey)
	require.NoError(t, err)
	require.NoError(t, keyWithoutUsage.Set(jwk.AlgorithmKey, jwa.ECDH_ES()))

	encJwks := jwk.NewSet()
	require.NoError(t, encJwks.AddKey(encKey))

	noUsageJwks := jwk.NewSet()
	require.NoError(t, noUsageJwks.AddKey(keyWithoutUsage))

	tests := []struct {
		name            string
		encryption      *metadata.CredentialRequestEncryption
		expectErr       string
		expectEncrypted bool
	}{
		{
			name:            "no encryption config",
			encryption:      nil,
			expectEncrypted: false,
		},
		{
			name: "encryption not required",
			encryption: &metadata.CredentialRequestEncryption{
				Jwks:               encJwks,
				EncValuesSupported: []string{"A128GCM"},
				EncryptionRequired: false,
			},
			expectEncrypted: false,
		},
		{
			name: "encryption required with valid config",
			encryption: &metadata.CredentialRequestEncryption{
				Jwks:               encJwks,
				EncValuesSupported: []string{"A128GCM"},
				EncryptionRequired: true,
			},
			expectEncrypted: true,
		},
		{
			name: "encryption required but no supported content encryption algorithm",
			encryption: &metadata.CredentialRequestEncryption{
				Jwks:               encJwks,
				EncValuesSupported: []string{"UNSUPPORTED_ALG_XYZ"},
				EncryptionRequired: true,
			},
			expectErr: "no supported encryption algorithm found for credential request encryption",
		},
		{
			name: "encryption required but no key with enc usage in JWKS",
			encryption: &metadata.CredentialRequestEncryption{
				Jwks:               noUsageJwks,
				EncValuesSupported: []string{"A128GCM"},
				EncryptionRequired: true,
			},
			expectErr: "no suitable key found in jwks for credential request encryption",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// configureIssuerSettings fetches AS metadata over HTTP; serve a minimal response
			asServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{}`))
			}))
			defer asServer.Close()

			s := &session{
				credentialOffer: &CredentialOffer{
					CredentialIssuer: asServer.URL,
					Grants: &Grants{
						PreAuthorizedCodeGrant: &PreAuthorizedCodeGrant{
							PreAuthorizedCode: "test-code",
						},
					},
				},
				credentialIssuerMetadata: &metadata.CredentialIssuerMetadata{
					CredentialRequestEncryption: tt.encryption,
				},
				issuerSettings: openid4vciSessionIssuerSettings{},
			}

			err := s.configureIssuerSettings()

			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectEncrypted, s.issuerSettings.useCredentialRequestEncryption)
			if tt.expectEncrypted {
				require.NotNil(t, s.issuerSettings.credentialRequestEncryptionKey)
				require.NotNil(t, s.issuerSettings.credentialRequestContentEncryptionAlg)
				require.Equal(t, jwa.A128GCM(), *s.issuerSettings.credentialRequestContentEncryptionAlg)
			}
		})
	}
}

func Test_openid4vciSession_configureIssuerSettings_grantSelection(t *testing.T) {
	authGrant := &AuthorizationCodeGrant{}
	preAuthGrant := &PreAuthorizedCodeGrant{PreAuthorizedCode: "pre-auth-code"}

	tests := []struct {
		name        string
		grants      *Grants
		expectGrant GrantType
		expectErr   string
	}{
		{
			name:        "both grants offered prefers pre-authorized code",
			grants:      &Grants{AuthorizationCodeGrant: authGrant, PreAuthorizedCodeGrant: preAuthGrant},
			expectGrant: GrantType_PreAuthorizedCode,
		},
		{
			name:        "only authorization code uses authorization code",
			grants:      &Grants{AuthorizationCodeGrant: authGrant},
			expectGrant: GrantType_AuthorizationCode,
		},
		{
			name:        "only pre-authorized code uses pre-authorized code",
			grants:      &Grants{PreAuthorizedCodeGrant: preAuthGrant},
			expectGrant: GrantType_PreAuthorizedCode,
		},
		{
			name:      "no grants returns error",
			grants:    &Grants{},
			expectErr: "no supported grant type found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer asServer.Close()

			s := &session{
				credentialOffer: &CredentialOffer{
					CredentialIssuer: asServer.URL,
					Grants:           tt.grants,
				},
				credentialIssuerMetadata: &metadata.CredentialIssuerMetadata{},
				issuerSettings:           openid4vciSessionIssuerSettings{},
			}

			err := s.configureIssuerSettings()

			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, s.issuerSettings.grantType)
			require.Equal(t, tt.expectGrant, s.issuerSettings.grantType.GetGrantType())
		})
	}
}

func Test_openid4vciSession_obtainCredential_sendsEncryptedRequest(t *testing.T) {
	ecPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwkPrivKey, err := jwk.Import(ecPrivateKey)
	require.NoError(t, err)
	require.NoError(t, jwkPrivKey.Set(jwk.AlgorithmKey, jwa.ECDH_ES()))
	require.NoError(t, jwkPrivKey.Set(jwk.KeyUsageKey, "enc"))

	pubKey, err := jwkPrivKey.PublicKey()
	require.NoError(t, err)

	var receivedContentType string
	var receivedBody []byte

	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		// Return 400 so obtainCredential returns an error without needing a valid credential response
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "test_error", "error_description": "intentional test error"}`))
	})

	sess, ts := setupTestEnvironment(t, NonceNotRequired, credEndpointHandler)
	defer ts.Close()

	sess.issuerSettings.useCredentialRequestEncryption = true
	sess.issuerSettings.credentialRequestEncryptionKey = &pubKey

	_, err = sess.obtainCredential("credential-config-1", nil, "test-token")
	// The 400 from the server causes this error — encryption itself must not have failed
	require.ErrorContains(t, err, "credential request failed with error")

	// The request must be sent as an encrypted JWT
	require.Equal(t, "application/jwt", receivedContentType)

	// JWE compact serialization has exactly 5 dot-separated parts
	parts := strings.Split(strings.TrimSpace(string(receivedBody)), ".")
	require.Len(t, parts, 5, "expected JWE compact serialization (5 dot-separated parts)")

	// Decrypt and verify the payload contains the correct credential configuration ID
	decrypted, err := jwe.Decrypt(receivedBody, jwe.WithKey(jwa.ECDH_ES(), jwkPrivKey))
	require.NoError(t, err)

	token, err := jwt.Parse(decrypted, jwt.WithVerify(false))
	require.NoError(t, err)

	var configId string
	require.NoError(t, token.Get("credential_configuration_id", &configId), "expected credential_configuration_id claim in decrypted JWT")
	require.Equal(t, "credential-config-1", configId)
}

func Test_buildAttributesWithValues_PayloadDrives(t *testing.T) {
	en := "en"
	claims := []metadata.ClaimsDescription{
		{
			Path:    metadata.ClaimsPathPointer{"family_name"},
			Display: []metadata.Display{{Name: "Family Name", Locale: &en}},
		},
		{
			Path:    metadata.ClaimsPathPointer{"address"},
			Display: []metadata.Display{{Name: "Address", Locale: &en}},
		},
	}
	payload := sdjwtvc.ProcessedSdJwtPayload{
		"family_name": "Smith",
		"given_name":  "Alice",
		"address":     map[string]any{"city": "Amsterdam", "extra": ""},
		"iss":         "https://issuer.example.com",
		"iat":         float64(1),
		"sub":         "u1",
	}

	attrs := buildAttributesWithValues(claims, payload)

	byPath := map[string]int{}
	for i, a := range attrs {
		var parts []string
		for _, p := range a.ClaimPath {
			parts = append(parts, toStr(p))
		}
		byPath[strings.Join(parts, ".")] = i
	}

	// Standard claims are filtered out.
	for _, key := range []string{"iss", "iat", "sub"} {
		_, present := byPath[key]
		require.False(t, present, "standard claim %q should not appear", key)
	}

	// family_name leaf has the metadata display.
	idx, ok := byPath["family_name"]
	require.True(t, ok, "family_name should appear")
	require.NotNil(t, attrs[idx].DisplayName)
	require.Equal(t, "Family Name", (*attrs[idx].DisplayName)["en"])

	// given_name is in payload but not metadata → DisplayName nil.
	idx, ok = byPath["given_name"]
	require.True(t, ok, "given_name should appear despite not being in metadata")
	require.Nil(t, attrs[idx].DisplayName)

	// address section header.
	idx, ok = byPath["address"]
	require.True(t, ok, "address section header should appear")
	require.NotNil(t, attrs[idx].DisplayName)
	require.Equal(t, "Address", (*attrs[idx].DisplayName)["en"])
	require.Nil(t, attrs[idx].Value)

	// address.city: no metadata → no inherited display.
	idx, ok = byPath["address.city"]
	require.True(t, ok)
	require.Nil(t, attrs[idx].DisplayName)
	require.NotNil(t, attrs[idx].Value)
	require.NotNil(t, attrs[idx].Value.String)
	require.Equal(t, "Amsterdam", *attrs[idx].Value.String)

	// address.extra: empty-string value kept.
	idx, ok = byPath["address.extra"]
	require.True(t, ok, "empty-string values should be kept")
	require.NotNil(t, attrs[idx].Value)
	require.NotNil(t, attrs[idx].Value.String)
	require.Equal(t, "", *attrs[idx].Value.String)
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
