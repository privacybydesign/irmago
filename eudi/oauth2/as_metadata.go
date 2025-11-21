package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type AuthorizationServerMetadata struct {
	// RFC 8414 fields
	Issuer                                             string   `json:"issuer"`
	AuthorizationEndpoint                              string   `json:"authorization_endpoint"`
	TokenEndpoint                                      string   `json:"token_endpoint"`
	JwksUri                                            *string  `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                               *string  `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    []string `json:"scopes_supported"`
	ResponseTypesSupported                             []string `json:"response_types_supported"`
	ResponseModesSupported                             []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               *string  `json:"service_documentation,omitempty"`
	UiLocalesSupported                                 []string `json:"ui_locales_supported,omitempty"`
	OpPolicyUri                                        *string  `json:"op_policy_uri,omitempty"`
	OpTosUri                                           *string  `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                 *string  `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              *string  `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported,omitempty"`

	// RFC 9396 extension for OAuth 2.0 Rich Authorization Requests
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`
}

type TokenResponse struct {
	// RFC 6749 fields
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    *int    `json:"expires_in,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
	Scope        *string `json:"scope,omitempty"`

	// RFC 9396 extension for OAuth 2.0 Rich Authorization Requests
	AuthorizationDetails *string `json:"authorization_details,omitempty"`
}

func GetOAuthMetadataUrlFromAuthorizationServer(authorizationServer string) (string, error) {
	return getWellKnownUrlFromAuthorizationServer(authorizationServer, "oauth-authorization-server")
}

func GetOpenIdMetadataUrlFromAuthorizationServer(authorizationServer string) (string, error) {
	return getWellKnownUrlFromAuthorizationServer(authorizationServer, "openid-configuration")
}

func getWellKnownUrlFromAuthorizationServer(authorizationServer string, wellKnownPath string) (string, error) {
	url, err := url.Parse(authorizationServer)
	if err != nil {
		return "", err
	}

	asUrl := fmt.Sprintf("%s://%s/.well-known/%s", url.Scheme, url.Host, wellKnownPath)

	if url.Path != "" {
		asUrl = fmt.Sprintf("%s/%s", asUrl, url.Path)
	}

	return asUrl, nil
}

// TryFetchAuthorizationServerMetadata will try fetching unsigned Authorization Server Metadata from the default OAuth 2.0
// well-known URL (/.well-known/oauth-authorization-server) first.
// If that fails, it will try fetching it from the OpenID Connect well-known URL (/.well-known/openid-configuration).
func TryFetchAuthorizationServerMetadata(authorizationServerUrl string) (*AuthorizationServerMetadata, error) {
	url, err := GetOAuthMetadataUrlFromAuthorizationServer(authorizationServerUrl)
	if err != nil {
		return nil, err
	}
	asMetadata, err := fetchUnsignedAuthorizationServerMetadata(url)
	if err == nil {
		return asMetadata, nil
	}

	url, err = GetOpenIdMetadataUrlFromAuthorizationServer(authorizationServerUrl)
	if err != nil {
		return nil, err
	}
	asMetadata, err = fetchUnsignedAuthorizationServerMetadata(url)
	if err == nil {
		return asMetadata, nil
	}

	// As a last resort, well try to append both well-known paths to the authorization server URL (which is not spec-compliant)
	asMetadata, err = fetchUnsignedAuthorizationServerMetadata(authorizationServerUrl + "/.well-known/oauth-authorization-server")
	if err == nil {
		return asMetadata, nil
	}

	url, err = GetOpenIdMetadataUrlFromAuthorizationServer(authorizationServerUrl + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	asMetadata, err = fetchUnsignedAuthorizationServerMetadata(url)
	if err == nil {
		return asMetadata, nil
	}

	return nil, fmt.Errorf("could not fetch authorization server metadata from authorization server %s", authorizationServerUrl)
}

func fetchUnsignedAuthorizationServerMetadata(url string) (*AuthorizationServerMetadata, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not obtain authorization server metadata from %s (StatusCode: %d)", url, response.StatusCode)
	}

	var asMetadata AuthorizationServerMetadata
	err = json.NewDecoder(response.Body).Decode(&asMetadata)
	if err != nil {
		return nil, err
	}

	return &asMetadata, nil
}
