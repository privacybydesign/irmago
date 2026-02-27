package irmaclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/privacybydesign/irmago/eudi/oauth2"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/irma"
)

type GrantHandler interface {
	HandleGrant(s *openid4vciSession) (AccessTokenResponse, error)
}

type codeResponse struct {
	permissionGranted bool
	code              *string
}

type AccessTokenResponse interface {
	PermissionGranted() bool
	GetAccessToken() string
	GetRefreshToken() *string
}

type authTokenPermissionResponse struct {
	permissionGranted bool
	transactionCode   *string
}

type authTokenResponse struct {
	authTokenPermissionResponse
	accessToken  string
	refreshToken *string
}

func (r *authTokenResponse) PermissionGranted() bool {
	return r.permissionGranted
}

func (r *authTokenResponse) GetAccessToken() string {
	return r.accessToken
}

func (r *authTokenResponse) GetRefreshToken() *string {
	return r.refreshToken
}

type AuthorizationCodeFlowHandler struct {
}

type pkceParameters struct {
	CodeVerifier  string
	CodeChallenge oauth2.CodeChallenge
}

// HandleGrant TODO: accept raw input, not session
func (h *AuthorizationCodeFlowHandler) HandleGrant(s *openid4vciSession) (AccessTokenResponse, error) {
	// TODO: check if we want/need to use Pushed Authorization Requests here if the AS supports it

	// Generate the code_challenge from the code_verifier, using a method supported by the AS (if any)
	pkce := &pkceParameters{}
	challengeProvider := s.issuerSettings.authorizationServerMetadata.GetCodeChallengeProvider()
	if challengeProvider != nil {
		pkce.CodeVerifier = oauth2.GenerateDefaultSizeVerifier()
		pkce.CodeChallenge = challengeProvider.GenerateCodeChallenge(pkce.CodeVerifier)
	} else {
		irma.Logger.Info("AS does not support PKCE code challenge methods, proceeding without code challenge")
	}

	// ClientIds for testing:  how do we differentiate between them?
	// Entra: '65d1d280-0f23-4763-bf41-ea4c17cde792'
	// Auth0: 'FiEH7ZmdnrDphzAjvdk9scynlm0A1XV9',
	// Keycloak: 'eudiw'
	clientId := "eudiw" // TODO: should we allow the client_id to be configured here, or is it always the same?

	scopes := s.extractScopesFromCredentialOffer()
	if len(scopes) > 0 {
		// TODO: either request using authorization_details or scopes, not both
	}

	var resource *string
	if len(s.credentialIssuerMetadata.AuthorizationServers) > 0 {
		resource = &s.credentialIssuerMetadata.CredentialIssuer
	}

	authRequestUrl := openid4vci.BuildAuthorizationRequestUrl(
		s.issuerSettings.authorizationServerMetadata.AuthorizationEndpoint,
		"yivi-app://callback",
		&clientId,
		scopes,
		&pkce.CodeChallenge,
		s.credentialOffer.Grants.AuthorizationCodeGrant.IssuerState,
		resource,
	)

	request := &irma.AuthorizationCodeFlowRequest{
		CredentialInfoList:      s.credentials,
		AuthorizationRequestUrl: authRequestUrl,
	}

	pendingAuthCodeRequestChannel := make(chan *codeResponse, 1)
	defer func() {
		pendingAuthCodeRequestChannel = nil
	}()

	s.handler.RequestAuthorizationCodeFlowPermission(
		request,
		s.requestorInfo,
		CodeHandler(func(proceed bool, code *string) {
			pendingAuthCodeRequestChannel <- &codeResponse{
				permissionGranted: proceed,
				code:              code,
			}
		}),
	)

	// Wait for the code handler to be called
	permission := <-pendingAuthCodeRequestChannel

	// TODO: start exchange of code for token here, and return token response instead of code response, to avoid having to wait for the token handler to be called in a separate step after this

	// Wait for the token handler to be called
	// tokenPermission := <-pendingAuthTokenRequestChannel
	authTokenResponse := &authTokenResponse{
		authTokenPermissionResponse: authTokenPermissionResponse{permissionGranted: permission.permissionGranted},
	}

	return authTokenResponse, nil
}

type PreAuthorizedCodeFlowHandler struct {
}

// HandleGrant TODO: accept raw input, not session
func (h *PreAuthorizedCodeFlowHandler) HandleGrant(s *openid4vciSession) (AccessTokenResponse, error) {
	pendingAuthTokenPermissionRequestChannel := make(chan *authTokenPermissionResponse, 1)
	defer func() {
		pendingAuthTokenPermissionRequestChannel = nil
	}()

	var transactionCodeParameters *irma.PreAuthorizedCodeTransactionCodeParameters = nil
	if s.credentialOffer.Grants.PreAuthorizedCodeGrant.TxCode != nil {
		txCode := s.credentialOffer.Grants.PreAuthorizedCodeGrant.TxCode

		txCodeInputMode := "numeric" // Default input mode is 'numeric' if it's not specified in the grant
		if txCode.InputMode != nil {
			txCodeInputMode = string(*txCode.InputMode)
		}

		transactionCodeParameters = &irma.PreAuthorizedCodeTransactionCodeParameters{
			InputMode:   txCodeInputMode,
			Length:      txCode.Length,
			Description: txCode.Description,
		}
	}

	request := &irma.PreAuthorizedCodeFlowPermissionRequest{
		CredentialInfoList:        s.credentials,
		TransactionCodeParameters: transactionCodeParameters,
	}
	s.handler.RequestPreAuthorizedCodeFlowPermission(
		request,
		s.requestorInfo,
		TokenPermissionHandler(func(proceed bool, transactionCode *string) {
			if proceed {
				irma.Logger.Printf("received access token via authorization code flow")
				pendingAuthTokenPermissionRequestChannel <- &authTokenPermissionResponse{permissionGranted: true, transactionCode: transactionCode}
			} else {
				irma.Logger.Printf("user cancelled authorization code flow")
				pendingAuthTokenPermissionRequestChannel <- &authTokenPermissionResponse{permissionGranted: false}
			}
		}),
	)

	// Wait for the token handler to be called
	permission := <-pendingAuthTokenPermissionRequestChannel

	if !permission.permissionGranted {
		return &authTokenResponse{
			authTokenPermissionResponse: *permission,
		}, nil
	}

	return h.requestAccessToken(s, permission.transactionCode)
}

func (h *PreAuthorizedCodeFlowHandler) requestAccessToken(s *openid4vciSession, transactionCode *string) (AccessTokenResponse, error) {
	values := url.Values{}

	values.Add("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	values.Add("pre-authorized_code", s.credentialOffer.Grants.PreAuthorizedCodeGrant.PreAuthorizedCode)
	values.Add("redirect_uri", "yivi-app://callback")

	// If a tx_code is required, it should be asked from the user via the TokenPermissionHandler callback
	if s.credentialOffer.Grants.PreAuthorizedCodeGrant.TxCode != nil {
		if transactionCode == nil {
			return nil, fmt.Errorf("transaction code is required by issuer, but was not provided by user")
		}
		values.Add("tx_code", *transactionCode)
	}

	// TODO: after we've added support for fetching AS metadata, we should check if we need to add Authorization Details parameter

	req, err := http.NewRequest(http.MethodPost, s.issuerSettings.authorizationServerMetadata.TokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return handleTokenResponse(response)
}

func handleTokenResponse(response *http.Response) (*authTokenResponse, error) {
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		var errResponse oauth2.TokenErrorResponse
		err := json.NewDecoder(response.Body).Decode(&errResponse)
		if err != nil {
			return nil, fmt.Errorf("token endpoint returned status code: %d, %s", response.StatusCode, err)
		}
		errDescription := ""
		if errResponse.ErrorDescription != nil {
			errDescription = *errResponse.ErrorDescription + " - "
		}
		errUri := ""
		if errResponse.ErrorUri != nil {
			errUri = " More info: " + *errResponse.ErrorUri
		}
		return nil, fmt.Errorf("token endpoint returned status code %d, %s%s.%s", response.StatusCode, errResponse.Error, errDescription, errUri)
	}

	var tokenResponse oauth2.TokenResponse
	err := json.NewDecoder(response.Body).Decode(&tokenResponse)
	if err != nil {
		return nil, err
	}

	return &authTokenResponse{
		authTokenPermissionResponse: authTokenPermissionResponse{permissionGranted: true},
		accessToken:                 tokenResponse.AccessToken,
		refreshToken:                tokenResponse.RefreshToken,
	}, nil
}
