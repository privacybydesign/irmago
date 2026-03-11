package irmaclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/privacybydesign/irmago/eudi/oauth2"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/irma"
)

const YiviAppRedirectUri = "yivi-app://auth-callback"
const YiviClientId = "yivi-wallet"

type GrantHandler interface {
	HandleGrant(s *openid4vciSession) (AccessTokenResponse, error)
}

type codeResponse struct {
	permissionGranted bool
	code              *string
}

// TODO: we need to handle the authorization of MULTIPLE instances of the same credential configuration
// i.e. we might have 2+ of the same credentials available, with different claim values.
// The user needs to choose which credential(s) to add to the wallet?
type AccessTokenResponse interface {
	PermissionGranted() bool
	GetAccessToken() string
	GetRefreshToken() *string
}

type preAuthPermissionResponse struct {
	permissionGranted bool
	transactionCode   *string
}

type authTokenResponse struct {
	permissionGranted bool
	token             *oauth2.TokenResponse
}

func (r *authTokenResponse) PermissionGranted() bool {
	return r.permissionGranted
}

func (r *authTokenResponse) GetAccessToken() string {
	return r.token.AccessToken
}

func (r *authTokenResponse) GetRefreshToken() *string {
	return r.token.RefreshToken
}

type AuthorizationCodeFlowHandler struct {
	httpClient *http.Client
}

type pkceParameters struct {
	CodeVerifier  string
	CodeChallenge oauth2.CodeChallenge
}

// HandleGrant TODO: accept raw input, not session
func (h *AuthorizationCodeFlowHandler) HandleGrant(s *openid4vciSession) (AccessTokenResponse, error) {
	// TODO: split this func into doCodeRequest + doTokenRequest

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
	//clientId := "eudiw" // TODO: replace with Client Attestation once we have that, and fetch the client_id from the AS metadata instead of hardcoding it here
	clientId := YiviClientId

	authRequest := openid4vci.BuildAuthorizationRequestValues(
		YiviAppRedirectUri,
		&clientId,
		&pkce.CodeChallenge,
		s.credentialOffer.Grants.AuthorizationCodeGrant.IssuerState,
		// TODO: state -> should we generate a random state here to correlate the authorization response to the session
		// We will need a func in the client.Client that can correlate the authorization response to the session based on the state, since the authorization response will be received in the app's main activity, which does not have access to the session directly, and then pass the authorization response (or just the code) to the session that initiated the authorization request
	)

	// Add `authorization_details` if the AS supports the feature and the Credential Issuer offers multiple credentials in the Credential Offer
	authDetails, err := s.extractAuthorizationDetailsJson()
	if err != nil {
		return nil, fmt.Errorf("failed to extract authorization details from credential offer: %v", err)
	}
	if authDetails != nil {
		authRequest.Add("authorization_details", *authDetails)
	}

	// Even if authorization_details will be sent, we should also add the scopes to the authorization request if the AS supports the `scope` parameter, since some ASes might require it, and it does not hurt to include it as well
	scopes := s.extractScopesFromCredentialOffer()
	if len(scopes) > 0 {
		authRequest.Add("scope", strings.Join(scopes, " "))
	}

	if len(s.credentialIssuerMetadata.AuthorizationServers) > 0 {
		authRequest.Add("resource", s.credentialIssuerMetadata.CredentialIssuer)
	}

	// If the AS supports PAR, we should always use it, regardless of wether the issuer requires it or not, since it is more secure. If the AS does not support PAR, we will just use the normal authorization endpoint.
	// From here, we can only provide the authorization request endpoint to the client, but the client should be able to figure out itself whether it needs to use PAR or not based on the AS metadata that we provide to it, and then use the correct endpoint accordingly.
	parEndpoint := s.issuerSettings.authorizationServerMetadata.PushedAuthorizationRequestEndpoint
	if parEndpoint != nil {
		parResponse, err := h.pushAuthorizationRequest(*parEndpoint, authRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to execute pushed authorization request: %v", err)
		}

		// Extract the values from the PAR response and replace all values (except the client_id) in the authRequest with the values from the PAR response
		authRequest = url.Values{}
		authRequest.Add("client_id", clientId)
		authRequest.Add("request_uri", parResponse.RequestUri)
	}

	// Construct the URL that the client should open in the browser to start the authorization code flow
	authRequestUrl, err := url.Parse(s.issuerSettings.authorizationServerMetadata.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorization endpoint URL: %v", err)
	}
	authRequestUrl.RawQuery = authRequest.Encode()

	request := &irma.AuthorizationCodeFlowRequest{
		CredentialInfoList:      s.credentials,
		AuthorizationRequestUrl: authRequestUrl.String(),
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
	userInteraction := <-pendingAuthCodeRequestChannel

	if !userInteraction.permissionGranted {
		// User cancelled or denied the code request
		return nil, fmt.Errorf("authorization has been cancelled or denied by user")
	}

	// Exchange of code for token and return token response
	return h.doTokenRequest(s.issuerSettings.authorizationServerMetadata.TokenEndpoint,
		*userInteraction.code, pkce, scopes, authDetails)
}

func (h *AuthorizationCodeFlowHandler) pushAuthorizationRequest(parEndpoint string, payload url.Values) (*oauth2.PushedAuthorizationResponse, error) {
	req, err := http.NewRequest(http.MethodPost, parEndpoint, bytes.NewBufferString(payload.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request for pushed authorization request: %v", err)
	}

	irma.Logger.Infof("Sending PAR request: %s", payload.Encode())

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute pushed authorization request: %v", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read PAR response body: %v", err)
	}
	irma.Logger.Infof("PAR response body: %s", string(responseBody))

	// We accept both 201 + 200, where the specs require 201
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		// TODO: generalize error handling for all Authorization and Token Requests
		var errResponse oauth2.ErrorResponse
		err := json.NewDecoder(bytes.NewReader(responseBody)).Decode(&errResponse)
		if err != nil {
			return nil, fmt.Errorf("pushed authorization request returned status code: %d, %s", response.StatusCode, err)
		}
		errDescription := ""
		if errResponse.ErrorDescription != nil {
			errDescription = *errResponse.ErrorDescription + " - "
		}
		errUri := ""
		if errResponse.ErrorUri != nil {
			errUri = " More info: " + *errResponse.ErrorUri
		}
		return nil, fmt.Errorf("pushed authorization request returned status code %d, %s%s.%s", response.StatusCode, errResponse.Error, errDescription, errUri)
	}

	var parResponse oauth2.PushedAuthorizationResponse
	err = json.NewDecoder(bytes.NewReader(responseBody)).Decode(&parResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pushed authorization response: %v", err)
	}

	return &parResponse, nil
}

func (h *AuthorizationCodeFlowHandler) doTokenRequest(
	tokenEndpoint string,
	code string,
	pkce *pkceParameters,
	scopes []string,
	authDetails *string,
) (AccessTokenResponse, error) {
	payload := url.Values{}

	payload.Add("grant_type", "authorization_code")
	payload.Add("code", code)
	payload.Add("client_id", YiviClientId)
	payload.Add("redirect_uri", YiviAppRedirectUri)

	if pkce != nil {
		payload.Add("code_verifier", pkce.CodeVerifier)
	}

	if len(scopes) > 0 {
		payload.Add("scope", strings.Join(scopes, " "))
	}

	if authDetails != nil {
		payload.Add("authorization_details", *authDetails)
	}

	irma.Logger.Infof("Sending token request: %s", payload.Encode())

	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, bytes.NewBufferString(payload.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request for token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute token request: %v", err)
	}
	defer response.Body.Close()

	return handleTokenResponse(response)
}

type PreAuthorizedCodeFlowHandler struct {
}

// HandleGrant TODO: accept raw input, not session?
func (h *PreAuthorizedCodeFlowHandler) HandleGrant(s *openid4vciSession) (AccessTokenResponse, error) {
	pendingAuthTokenPermissionRequestChannel := make(chan *preAuthPermissionResponse, 1)
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
				pendingAuthTokenPermissionRequestChannel <- &preAuthPermissionResponse{permissionGranted: true, transactionCode: transactionCode}
			} else {
				irma.Logger.Printf("user cancelled authorization code flow")
				pendingAuthTokenPermissionRequestChannel <- &preAuthPermissionResponse{permissionGranted: false}
			}
		}),
	)

	// Wait for the token handler to be called
	permission := <-pendingAuthTokenPermissionRequestChannel

	if !permission.permissionGranted {
		return &authTokenResponse{permissionGranted: false}, nil
	}

	return h.doTokenRequest(s, permission.transactionCode)
}

func (h *PreAuthorizedCodeFlowHandler) doTokenRequest(s *openid4vciSession, transactionCode *string) (AccessTokenResponse, error) {
	values := url.Values{}

	values.Add("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	values.Add("pre-authorized_code", s.credentialOffer.Grants.PreAuthorizedCodeGrant.PreAuthorizedCode)
	values.Add("redirect_uri", YiviAppRedirectUri)

	// If a tx_code is required, it should be asked from the user via the TokenPermissionHandler callback
	if s.credentialOffer.Grants.PreAuthorizedCodeGrant.TxCode != nil {
		if transactionCode == nil {
			return nil, fmt.Errorf("transaction code is required by issuer, but was not provided by user")
		}
		values.Add("tx_code", *transactionCode)
	}

	// Add `authorization_details` if the AS supports the feature and the Credential Issuer offers multiple credentials in the Credential Offer
	authDetails, err := s.extractAuthorizationDetailsJson()
	if err != nil {
		return nil, fmt.Errorf("failed to extract authorization details from credential offer: %v", err)
	}
	if authDetails != nil {
		values.Add("authorization_details", *authDetails)
	}

	// Initiate request
	req, err := http.NewRequest(http.MethodPost, s.issuerSettings.authorizationServerMetadata.TokenEndpoint, bytes.NewBufferString(values.Encode()))
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
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response body: %v", err)
	}
	irma.Logger.Infof("Token response body: %s", string(responseBody))

	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		var errResponse oauth2.ErrorResponse
		err := json.NewDecoder(bytes.NewReader(responseBody)).Decode(&errResponse)
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
	err = json.NewDecoder(bytes.NewReader(responseBody)).Decode(&tokenResponse)
	if err != nil {
		return nil, err
	}

	return &authTokenResponse{
		permissionGranted: true,
		token:             &tokenResponse,
	}, nil
}
