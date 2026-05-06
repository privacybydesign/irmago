package openid4vci

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/oauth2"
)

// maxTxCodeAttempts is the total number of times the user may submit a tx_code
// before the session fails. The Authorization Server is the security boundary
// for tx_code lockout; this client-side limit is a UX guardrail.
const maxTxCodeAttempts = 3

const YiviAppRedirectUri = "yivi-app://auth-callback"
const YiviClientId = "yivi-wallet"

type GrantHandler interface {
	HandleGrant(s *session) (AccessTokenResponse, error)
}

type codeResponse struct {
	permissionGranted bool
	code              *string
}

// AccessTokenResponse handles the authorization of credential configurations.
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
func (h *AuthorizationCodeFlowHandler) HandleGrant(s *session) (AccessTokenResponse, error) {
	// TODO: split this func into doCodeRequest + doTokenRequest

	// Generate the code_challenge from the code_verifier, using a method supported by the AS (if any)
	pkce := &pkceParameters{}
	challengeProvider := s.issuerSettings.authorizationServerMetadata.GetCodeChallengeProvider()
	if challengeProvider != nil {
		pkce.CodeVerifier = oauth2.GenerateDefaultSizeVerifier()
		pkce.CodeChallenge = challengeProvider.GenerateCodeChallenge(pkce.CodeVerifier)
	}

	// ClientIds for testing:  how do we differentiate between them?
	// Entra: '65d1d280-0f23-4763-bf41-ea4c17cde792'
	// Auth0: 'FiEH7ZmdnrDphzAjvdk9scynlm0A1XV9',
	// Keycloak: 'eudiw'
	//clientId := "eudiw" // TODO: replace with Client Attestation once we have that, and fetch the client_id from the AS metadata instead of hardcoding it here
	clientId := YiviClientId

	// Build the authorization request parameters
	// The 'state' parameter will be added by the openid4vciSessionAdapter, so it can correlate the authorization response to the session when receiving the callback
	authRequest := buildAuthorizationRequestValues(
		YiviAppRedirectUri,
		&clientId,
		&pkce.CodeChallenge,
		s.credentialOffer.Grants.AuthorizationCodeGrant.IssuerState,
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

	request := &clientmodels.AuthorizationCodeFlowRequest{
		Credentials:             s.credentials,
		AuthorizationEndpoint:   s.issuerSettings.authorizationServerMetadata.AuthorizationEndpoint,
		AuthorizationParameters: authRequest,
	}

	pendingAuthCodeRequestChannel := make(chan *codeResponse, 1)
	defer func() {
		pendingAuthCodeRequestChannel = nil
	}()

	s.handler.RequestAuthorizationCodeFlowPermission(
		request,
		s.requestorInfo,
		AuthCodeHandler(func(proceed bool, code *string) {
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

func buildAuthorizationRequestValues(
	redirectUri string,
	clientId *string,
	pkce *oauth2.CodeChallenge,
	issuerState *string,
) url.Values {
	q := url.Values{}
	q.Add("response_type", "code")
	q.Add("redirect_uri", redirectUri)

	if clientId != nil {
		q.Add("client_id", *clientId)
	}

	if pkce != nil {
		q.Add("code_challenge", pkce.GetCodeChallenge())
		q.Add("code_challenge_method", pkce.GetCodeChallengeMethod())
	}
	if issuerState != nil {
		q.Add("issuer_state", *issuerState)
	}

	// The `state` parameter is added in the adapter, where it is used to correlate the authorization response to the session initiating the request, since we have a browser-based redirect.
	return q
}

func (h *AuthorizationCodeFlowHandler) pushAuthorizationRequest(parEndpoint string, payload url.Values) (*oauth2.PushedAuthorizationResponse, error) {
	req, err := http.NewRequest(http.MethodPost, parEndpoint, bytes.NewBufferString(payload.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create Pushed Authorization Request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute Pushed Authorization Request: %v", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pushed Authorization Request response body: %v", err)
	}

	// We accept both 201 + 200, where the specs require 201
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		// TODO: generalize error handling for all Authorization and Token Requests
		var errResponse oauth2.ErrorResponse
		err := json.NewDecoder(bytes.NewReader(responseBody)).Decode(&errResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to decode Pushed Authorization Request error response: %v", err)
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
		return nil, fmt.Errorf("failed to decode Pushed Authorization Response: %v", err)
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

	eudi.Logger.Infof("Sending token request: %s", payload.Encode())

	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, bytes.NewBufferString(payload.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request for Token Request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute Token Request: %v", err)
	}
	defer response.Body.Close()

	return handleTokenResponse(response)
}

type PreAuthorizedCodeFlowHandler struct {
}

// HandleGrant TODO: accept raw input, not session?
func (h *PreAuthorizedCodeFlowHandler) HandleGrant(s *session) (AccessTokenResponse, error) {
	var transactionCodeParameters *clientmodels.PreAuthorizedCodeTransactionCodeParameters = nil
	txCodeRequired := s.credentialOffer.Grants.PreAuthorizedCodeGrant.TxCode != nil
	if txCodeRequired {
		txCode := s.credentialOffer.Grants.PreAuthorizedCodeGrant.TxCode

		txCodeInputMode := "numeric" // Default input mode is 'numeric' if it's not specified in the grant
		if txCode.InputMode != nil {
			txCodeInputMode = string(*txCode.InputMode)
		}

		transactionCodeParameters = &clientmodels.PreAuthorizedCodeTransactionCodeParameters{
			InputMode:   txCodeInputMode,
			Length:      txCode.Length,
			Description: txCode.Description,
		}
	}

	for attempt := 0; attempt < maxTxCodeAttempts; attempt++ {
		// Fresh channel per attempt: if a stale callback fires after we've moved on
		// (race during cancel/dismiss), it lands on a channel we no longer read
		// rather than corrupting the next iteration's response.
		ch := make(chan *preAuthPermissionResponse, 1)

		request := &clientmodels.PreAuthorizedCodeFlowPermissionRequest{
			Credentials:               s.credentials,
			TransactionCodeParameters: transactionCodeParameters,
		}
		if attempt > 0 {
			remaining := maxTxCodeAttempts - attempt
			request.RemainingAttempts = &remaining
		}

		s.handler.RequestPreAuthorizedCodeFlowPermission(
			request,
			s.requestorInfo,
			TokenPermissionHandler(func(proceed bool, transactionCode *string) {
				ch <- &preAuthPermissionResponse{
					permissionGranted: proceed,
					transactionCode:   transactionCode,
				}
			}),
		)

		permission := <-ch
		if !permission.permissionGranted {
			return &authTokenResponse{permissionGranted: false}, nil
		}

		response, err := h.doTokenRequest(s, permission.transactionCode)
		if err == nil {
			return response, nil
		}

		if !shouldRetryTxCode(err, txCodeRequired) {
			return nil, err
		}
		// On the final attempt, surface the error instead of looping again.
		if attempt+1 >= maxTxCodeAttempts {
			return nil, err
		}
	}
	// Unreachable: the loop always returns.
	return nil, fmt.Errorf("transaction code retry loop exited unexpectedly")
}

// shouldRetryTxCode reports whether a token-request error indicates a wrong
// transaction code, in which case the user can be re-prompted. OpenID4VCI §6.3
// permits the AS to respond with either invalid_grant or invalid_request for a
// wrong tx_code; both also cover other invalid-grant conditions (e.g. expired
// pre-authorized code), which we accept as a known false-positive — the AS will
// reject the next attempt either way.
func shouldRetryTxCode(err error, txCodeRequired bool) bool {
	if !txCodeRequired {
		return false
	}
	var tokErr *oauth2.TokenError
	if !errors.As(err, &tokErr) {
		return false
	}
	return tokErr.ErrorCode == "invalid_grant" || tokErr.ErrorCode == "invalid_request"
}

func (h *PreAuthorizedCodeFlowHandler) doTokenRequest(s *session, transactionCode *string) (AccessTokenResponse, error) {
	values := url.Values{}

	values.Add("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	values.Add("pre-authorized_code", s.credentialOffer.Grants.PreAuthorizedCodeGrant.PreAuthorizedCode)
	values.Add("redirect_uri", YiviAppRedirectUri)

	// If a tx_code is required, it should be asked from the user via the TokenPermissionHandler callback
	if s.credentialOffer.Grants.PreAuthorizedCodeGrant.TxCode != nil {
		if transactionCode == nil {
			return nil, fmt.Errorf("transaction code is required by issuer, but was not provided")
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
		return nil, fmt.Errorf("failed to create request for Token Request: %v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute Token Request: %v", err)
	}
	defer response.Body.Close()

	return handleTokenResponse(response)
}

func handleTokenResponse(response *http.Response) (*authTokenResponse, error) {
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Token Response body: %v", err)
	}

	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		var errResponse oauth2.ErrorResponse
		err := json.NewDecoder(bytes.NewReader(responseBody)).Decode(&errResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to decode Token Response error: %v", err)
		}
		return nil, &oauth2.TokenError{
			StatusCode:       response.StatusCode,
			ErrorCode:        errResponse.Error,
			ErrorDescription: errResponse.ErrorDescription,
			ErrorUri:         errResponse.ErrorUri,
		}
	}

	var tokenResponse oauth2.TokenResponse
	err = json.NewDecoder(bytes.NewReader(responseBody)).Decode(&tokenResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Token Response: %v", err)
	}

	return &authTokenResponse{
		permissionGranted: true,
		token:             &tokenResponse,
	}, nil
}
