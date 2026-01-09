package irmaclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/oauth2"
)

type GrantHandler interface {
	HandleGrant(s *openid4vciSession) (AccessTokenResponse, error)
}

type authTokenRequest struct {
	channel chan *authTokenResponse
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

// TODO: accept raw input, not session
func (h *AuthorizationCodeFlowHandler) HandleGrant(s *openid4vciSession) (AccessTokenResponse, error) {
	pendingAuthTokenRequestChannel := make(chan *authTokenResponse, 1)
	defer func() {
		pendingAuthTokenRequestChannel = nil
	}()

	request := &irma.AuthorizationCodeFlowAndTokenExchangeRequest{
		CredentialInfoList: s.credentials,
		AuthorizationRequestParameters: irma.AuthorizationRequestParameters{
			IssuerDiscoveryUrl: getDiscoveryUrlFromIssuer(s.authorizationServer),
			IssuerState:        s.credentialOffer.Grants.AuthorizationCodeGrant.IssuerState,
			Resource:           s.credentialOffer.CredentialIssuer,
			Scopes:             s.extractScopesFromCredentialOffer(),
		},
	}
	s.handler.RequestPermissionAndPerformAuthCodeWithTokenExchange(
		request,
		s.requestorInfo,
		TokenHandler(func(proceed bool, accessToken string, refreshToken *string) {
			if proceed {
				irma.Logger.Printf("received access token via authorization code flow")
				pendingAuthTokenRequestChannel <- &authTokenResponse{
					authTokenPermissionResponse: authTokenPermissionResponse{permissionGranted: true},
					accessToken:                 accessToken,
					refreshToken:                refreshToken,
				}
			} else {
				irma.Logger.Printf("User cancelled authorization code flow")
				pendingAuthTokenRequestChannel <- &authTokenResponse{
					authTokenPermissionResponse: authTokenPermissionResponse{permissionGranted: false},
				}
			}
		}),
	)

	// Wait for the token handler to be called
	return <-pendingAuthTokenRequestChannel, nil
}

type PreAuthorizedCodeFlowHandler struct {
}

// TODO: accept raw input, not session
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

	req, err := http.NewRequest(http.MethodPost, s.authorizationServerMetadata.TokenEndpoint, strings.NewReader(values.Encode()))
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
