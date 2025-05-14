package irmaclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

type OpenID4VPClient struct {
	Compatibility openid4vp.CompatibilityMode
	QueryHandlers []dcql.CredentialQueryHandler
}

func NewOpenID4VPClient(queryHandlers []dcql.CredentialQueryHandler) (*OpenID4VPClient, error) {
	return &OpenID4VPClient{
		Compatibility: openid4vp.Compatibility_Draft24,
		QueryHandlers: queryHandlers,
	}, nil
}

func (client *OpenID4VPClient) NewSession(fullUrl string, handler Handler) SessionDismisser {
	client.handleSessionAsync(fullUrl, handler)
	return client
}

func (client *OpenID4VPClient) Dismiss() {
	irma.Logger.Info("openid4vp: session dismissed")
}

func (client *OpenID4VPClient) handleSessionAsync(fullUrl string, handler Handler) {
	go func() {
		components, err := url.Parse(fullUrl)

		if err != nil {
			irma.Logger.Errorf("openid4vp: failed to parse request: %v", err)
			handler.Failure(nil)
			return
		}

		uri := components.Query().Get("request_uri")
		if uri == "" {
			irma.Logger.Error("openid4vp: request missing required request_uri")
			handler.Failure(nil)
			return
		}

		irma.Logger.Infof("starting openid4vp session: %v\n", uri)
		response, err := http.Get(uri)
		if err != nil {
			irma.Logger.Errorf("openid4vp: failed to get authorization request: %v", err)
			handler.Failure(nil)
			return
		}

		defer response.Body.Close()

		jawd, err := io.ReadAll(response.Body)

		if err != nil {
			irma.Logger.Errorf("openid4vp: failed to read authorization request body: %v", err)
			handler.Failure(nil)
			return
		}

		request, err := ParseAuthorizationRequestJwt(string(jawd))
		if err != nil {
			irma.Logger.Errorf("openid4vp: failed to read authorization request jwt: %v", err)
			handler.Failure(nil)
			return
		}
		irma.Logger.Infof("auth request: %#v\n", request)
		err = client.HandleAuthorizationRequest(request, handler)

		if err != nil {
			irma.Logger.Errorf("openid4vp: failed to handle authorization request: %v", err)
			handler.Failure(nil)
			return
		}
		handler.Success("managed to complete openid4vp session")
	}()
}

type AuthorizationResponseConfig struct {
	State             string
	QueryResponses    []dcql.QueryResponse
	ResponseUri       string
	ResponseType      string
	ResponseMode      openid4vp.ResponseMode
	CompatibilityMode openid4vp.CompatibilityMode
	EncryptionKey     *jwk.Key
}

func (client *OpenID4VPClient) HandleAuthorizationRequest(request *openid4vp.AuthorizationRequest, handler Handler) error {
	queryResponses, err := dcql.QueryCredentials(request.DcqlQuery, client.QueryHandlers)

	if err != nil {
		return err
	}

	httpClient := http.Client{}
	authResponse := AuthorizationResponseConfig{
		CompatibilityMode: client.Compatibility,
		State:             request.State,
		QueryResponses:    queryResponses,
		ResponseUri:       request.ResponseUri,
		ResponseType:      request.ResponseType,
		ResponseMode:      request.ResponseMode,
	}
	responseReq, err := createAuthorizationResponseHttpRequest(authResponse)
	if err != nil {
		return err
	}

	response, err := httpClient.Do(responseReq)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("response status was not ok: %v", response)
	}
	return nil
}

func ParseAuthorizationRequestJwt(authReqJwt string) (*openid4vp.AuthorizationRequest, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(string(authReqJwt), &openid4vp.AuthorizationRequest{})

	typ, ok := token.Header["typ"]
	if !ok {
		return nil, errors.New("auth request JWT needs to contain 'typ' in header, but doesn't")
	}
	if typ != openid4vp.AuthRequestJwtTyp {
		return nil, fmt.Errorf("auth request JWT typ in header should be %v but was %v", openid4vp.AuthRequestJwtTyp, typ)
	}

	if err != nil {
		return nil, err
	}

	claims := token.Claims.(*openid4vp.AuthorizationRequest)

	return claims, nil
}

func createAuthorizationResponseHttpRequest(config AuthorizationResponseConfig) (*http.Request, error) {
	values := url.Values{}

	if config.ResponseMode == openid4vp.ResponseMode_DirectPost {
		vpToken, err := createDirectPostVpToken(config.CompatibilityMode, config.QueryResponses)
		if err != nil {
			return nil, err
		}
		values.Add("vp_token", vpToken)
	}

	if config.ResponseMode == openid4vp.ResponseMode_DirectPostJwt {
		if config.EncryptionKey == nil {
			return nil, fmt.Errorf("using response mode %v, but the encryption key is nil", openid4vp.ResponseMode_DirectPostJwt)
		}
		jwe, err := createDirectPostJwtEncryptedResponse(config.CompatibilityMode, config.QueryResponses, *config.EncryptionKey)
		if err != nil {
			return nil, err
		}
		values.Add("response", jwe)
	}

	values.Add("state", config.State)

	req, err := http.NewRequest(http.MethodPost, config.ResponseUri, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	return req, nil
}

func createDirectPostJwtEncryptedResponse(compatibility openid4vp.CompatibilityMode, queryResponses []dcql.QueryResponse, encryptionKey jwk.Key) (string, error) {
	vpToken, err := createVpToken(compatibility, queryResponses)
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"vp_token": vpToken,
	}
	return encryptJwe(payload, encryptionKey)
}

func encryptJwe(payload map[string]any, key jwk.Key) (string, error) {
	return "", nil
}

func createVpToken(compatibility openid4vp.CompatibilityMode, queryResponses []dcql.QueryResponse) (any, error) {
	if compatibility == openid4vp.Compatibility_LatestDraft {
		content := map[string][]string{}
		for _, resp := range queryResponses {
			content[resp.QueryId] = resp.Credentials
		}

		return content, nil
	}
	if compatibility == openid4vp.Compatibility_Draft24 {
		content := map[string]string{}
		for _, resp := range queryResponses {
			content[resp.QueryId] = resp.Credentials[0]
		}
		return content, nil
	}
	return nil, fmt.Errorf("%v is not a supported value for compatibility mode", compatibility)
}

func createDirectPostVpToken(compatibility openid4vp.CompatibilityMode, queryResponses []dcql.QueryResponse) (string, error) {
	content, err := createVpToken(compatibility, queryResponses)
	if err != nil {
		return "", err
	}
	result, err := json.Marshal(content)
	return string(result), err
}
