package irmaclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
)

type openid4vciSession struct {
	credentialOffer          *openid4vci.CredentialOffer
	credentialIssuerMetadata *openid4vci.CredentialIssuerMetadata
	requestorInfo            *irma.RequestorInfo
	credentials              []*irma.CredentialTypeInfo
	storageClient            SdJwtVcStorageClient
	httpClient               *http.Client
	handler                  Handler
	pendingPermissionRequest *permissionRequest
}

func (s *openid4vciSession) perform() error {
	s.pendingPermissionRequest = &permissionRequest{
		channel: make(chan *permissionResponse, 1),
	}
	defer func() {
		s.pendingPermissionRequest = nil
	}()

	if s.credentialOffer.Grants.AuthorizationCodeGrant != nil {
		authorizationServer, err := s.getAuthorizationServer()
		if err != nil {
			s.handler.Failure(&irma.SessionError{
				Err: fmt.Errorf("could not determine authorization server to use: %v", err),
			})
			return nil
		}
		s.requestAuthorizationCodeFlowPermission(authorizationServer)
	} else {
		s.handler.Failure(&irma.SessionError{
			Err: fmt.Errorf("only authorization code grant is supported"),
		})
	}

	permissionResponse := s.awaitPermission()

	if permissionResponse == nil {
		s.handler.Cancelled()
		return nil
	}

	s.handler.Success("openid4vci session completed")
	return nil
}

func (s *openid4vciSession) requestAuthorizationCodeFlowPermission(authorizationServer string) {
	issuanceRequest := &irma.AuthorizationCodeIssuanceRequest{
		CredentialInfoList:  s.credentials,
		AuthorizationServer: authorizationServer,
	}

	s.handler.RequestAuthorizationCodeFlowIssuancePermission(
		issuanceRequest,
		s.requestorInfo,
		PermissionHandler(func(proceed bool, choice *irma.DisclosureChoice) {
			if proceed {
				s.pendingPermissionRequest.channel <- &permissionResponse{}
			} else {
				s.pendingPermissionRequest.channel <- nil
			}
		}),
	)
}

func (s *openid4vciSession) getAuthorizationServer() (string, error) {
	if s.credentialOffer.Grants.AuthorizationCodeGrant.AuthorizationServer != nil || len(s.credentialIssuerMetadata.AuthorizationServers) == 0 {
		// Use the credential issuer as the authorization server if no other authorization servers are listed in the metadata
		return s.credentialOffer.CredentialIssuer, nil
	} else {
		// Match the authorization server from the offer to the metadata
		for _, authServer := range s.credentialIssuerMetadata.AuthorizationServers {
			if authServer == *s.credentialOffer.Grants.AuthorizationCodeGrant.AuthorizationServer && strings.HasPrefix(authServer, "https://") {
				return authServer, nil
			}
		}
	}
	return "", fmt.Errorf("no valid authorization server found in credential issuer metadata")
}

func (s *openid4vciSession) awaitPermission() *permissionResponse {
	return <-s.pendingPermissionRequest.channel
}

func (s *openid4vciSession) requestCredentials(accessToken string) error {
	// TODO: check if we need to set credential_identifier or credential_configuration_id field
	request := &openid4vci.CredentialRequest{}

	jsonRequest, err := json.Marshal(request)
	if err != nil {
		return err
	}

	// Send the request
	req, err := http.NewRequest("POST", s.credentialIssuerMetadata.CredentialEndpoint, bytes.NewBuffer(jsonRequest))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			irma.Logger.Warnf("failed to close credential request response body: %v", err)
		}
	}()
	if err != nil {
		return err
	}

	// Process the response
	deferredResponse := false
	if resp.StatusCode == http.StatusAccepted {
		deferredResponse = true
		return fmt.Errorf("wallet does not accept deferred credential responses")
	} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Parse the error from the WWW-Authenticate header
		authHeader := resp.Header.Get("WWW-Authenticate")
		authHeader = strings.TrimPrefix(authHeader, "Bearer ")

		// Example header: WWW-Authenticate: Bearer error="invalid_token", error_description="The access token expired"
		var errMsg, errDesc, errUri, scope string
		parts := strings.SplitSeq(authHeader, ",")
		for part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "error=") {
				errMsg = strings.Trim(part[len("error="):], `"`)
			} else if strings.HasPrefix(part, "error_description=") {
				errDesc = strings.Trim(part[len("error_description="):], `"`)
			} else if strings.HasPrefix(part, "scope=") {
				scope = strings.Trim(part[len("scope="):], `"`)
			} else if strings.HasPrefix(part, "error_uri=") {
				errUri = strings.Trim(part[len("error_uri="):], `"`)
			}
		}

		if errMsg != "" {
			errLog := fmt.Sprintf("credential request failed with error %s", errMsg)
			if errDesc != "" {
				errLog += fmt.Sprintf(": %s", errDesc)
			}
			if errUri != "" {
				errLog += fmt.Sprintf(" (see %s)", errUri)
			}
			if scope != "" {
				errLog += fmt.Sprintf(" (required scope: %s)", scope)
			}
			return fmt.Errorf("%s", errLog)
		}
		return fmt.Errorf("credential request unauthorized")
	} else if resp.StatusCode == http.StatusBadRequest {
		var errorResponse openid4vci.CredentialErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errorResponse)
		if err != nil {
			return fmt.Errorf("could not decode credential error response: %v", err)
		}
		return fmt.Errorf("credential request failed with error %s: %s", errorResponse.Error, errorResponse.ErrorDescription)
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("credential request failed: %s", resp.Status)
	}

	var credentialResponse openid4vci.CredentialResponse
	err = json.NewDecoder(resp.Body).Decode(&credentialResponse)
	if err != nil {
		return fmt.Errorf("could not decode credential response: %v", err)
	}

	err = credentialResponse.Validate(deferredResponse)
	if err != nil {
		return fmt.Errorf("invalid credential response: %v", err)
	}

	// Verify and store the received credentials
	sdJwts := make([]sdjwtvc.SdJwtVc, len(credentialResponse.Credentials))
	for i, cred := range credentialResponse.Credentials {
		sdJwts[i] = sdjwtvc.SdJwtVc(cred.Credential)
	}

	// Store the credentials using the storage client
	return s.storageClient.VerifyAndStoreSdJwts(sdJwts, nil)
}
