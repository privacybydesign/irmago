package irmaclient

import (
	"fmt"
	"strings"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
)

type openid4vciSession struct {
	credentialOffer          *openid4vci.CredentialOffer
	credentialIssuerMetadata *openid4vci.CredentialIssuerMetadata
	requestorInfo            *irma.RequestorInfo
	credentials              []*irma.CredentialTypeInfo
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
