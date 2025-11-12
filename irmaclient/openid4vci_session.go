package irmaclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
)

// TokenRequestor is used to asking the user for permission to start the authorization code flow, and let the app handle the code exchange for an access token.
type TokenRequestor interface {
	// RequestToken should start the authorization code flow and get the resulting token(s) via the `TokenHandler`.
	RequestToken(request *irma.AuthorizationCodeAndTokenExchangeRequest,
		requestorInfo *irma.RequestorInfo,
		callback TokenHandler)
}

type authTokenRequest struct {
	channel chan *authTokenResponse
}

type authTokenResponse struct {
	permissionGranted bool
	accessToken       string
	refreshToken      *string
}

type openid4vciSession struct {
	credentialOffer          *openid4vci.CredentialOffer
	credentialIssuerMetadata *openid4vci.CredentialIssuerMetadata
	requestorInfo            *irma.RequestorInfo
	credentials              []*irma.CredentialTypeInfo
	storageClient            SdJwtVcStorageClient
	httpClient               *http.Client
	handler                  Handler
	pendingAuthTokenRequest  *authTokenRequest
	keyBinder                sdjwtvc.KeyBinder
}

func (s *openid4vciSession) perform() error {
	if s.credentialOffer.Grants.AuthorizationCodeGrant == nil {
		s.handler.Failure(&irma.SessionError{
			Err: fmt.Errorf("only authorization code grant is supported"),
		})
		return nil
	}

	authorizationServer, err := s.getAuthorizationServer()
	if err != nil {
		s.handler.Failure(&irma.SessionError{
			Err: fmt.Errorf("could not determine authorization server to use: %v", err),
		})
		return nil
	}

	// Request permission to add the credential, which will start the authorization code flow in the frontend and return the access token via the TokenHandler
	s.pendingAuthTokenRequest = &authTokenRequest{
		channel: make(chan *authTokenResponse, 1),
	}
	defer func() {
		s.pendingAuthTokenRequest = nil
	}()

	issuanceRequest := &irma.OpenId4VciIssuanceRequest{
		CredentialInfoList: s.credentials,
		AuthorizationRequestParameters: irma.AuthorizationRequestParameters{
			IssuerDiscoveryUrl: getDiscoveryUrlFromIssuer(authorizationServer),
			ClientID:           "yivi-app",
			IssuerState:        s.credentialOffer.Grants.AuthorizationCodeGrant.IssuerState,
			Resource:           s.credentialOffer.CredentialIssuer,
			Scopes:             s.extractScopesFromCredentialOffer(),
		},
	}
	s.handler.RequestOpenId4VciIssuancePermission(
		issuanceRequest,
		s.requestorInfo,
		TokenHandler(func(proceed bool, accessToken string, refreshToken *string) {
			if proceed {
				irma.Logger.Printf("received access token via authorization code flow")
				s.pendingAuthTokenRequest.channel <- &authTokenResponse{permissionGranted: true, accessToken: accessToken, refreshToken: refreshToken}
			} else {
				irma.Logger.Printf("User cancelled authorization code flow")
				s.pendingAuthTokenRequest.channel <- &authTokenResponse{permissionGranted: false}
			}
		}),
	)
	permission := s.awaitPermission()

	if permission == nil {
		s.handler.Cancelled()
		return nil
	}

	// AccessToken received;
	// TODO: request credential(s)
	err = s.requestCredentials(permission.accessToken)
	if err != nil {
		s.handler.Failure(&irma.SessionError{
			Err: fmt.Errorf("could not request credentials: %v", err),
		})
		return nil
	}

	s.handler.Success("openid4vci session completed")
	return nil
}

func (s *openid4vciSession) awaitPermission() *authTokenResponse {
	return <-s.pendingAuthTokenRequest.channel
}

func (s *openid4vciSession) getAuthorizationServer() (string, error) {
	if len(s.credentialIssuerMetadata.AuthorizationServers) == 0 {
		// Use the credential issuer as the authorization server if no authorization servers are listed in the metadata
		return s.credentialOffer.CredentialIssuer, nil
	} else {
		// Try to match the authorization server from the offer to the metadata, or just pick the first one if no hint is given in the offer
		if s.credentialOffer.Grants.AuthorizationCodeGrant.AuthorizationServer == nil {
			return s.credentialIssuerMetadata.AuthorizationServers[0], nil
		}

		for _, authServer := range s.credentialIssuerMetadata.AuthorizationServers {
			if authServer == *s.credentialOffer.Grants.AuthorizationCodeGrant.AuthorizationServer && strings.HasPrefix(authServer, "https://") {
				// TODO: get metadata from the authorization server's .well-known endpoint to verify it supports the required features and to extract endpoints
				return authServer, nil
			}
		}
	}
	return "", fmt.Errorf("no valid authorization server found in credential issuer metadata")
}

func (s *openid4vciSession) requestCredentials(accessToken string) error {
	// If the issuer provides a Nonce endpoint, we should get a fresh c_nonce here and use it in all credential requests that require proof of possession
	var cNonce *string
	if s.credentialIssuerMetadata.NonceEndpoint != "" {
		cNonceValue, err := s.requestNonce()
		if err != nil {
			return fmt.Errorf("could not obtain nonce from issuer: %v", err)
		}
		cNonce = &cNonceValue
	}

	// TODO: Request credentials in parallel
	for _, credConfigId := range s.credentialOffer.CredentialConfigurationIds {
		// TODO: check if/how we need to set/pass credential_identifier or credential_configuration_id field to the Credential Request
		// As the credential identifier can be returned from the Authorization Details in the Token Response from authorization code flow
		err := s.requestCredential(credConfigId, cNonce, accessToken)
		if err != nil {
			// TODO: how to handle if a single request fails but others succeed?
			return fmt.Errorf("could not request credential %q: %v", credConfigId, err)
		}
	}
	return nil
}

// requestCredential requests a credential for the given credential configuration ID. Make sure the cNonce is provided if required (Nonce Endpoint is available) and is fresh.
func (s *openid4vciSession) requestCredential(credConfigId string, cNonce *string, accessToken string) error {
	if s.credentialIssuerMetadata.NonceEndpoint != "" && cNonce == nil {
		return fmt.Errorf("credential request requires nonce but none was provided")
	}

	credConfig := s.credentialIssuerMetadata.CredentialConfigurationsSupported[credConfigId]

	// TODO: fill correct fields in Credential Request..
	// For now, we only support the credential_configuration_id parameter, no credential_identifier from authorization details
	request := &openid4vci.CredentialRequest{
		CredentialConfigurationId: &credConfigId,
	}

	// If Cryptographic Key Binding is required, we need to create key binding keys and proofs
	if len(credConfig.CryptographicBindingMethodsSupported) > 0 {
		// Create a number (equals to the desired batch size or 1 otherwise) of key binding keys and proofs using the c_nonce
		num := uint(1)
		if s.credentialIssuerMetadata.BatchCredentialIssuance != nil {
			num = s.credentialIssuerMetadata.BatchCredentialIssuance.BatchSize
		}

		// Since we now only support JWT proofs (and the issuer supports this, as checked with ValidateSupportedFeatures), we can directly use that to create the key pairs with JWT proofs
		proofType := credConfig.ProofTypesSupported[openid4vci.ProofTypeIdentifier_JWT]

		// Determine signing algorithm for key binding proofs
		var alg jwa.SignatureAlgorithm
		for _, algName := range proofType.ProofSigningAlgValuesSupported {
			foundAlg, ok := jwa.LookupSignatureAlgorithm(algName)
			if ok {
				alg = foundAlg
				break
			}
		}

		// According to the spec, the 'issuer' should be an identifier which identifies the wallet TYPE, not the wallet INSTANCE
		// Fow now, we just use our applicationId as a fixed value
		issuer := "org.irmacard.cardemu"
		proofJwts, err := s.keyBinder.CreateKeyPairsWithJwtProofs(num, alg, issuer, s.credentialIssuerMetadata.CredentialIssuer, cNonce)
		if err != nil {
			return fmt.Errorf("could not create key pairs: %v", err)
		}

		// Use unsafe to convert []string to []any without allocations
		// If we use type-safe conversion, we would need to allocate and copy each element
		// which is costly when dealing with many key bindings
		// x := *(*[]any)(unsafe.Pointer(&proofJwts))
		// x = x[:len(proofJwts)]
		x := make([]any, len(proofJwts))
		for i, v := range proofJwts {
			x[i] = v
		}

		// TODO: we need to thoroughly test that this works as intended and does not lead to issues
		// for example; reading more proofs then we created, etc.
		request.Proofs = &openid4vci.Proofs{
			openid4vci.ProofTypeIdentifier_JWT: x,
		}
	}

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
	req.Header.Set("Content-Type", "application/json")

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

// requestNonce requests a fresh nonce from the issuer's nonce endpoint
func (s *openid4vciSession) requestNonce() (string, error) {
	// TODO: implement use of DPoP nonce
	req, err := http.NewRequest("POST", s.credentialIssuerMetadata.NonceEndpoint, bytes.NewBuffer([]byte{}))
	resp, err := s.httpClient.Do(req)
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			irma.Logger.Warnf("failed to close credential request response body: %v", err)
		}
	}()
	if err != nil {
		return "", err
	}
	if !(resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK) {
		return "", fmt.Errorf("nonce request failed: %s", resp.Status)
	}

	var nonceResponse openid4vci.NonceResponse
	err = json.NewDecoder(resp.Body).Decode(&nonceResponse)
	if err != nil {
		return "", fmt.Errorf("could not decode nonce response: %v", err)
	}

	return nonceResponse.Nonce, nil
}

func (s *openid4vciSession) extractScopesFromCredentialOffer() []string {
	var scopes []string
	for _, configId := range s.credentialOffer.CredentialConfigurationIds {
		config := s.credentialIssuerMetadata.CredentialConfigurationsSupported[configId]
		scopes = append(scopes, config.Scope)
	}
	return scopes
}

// TODO: this function is only used while we only use EUDIPLO;  we need to change the code to actually get the metadata, and fall back to /.well-known/openid-configuration if needed
func getDiscoveryUrlFromIssuer(authServer string) string {
	// Used for: Keycloak
	return fmt.Sprintf("%s/.well-known/oauth-authorization-server/", authServer)

	//uri, _ := url.Parse(authServer)

	// Used for: EUDIPLO
	//return fmt.Sprintf("%s://%s/.well-known/openid-configuration", uri.Scheme, uri.Host)

	//return fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server/", uri.Scheme, uri.Host)
	//return fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server/%s", uri.Scheme, uri.Host, strings.Trim(uri.Path, "/"))
}
