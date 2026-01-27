package irmaclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/oauth2"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/irma"
)

type openid4vciSession struct {
	credentialOffer           *openid4vci.CredentialOffer
	credentialIssuerMetadata  *openid4vci.CredentialIssuerMetadata
	requestorInfo             *irma.RequestorInfo
	credentials               []*irma.CredentialTypeInfo
	storageClient             SdJwtVcStorageClient
	httpClient                *http.Client
	handler                   Handler
	keyBinder                 sdjwtvc.KeyBinder
	credentialMetadataStorage CredentialMetadataStorage
	issuerMetadataStorage     IssuerMetadataStorage

	// Settings determined from the Credential Offer and Credential Issuer metadata
	grantType                   openid4vci.Grant
	authorizationServer         string
	authorizationServerMetadata *oauth2.AuthorizationServerMetadata

	// Credential Request encryption settings
	useCredentialRequestEncryption bool
	credentialRequestEncryptionAlg *jwa.ContentEncryptionAlgorithm
	credentialRequestEncryptionKey *jwk.Key
}

func (s *openid4vciSession) perform() error {
	// TODO: validate all properties are correctly set

	// Determine all settings for the session based on the Credential Offer and Credential Issuer metadata
	err := s.configureIssuerSettings()
	if err != nil {
		s.handler.Failure(&irma.SessionError{
			Err: fmt.Errorf("could not configure the session: %v", err),
		})
		return nil
	}

	// Based on the grant type, perform the appropriate flow
	var grantHandler GrantHandler
	switch s.grantType.GetGrantType() {
	case openid4vci.GrantType_AuthorizationCode:
		grantHandler = &AuthorizationCodeFlowHandler{}
	case openid4vci.GrantType_PreAuthorizedCode:
		grantHandler = &PreAuthorizedCodeFlowHandler{}
	default:
		s.handler.Failure(&irma.SessionError{
			Err: fmt.Errorf("unsupported grant type"),
		})
		return nil
	}

	// Await permission and access token
	permission, err := grantHandler.HandleGrant(s)
	if err != nil {
		s.handler.Failure(&irma.SessionError{
			Err: fmt.Errorf("could not obtain permission to continue issuance session: %v", err),
		})
		return nil
	}

	// Check if permission was granted
	if permission == nil || !permission.PermissionGranted() {
		s.handler.Cancelled()
		return nil
	}

	// AccessToken received;
	err = s.requestCredentials(permission.GetAccessToken())
	if err != nil {
		s.handler.Failure(&irma.SessionError{
			Err: fmt.Errorf("could not request credentials: %v", err),
		})
		return nil
	}

	s.handler.Success("openid4vci session completed")
	return nil
}

func (s *openid4vciSession) configureIssuerSettings() error {
	// Determine which grant-type to use (Authorization Code is preferred over Pre-Authorized Code)
	if s.credentialOffer.Grants.AuthorizationCodeGrant != nil {
		s.grantType = s.credentialOffer.Grants.AuthorizationCodeGrant
	} else if s.credentialOffer.Grants.PreAuthorizedCodeGrant != nil {
		s.grantType = s.credentialOffer.Grants.PreAuthorizedCodeGrant
	} else {
		return fmt.Errorf("no supported grant type found in credential offer")
	}

	// Determine authorization server to use and fetch its metadata
	authorizationServer, err := s.getAuthorizationServer()
	if err != nil {
		return fmt.Errorf("could not determine authorization server to use: %v", err)
	}
	asMetadata, err := oauth2.TryFetchAuthorizationServerMetadata(authorizationServer)
	if err != nil {
		return fmt.Errorf("could not fetch authorization server metadata: %v", err)
	}
	s.authorizationServer = authorizationServer
	s.authorizationServerMetadata = asMetadata

	// Determine if we need to use Credential Request Encryption
	s.useCredentialRequestEncryption = false
	if s.credentialIssuerMetadata.CredentialRequestEncryption != nil {
		requestEncryption := *s.credentialIssuerMetadata.CredentialRequestEncryption

		if requestEncryption.EncryptionRequired {
			s.useCredentialRequestEncryption = true

			// Determine which encryption algorithm to use
			for _, algName := range requestEncryption.EncValuesSupported {
				if alg, ok := jwa.LookupContentEncryptionAlgorithm(algName); ok {
					//if alg, ok := jwa.LookupKeyEncryptionAlgorithm(algName); ok {
					s.credentialRequestEncryptionAlg = &alg
					break
				}
			}
			if s.credentialRequestEncryptionAlg == nil {
				return fmt.Errorf("no supported encryption algorithm found for credential request encryption")
			}

			// Get a key from the JWKS to use for encryption
			for i := 0; i < requestEncryption.Jwks.Len(); i++ {
				if key, found := requestEncryption.Jwks.Key(i); found {
					keyAlg, keyAlgPresent := key.Algorithm()
					keyUsage, keyUsagePresent := key.KeyUsage()

					if keyAlgPresent && keyAlg.String() == s.credentialRequestEncryptionAlg.String() && keyUsagePresent && keyUsage == "enc" {
						s.credentialRequestEncryptionKey = &key
					}
				} else {
					break
				}
			}
			if s.credentialRequestEncryptionKey == nil {
				return fmt.Errorf("no suitable key found in credential request encryption for algorithm %s", s.credentialRequestEncryptionAlg.String())
			}
		}
	}

	return nil
}

func (s *openid4vciSession) getAuthorizationServer() (string, error) {
	if len(s.credentialIssuerMetadata.AuthorizationServers) == 0 {
		// Use the credential issuer as the authorization server if no authorization servers are listed in the metadata
		return s.credentialOffer.CredentialIssuer, nil
	} else {
		credentialOfferedAuthServer := s.grantType.GetAuthorizationServer()

		// Try to match the authorization server from the offer to the metadata, or just pick the first one if no hint is given in the offer
		if credentialOfferedAuthServer == nil {
			return s.credentialIssuerMetadata.AuthorizationServers[0], nil
		}

		for _, authServer := range s.credentialIssuerMetadata.AuthorizationServers {
			if authServer == *credentialOfferedAuthServer {
				// TODO: get metadata from the authorization server's .well-known endpoint to verify it supports the required features and to extract endpoints
				return authServer, nil
			}
		}
	}
	return "", fmt.Errorf("no valid authorization server found in credential issuer metadata")
}

func storeIssuerMetadata(storage IssuerMetadataStorage, metadata *openid4vci.CredentialIssuerMetadata) error {
	name := toTranslatedValue(metadata.Display, func(display openid4vci.CredentialIssuerDisplay) (string, string) {
		return display.Locale, display.Name
	})

	logoUri := toTranslatedValue(metadata.Display, func(display openid4vci.CredentialIssuerDisplay) (string, string) {
		return display.Locale, display.Logo.Uri
	})

	toStore := &IssuerMetadata{
		IssuerId: metadata.CredentialIssuer,
		Name:     name,
		// TODO: figure out a way to find the logo's
		LogoPath: logoUri,
	}
	return storage.Add(toStore)
}

func (s *openid4vciSession) requestCredentials(accessToken string) error {
	if err := storeIssuerMetadata(s.issuerMetadataStorage, s.credentialIssuerMetadata); err != nil {
		return fmt.Errorf("failed to store issuer metadata: %w", err)
	}

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
			// I think, we need to add transaction support; if a single Credential Configuration fails, the entire Credential Offer fails and no credentials should be stored
			return fmt.Errorf("could not request credential %q: %v", credConfigId, err)
		}
	}
	return nil
}

func toTranslatedValue[T any](displays []T, mapper func(T) (string, string)) irma.TranslatedString {
	result := irma.TranslatedString{}
	for _, d := range displays {
		lang, value := mapper(d)
		if lang == "" {
			lang = "en"
		}
		result[lang] = value
	}
	return result
}

func storeCredentialMetadata(storage CredentialMetadataStorage, config *openid4vci.CredentialConfiguration, issuerConfig *openid4vci.CredentialIssuerMetadata) error {
	name := toTranslatedValue(config.CredentialMetadata.Display, func(display openid4vci.CredentialDisplay) (string, string) {
		return display.Locale, display.Name
	})

	attributes := []AttributeMetadata{}
	for _, claim := range config.CredentialMetadata.Claims {
		name := toTranslatedValue(claim.Display, func(display openid4vci.Display) (string, string) {
			return display.Locale, display.Name
		})
		attr := AttributeMetadata{
			// TODO: make this more dynamic
			Id:   claim.Path[0],
			Name: name,
		}
		attributes = append(attributes, attr)
	}

	metadata := CredentialMetadata{
		CredentialId:     config.VerifiableCredentialType,
		Name:             name,
		IssuerId:         issuerConfig.CredentialIssuer,
		LogoPath:         irma.TranslatedString{},
		Attributes:       attributes,
		CredentialFormat: Format_SdJwtVc,
		LastUpdated:      int(time.Now().Unix()),
		Source:           "",
	}

	return storage.Store(&metadata)
}

// requestCredential requests a credential for the given credential configuration ID. Make sure the cNonce is provided if required (Nonce Endpoint is available) and is fresh.
func (s *openid4vciSession) requestCredential(credConfigId string, cNonce *string, accessToken string) error {
	if s.credentialIssuerMetadata.NonceEndpoint != "" && cNonce == nil {
		return fmt.Errorf("credential request requires nonce but none was provided")
	}

	credConfig := s.credentialIssuerMetadata.CredentialConfigurationsSupported[credConfigId]

	err := storeCredentialMetadata(s.credentialMetadataStorage, &credConfig, s.credentialIssuerMetadata)
	if err != nil {
		return fmt.Errorf("failed to store credential metadata")
	}

	requireCryptographicKeyBinding := len(credConfig.CryptographicBindingMethodsSupported) > 0

	// TODO: fill correct fields in Credential Request..
	// For now, we only support the credential_configuration_id parameter, no credential_identifier from authorization details
	request := &openid4vci.CredentialRequest{
		CredentialConfigurationId: &credConfigId,
	}

	// If Cryptographic Key Binding is required, we need to create key binding keys and proofs
	// TODO: disabled check for testing with Digidentity
	//if requireCryptographicKeyBinding {
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
	// TODO: replace with value from wallet attestation?
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

	request.Proofs = &openid4vci.Proofs{
		openid4vci.ProofTypeIdentifier_JWT: x,
	}
	//}

	// If the issuer requires encryption of the credential request, we need to handle that here
	var requestBody []byte
	var contentType string
	if s.useCredentialRequestEncryption {
		contentType = "application/jwt"

		// TODO: handle alg/key errors
		alg, _ := (*s.credentialRequestEncryptionKey).Algorithm()
		key, _ := (*s.credentialRequestEncryptionKey).PublicKey()

		token, err := jwt.NewBuilder().
			Claim("credential_configuration_id", request.CredentialConfigurationId).
			Claim("proofs", request.Proofs).
			Build()

		if err != nil {
			irma.Logger.Errorf("failed to build jwt for credential request: %v", err)
			return err
		}

		encryptedToken, err := jwt.NewSerializer().
			Encrypt(jwt.WithEncryptOption(jwe.WithKey(alg, key))).
			Serialize(token)

		requestBody = encryptedToken

		if err != nil {
			irma.Logger.Errorf("failed to encrypt jwt for credential request: %v", err)
			return err
		}
	} else {
		jsonRequest, err := json.Marshal(request)
		if err != nil {
			return err
		}

		contentType = "application/json"
		requestBody = jsonRequest
	}

	irma.Logger.Tracef("Sending credential request: %s", string(requestBody))

	// Send the request
	req, err := http.NewRequest("POST", s.credentialIssuerMetadata.CredentialEndpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}

	// Set the headers
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", contentType)

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
		//deferredResponse = true
		return fmt.Errorf("wallet does not accept deferred credential responses for now")
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
	} else if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// TODO: we're handling 201: Created as OK for now, but that is not completely according to spec
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
	sdJwts := make([]sdjwtvc.SdJwtVcKb, len(credentialResponse.Credentials))
	for i, cred := range credentialResponse.Credentials {
		sdJwts[i] = sdjwtvc.SdJwtVcKb(cred.Credential)

		// TODO: remove this
		if i == 0 {
			irma.Logger.Printf("first credential: %s", sdJwts[i])
		}
	}

	// Store the credentials using the storage client
	return s.storageClient.VerifyAndStoreSdJwts(sdJwts, nil, requireCryptographicKeyBinding)
}

// requestNonce requests a fresh nonce from the issuer's nonce endpoint
func (s *openid4vciSession) requestNonce() (string, error) {
	// TODO: implement use of DPoP nonce
	req, err := http.NewRequest("POST", s.credentialIssuerMetadata.NonceEndpoint, bytes.NewBuffer([]byte{}))
	if err != nil {
		return "", err
	}

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
