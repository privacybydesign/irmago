package openid4vci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/internal/services"
	"github.com/privacybydesign/irmago/eudi/internal/storage"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/oauth2"
	"github.com/privacybydesign/irmago/irma"
)

type session struct {
	credentialOffer          *CredentialOffer
	credentialIssuerMetadata *CredentialIssuerMetadata
	requestorInfo            *irma.RequestorInfo
	credentials              []*irma.CredentialTypeInfo
	storageClient            SdJwtVcStorageClient
	httpClient               *http.Client
	handler                  Handler
	storage                  storage.Storage
	holderVerifier           *sdjwtvc.HolderVerificationProcessor
	//keyBinder                sdjwtvc.KeyBinder

	issuerSettings openid4vciSessionIssuerSettings
}

// openid4vciSessionIssuerSettings contains all settings related to the Credential Issuer and Credential Offer that are required to perform the session, extracted from the Credential Offer and Credential Issuer metadata
type openid4vciSessionIssuerSettings struct {
	grantType                   Grant
	authorizationServer         string
	authorizationServerMetadata *oauth2.AuthorizationServerMetadata

	useCredentialRequestEncryption bool
	credentialRequestEncryptionAlg *jwa.ContentEncryptionAlgorithm
	credentialRequestEncryptionKey *jwk.Key
}

// sessionCredentialRequestPreferences contains wallet-based preferences related to the credential that will be requested
// We define this struct, so that we apply logic to the credential metadata, and choose the preferences from the available options, in case multiple options are offered by the issuer metadata (e.g. multiple supported encryption algorithms, or multiple supported key binding methods)
type sessionCredentialRequestPreferences struct {
	cryptographicBindingMethod *proofs.CryptographicBindingMethod
}

func (s *session) perform() error {
	// TODO: validate all session properties are correctly set

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
	switch s.issuerSettings.grantType.GetGrantType() {
	case GrantType_AuthorizationCode:
		grantHandler = &AuthorizationCodeFlowHandler{
			httpClient: s.httpClient,
		}
	case GrantType_PreAuthorizedCode:
		grantHandler = &PreAuthorizedCodeFlowHandler{}
	default:
		s.handler.Failure(&irma.SessionError{
			ErrorType: irma.ErrorInvalidRequest,
			Err:       fmt.Errorf("unsupported grant type"),
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
		irma.Logger.Infof("error requesting credentials: %v", err)
		s.handler.Failure(&irma.SessionError{
			Err: fmt.Errorf("could not request credentials: %v", err),
		})
		return nil
	}

	s.handler.Success("openid4vci session completed")
	return nil
}

func (s *session) configureIssuerSettings() error {
	// Determine which grant-type to use (Authorization Code is preferred over Pre-Authorized Code)
	if s.credentialOffer.Grants.AuthorizationCodeGrant != nil {
		s.issuerSettings.grantType = s.credentialOffer.Grants.AuthorizationCodeGrant
	} else if s.credentialOffer.Grants.PreAuthorizedCodeGrant != nil {
		s.issuerSettings.grantType = s.credentialOffer.Grants.PreAuthorizedCodeGrant
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
	s.issuerSettings.authorizationServer = authorizationServer
	s.issuerSettings.authorizationServerMetadata = asMetadata

	// TODO: verify AS supports the required features and to extract endpoints

	// Determine if we need to use Credential Request Encryption
	s.issuerSettings.useCredentialRequestEncryption = false
	if s.credentialIssuerMetadata.CredentialRequestEncryption != nil {
		requestEncryption := *s.credentialIssuerMetadata.CredentialRequestEncryption

		if requestEncryption.EncryptionRequired {
			s.issuerSettings.useCredentialRequestEncryption = true

			// Determine which encryption algorithm to use
			for _, algName := range requestEncryption.EncValuesSupported {
				if alg, ok := jwa.LookupContentEncryptionAlgorithm(algName); ok {
					s.issuerSettings.credentialRequestEncryptionAlg = &alg
					break
				}
			}
			if s.issuerSettings.credentialRequestEncryptionAlg == nil {
				return fmt.Errorf("no supported encryption algorithm found for credential request encryption")
			}

			// Get a key from the JWKS to use for encryption
			for i := 0; i < requestEncryption.Jwks.Len(); i++ {
				if key, found := requestEncryption.Jwks.Key(i); found {
					keyAlg, keyAlgPresent := key.Algorithm()
					keyUsage, keyUsagePresent := key.KeyUsage()

					if keyAlgPresent && keyAlg.String() == s.issuerSettings.credentialRequestEncryptionAlg.String() && keyUsagePresent && keyUsage == "enc" {
						s.issuerSettings.credentialRequestEncryptionKey = &key
					}
				} else {
					break
				}
			}
			if s.issuerSettings.credentialRequestEncryptionKey == nil {
				return fmt.Errorf("no suitable key found in credential request encryption for algorithm %s", s.issuerSettings.credentialRequestEncryptionAlg.String())
			}
		}
	}

	return nil
}

func getCredentialRequestPreferences(c CredentialConfiguration) *sessionCredentialRequestPreferences {
	s := &sessionCredentialRequestPreferences{}

	if len(c.CryptographicBindingMethodsSupported) > 0 {
		var cryptoBindingMethod proofs.CryptographicBindingMethod

		// Order of preferred cryptographic binding methods: JWK > DID > COSE, based on ease of implementation and expected level of support among issuers
		if slices.Contains(c.CryptographicBindingMethodsSupported, proofs.CryptographicBindingMethod_JWK) {
			cryptoBindingMethod = proofs.CryptographicBindingMethod_JWK
		} else if slices.Contains(c.CryptographicBindingMethodsSupported, proofs.CryptographicBindingMethod_DID_KEY) {
			cryptoBindingMethod = proofs.CryptographicBindingMethod_DID_KEY
		} else if slices.Contains(c.CryptographicBindingMethodsSupported, proofs.CryptographicBindingMethod_COSE) {
			cryptoBindingMethod = proofs.CryptographicBindingMethod_COSE
		}
		s.cryptographicBindingMethod = &cryptoBindingMethod
	}

	return s
}

func (s *session) getAuthorizationServer() (string, error) {
	if len(s.credentialIssuerMetadata.AuthorizationServers) == 0 {
		// Use the credential issuer as the authorization server if no authorization servers are listed in the metadata
		return s.credentialOffer.CredentialIssuer, nil
	} else {
		credentialOfferedAuthServer := s.issuerSettings.grantType.GetAuthorizationServer()

		// Try to match the authorization server from the offer to the metadata, or just pick the first one if no hint is given in the offer
		if credentialOfferedAuthServer == nil {
			return s.credentialIssuerMetadata.AuthorizationServers[0], nil
		}

		for _, authServer := range s.credentialIssuerMetadata.AuthorizationServers {
			if authServer == *credentialOfferedAuthServer {
				return authServer, nil
			}
		}
	}
	return "", fmt.Errorf("no valid authorization server found in credential issuer metadata")
}

func (s *session) requestCredentials(accessToken string) error {
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

// requestCredential requests a credential for the given credential configuration ID. Make sure the cNonce is provided if required (Nonce Endpoint is available) and is fresh.
func (s *session) requestCredential(credConfigId string, cNonce *string, accessToken string) error {
	if s.credentialIssuerMetadata.NonceEndpoint != "" && cNonce == nil {
		return fmt.Errorf("credential request requires nonce but none was provided")
	}

	credentialConfig, ok := s.credentialIssuerMetadata.CredentialConfigurationsSupported[credConfigId]
	if !ok {
		return fmt.Errorf("credential configuration %q not found in issuer metadata", credConfigId)
	}

	if err := credentialConfig.ValidateSupportedFeatures(); err != nil {
		return fmt.Errorf("credential configuration %q is not supported: %v", credConfigId, err)
	}

	// TODO: determine credential specific settings (like cryptographic key binding requirements) based on the credential configuration metadata, and pass those to the requestCredential function
	credentialRequestPreferences := getCredentialRequestPreferences(credentialConfig)
	requireCryptographicKeyBinding := credentialRequestPreferences.cryptographicBindingMethod != nil

	// TODO: fill correct fields in Credential Request..
	// For now, we only support the credential_configuration_id parameter, no credential_identifier from authorization details
	request := &CredentialRequest{
		CredentialConfigurationId: &credConfigId,
	}

	// If Cryptographic Key Binding is required, we need to create key binding keys and proofs
	// TODO: disabled check for testing with Digidentity
	keyBindingService := services.NewHolderBindingKeyService(s.storage)

	var keys uuid.UUIDs
	if requireCryptographicKeyBinding {
		// Create a number (equals to the desired batch size or 1 otherwise) of key binding keys and proofs using the c_nonce
		num := uint(1)
		if s.credentialIssuerMetadata.BatchCredentialIssuance != nil {
			num = s.credentialIssuerMetadata.BatchCredentialIssuance.BatchSize
		}

		// Since we now only support JWT proofs (and the issuer supports this, as checked with ValidateSupportedFeatures), we can directly use that to create the key pairs with JWT proofs
		proofType := credentialConfig.ProofTypesSupported[ProofTypeIdentifier_JWT]

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

		// Create a Proof builder, matching the `proofType` from the supported proof types
		proofBuilder := proofs.NewJwtProofBuilder(issuer, s.credentialIssuerMetadata.CredentialIssuer, alg, cNonce, eudi_jwt.NewSystemClock(), *credentialRequestPreferences.cryptographicBindingMethod)

		var proofs []string
		var err error

		keys, proofs, err = keyBindingService.CreateKeyPairsWithProofs(num, proofBuilder)
		if err != nil {
			return fmt.Errorf("could not create key pairs: %v", err)
		}

		// Use unsafe to convert []string to []any without allocations
		// If we use type-safe conversion, we would need to allocate and copy each element
		// which is costly when dealing with many key bindings
		// x := *(*[]any)(unsafe.Pointer(&proofJwts))
		// x = x[:len(proofJwts)]
		x := make([]any, len(proofs))
		for i, v := range proofs {
			x[i] = v
		}

		request.Proofs = &Proofs{
			ProofTypeIdentifier_JWT: x,
		}
	}

	// If the issuer requires encryption of the credential request, we need to handle that here
	var requestBody []byte
	var contentType string
	if s.issuerSettings.useCredentialRequestEncryption {
		contentType = "application/jwt"

		// TODO: handle alg/key errors
		alg, _ := (*s.issuerSettings.credentialRequestEncryptionKey).Algorithm()
		key, _ := (*s.issuerSettings.credentialRequestEncryptionKey).PublicKey()

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

	irma.Logger.Infof("Sending credential request: %s = %s", contentType, string(requestBody))

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
		var errorResponse CredentialErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errorResponse)
		if err != nil {
			return fmt.Errorf("could not decode credential error response: %v", err)
		}
		return fmt.Errorf("credential request failed with error %s: %s", errorResponse.Error, errorResponse.ErrorDescription)
	} else if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// TODO: we're handling 201: Created as OK for now, but that is not completely according to spec
		return fmt.Errorf("credential request failed: %s", resp.Status)
	}

	var credentialResponse CredentialResponse
	err = json.NewDecoder(resp.Body).Decode(&credentialResponse)
	if err != nil {
		return fmt.Errorf("could not decode credential response: %v", err)
	}

	err = credentialResponse.Validate(deferredResponse)
	if err != nil {
		return fmt.Errorf("invalid credential response: %v", err)
	}

	// Verify and store the received credentials
	var processedSdJwtPayload *sdjwtvc.ProcessedSdJwtPayload
	verifiedSdJwtVcs := make([]*sdjwtvc.VerifiedSdJwtVc, len(credentialResponse.Credentials))
	for i, cred := range credentialResponse.Credentials {
		// Verify the credential
		verifiedSdJwt, err := s.holderVerifier.ParseAndVerifySdJwtVc(sdjwtvc.SdJwtVcKb(cred.Credential))
		if err != nil {
			return fmt.Errorf("failed to verify credential: %v", err)
		}
		verifiedSdJwtVcs[i] = verifiedSdJwt

		if i == 0 {
			// Log the first credential for debugging purposes
			irma.Logger.Infof("Received credential (first from batch only): %s", string(cred.Credential))

			// Save the processed SD-JWT payload of the first credential, for storage in the credential batch
			// TODO: processedSdJwtPayload = needs to come from s.holderVerifier.ParseAndVerifySdJwtVc
		}
	}

	// Verify uniquness of key binding confirmations if required by the issuer settings
	err = sdjwtvc.CheckKeyBindingConfirmationUniqueness(verifiedSdJwtVcs)
	if err != nil {
		return fmt.Errorf("key binding confirmation uniqueness check failed: %v", err)
	}

	// Store the credentials + holder-binding keys + metadata (+ images?) in the storage (in bulk), so we can use a transaction and make sure everything is stored correctly, and also for performance reasons when dealing with batch issuance
	credentialService := services.NewCredentialService(s.storage)

	// TODO: fill metadata based on the credential response and issuer/credential configuration metadata
	metadata := services.IssuedCredentialMetadata{
		// CredentialConfigurationId: credConfigId,
		// Issuer:                    s.credentialIssuerMetadata.CredentialIssuer,
		// IssuanceDate:              verifiedSdJwtVcs[0].IssuanceDate, // Assuming all credentials in the batch share the same issuance date, as they should according to the spec
	}

	err = credentialService.VerifyAndStoreIssuedCredentials(verifiedSdJwtVcs, *processedSdJwtPayload, metadata, requireCryptographicKeyBinding, keys)
	if err != nil {
		// Error storing credentials; remove the already stored keys for the credentials that were received, to avoid orphaned keys in the storage
		if requireCryptographicKeyBinding {
			err = keyBindingService.RemoveKeys(keys)
			if err != nil {
				irma.Logger.Warnf("failed to remove key binding keys after credential storage failure: %v", err)
			}
		}
		return fmt.Errorf("failed to verify and store issued credentials: %v", err)
	}

	return nil
}

// requestNonce requests a fresh nonce from the issuer's nonce endpoint
func (s *session) requestNonce() (string, error) {
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

	var nonceResponse NonceResponse
	err = json.NewDecoder(resp.Body).Decode(&nonceResponse)
	if err != nil {
		return "", fmt.Errorf("could not decode nonce response: %v", err)
	}

	return nonceResponse.Nonce, nil
}

// extractScopesFromCredentialOffer finds the scopes in the issuer metadata, for the requested credential configurations from the credential offer.
func (s *session) extractScopesFromCredentialOffer() []string {
	var scopes []string
	for _, configId := range s.credentialOffer.CredentialConfigurationIds {
		config := s.credentialIssuerMetadata.CredentialConfigurationsSupported[configId]
		if config.Scope != nil && !slices.Contains(scopes, *config.Scope) {
			scopes = append(scopes, *config.Scope)
		}
	}
	return scopes
}

// extractAuthorizationDetailsJson extracts the authorization details from the credential offer and issuer metadata, and returns it as a JSON string to be included in the authorization request, if needed. If no authorization details are needed, it returns nil.
func (s *session) extractAuthorizationDetailsJson() (*string, error) {
	if len(s.issuerSettings.authorizationServerMetadata.AuthorizationDetailsTypesSupported) == 0 || len(s.credentialOffer.CredentialConfigurationIds) == 1 {
		return nil, nil
	}

	authDetails := make([]oauth2.AuthorizationDetailsRequestRecord, len(s.credentialOffer.CredentialConfigurationIds))
	for i, credential := range s.credentialOffer.CredentialConfigurationIds {
		authDetails[i] = oauth2.AuthorizationDetailsRequestRecord{
			Type:                      "openid_credential",
			CredentialConfigurationId: credential,
		}

		if len(s.credentialIssuerMetadata.AuthorizationServers) > 0 {
			authDetails[i].Locations[0] = s.credentialIssuerMetadata.CredentialIssuer
		}
	}
	authDetailsJsonBytes, err := json.Marshal(authDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authorization details: %v", err)
	}

	authDetailsJson := string(authDetailsJsonBytes)
	return &authDetailsJson, nil
}
