package openid4vci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/internal/httpext"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/oauth2"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
)

type session struct {
	credentialOffer          *CredentialOffer
	credentialIssuerMetadata *metadata.CredentialIssuerMetadata
	requestorInfo            *clientmodels.TrustedParty
	credentials              []*clientmodels.CredentialDescriptor
	httpClient               *http.Client
	handler                  Handler
	storage                  storage.Storage
	holderVerifier           *sdjwtvc.HolderVerificationProcessor

	issuerSettings openid4vciSessionIssuerSettings
}

// openid4vciSessionIssuerSettings contains all settings related to the Credential Issuer and Credential Offer that are required to perform the session, extracted from the Credential Offer and Credential Issuer metadata
type openid4vciSessionIssuerSettings struct {
	grantType                   Grant
	authorizationServer         string
	authorizationServerMetadata *oauth2.AuthorizationServerMetadata

	useCredentialRequestEncryption        bool
	credentialRequestContentEncryptionAlg *jwa.ContentEncryptionAlgorithm
	credentialRequestEncryptionKey        *jwk.Key
}

// sessionCredentialRequestPreferences contains wallet-based preferences related to the credential that will be requested
// We define this struct, so that we apply logic to the credential metadata, and choose the preferences from the available options, in case multiple options are offered by the issuer metadata (e.g. multiple supported encryption algorithms, or multiple supported key binding methods)
type sessionCredentialRequestPreferences struct {
	cryptographicBindingMethod *proofs.CryptographicBindingMethod
}

func (s *session) perform() {
	// TODO: validate all session properties are correctly set

	// Determine all settings for the session based on the Credential Offer and Credential Issuer metadata
	err := s.configureIssuerSettings()
	if err != nil {
		s.handler.Failure(&clientmodels.SessionError{
			WrappedError: fmt.Sprintf("could not configure the session: %v", err),
		})
		return
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
		s.handler.Failure(&clientmodels.SessionError{
			ErrorType:    "invalidRequest",
			WrappedError: "unsupported grant_type",
		})
		return
	}

	// Await permission and access token
	permission, err := grantHandler.HandleGrant(s)
	if err != nil {
		s.handler.Failure(&clientmodels.SessionError{
			WrappedError: fmt.Sprintf("could not continue issuance session: %v", err),
		})
		return
	}

	// Check if permission was granted
	if permission == nil || !permission.PermissionGranted() {
		s.handler.Cancelled()
		return
	}

	// Fetch and verify credentials (but do not store yet).
	fetched, err := s.obtainCredentials(permission.GetAccessToken())
	if err != nil {
		eudi.Logger.Infof("error obtaining credentials: %v", err)
		s.handler.Failure(&clientmodels.SessionError{
			WrappedError: err.Error(),
		})
		return
	}

	// Build offered credentials with actual attribute values from the verified SD-JWTs.
	offeredCredentials := s.buildOfferedCredentials(fetched)

	// Ask user for permission to add the offered credentials to the wallet.
	permissionChannel := make(chan bool, 1)
	s.handler.RequestPermission(
		offeredCredentials,
		s.requestorInfo,
		PermissionHandler(func(proceed bool) {
			permissionChannel <- proceed
		}),
	)

	permissionGranted := <-permissionChannel
	if !permissionGranted {
		for _, fc := range fetched {
			fc.cleanupKeys()
		}
		s.handler.Cancelled()
		return
	}

	// Permission granted — store the fetched credentials.
	if err := s.storeCredentials(fetched); err != nil {
		s.handler.Failure(&clientmodels.SessionError{
			WrappedError: fmt.Sprintf("could not store credentials: %v", err),
		})
		return
	}

	s.handler.Success("openid4vci session completed", offeredCredentials)
}

// fetchedCredential holds the result of fetching and verifying credentials
// for a single credential configuration, before they are stored.
type fetchedCredential struct {
	credentialConfigurationId      string
	verifiedSdJwtVcs               []*sdjwtvc.VerifiedSdJwtVc
	requireCryptographicKeyBinding bool
	publicKeyIdentifiers           []models.PublicHolderBindingKey
	keyBindingService              services.HolderBindingKeyService
}

func (fc *fetchedCredential) cleanupKeys() {
	if !fc.requireCryptographicKeyBinding || len(fc.publicKeyIdentifiers) == 0 || fc.keyBindingService == nil {
		return
	}
	keyIds := make([]datatypes.UUID, len(fc.publicKeyIdentifiers))
	for i, key := range fc.publicKeyIdentifiers {
		keyIds[i] = key.ID
	}
	if err := fc.keyBindingService.RemoveKeys(keyIds); err != nil {
		eudi.Logger.Warnf("failed to remove holder binding keys: %v", err)
	}
}

func (s *session) obtainCredentials(accessToken string) ([]*fetchedCredential, error) {
	var cNonce *string
	if s.credentialIssuerMetadata.NonceEndpoint != "" {
		cNonceValue, err := s.requestNonce()
		if err != nil {
			return nil, err
		}
		cNonce = &cNonceValue
	}

	// TODO: handle in parallel
	var result []*fetchedCredential
	for _, credentialConfigurationId := range s.credentialOffer.CredentialConfigurationIds {
		fc, err := s.obtainCredential(credentialConfigurationId, cNonce, accessToken)
		if err != nil {
			for _, prev := range result {
				prev.cleanupKeys()
			}
			return nil, fmt.Errorf("could not obtain credential %q: %v", credentialConfigurationId, err)
		}
		result = append(result, fc)
	}
	return result, nil
}

func (s *session) storeCredentials(fetched []*fetchedCredential) error {
	credentialService := services.NewCredentialService(s.storage)
	for _, fc := range fetched {
		err := credentialService.VerifyAndStoreIssuedCredentials(
			fc.verifiedSdJwtVcs,
			fc.credentialConfigurationId,
			*s.credentialIssuerMetadata,
			fc.requireCryptographicKeyBinding,
			fc.publicKeyIdentifiers,
		)
		if err != nil {
			fc.cleanupKeys()
			return fmt.Errorf("failed to store credentials for %q: %v", fc.credentialConfigurationId, err)
		}
	}
	return nil
}

// buildOfferedCredentials creates Credential instances for the permission dialog
// by combining issuer metadata (display names, claim paths) with actual attribute
// values from the fetched and verified SD-JWT VCs.
func (s *session) buildOfferedCredentials(fetched []*fetchedCredential) []*clientmodels.Credential {
	batch := s.credentialIssuerMetadata.BatchCredentialIssuance
	result := make([]*clientmodels.Credential, 0, len(fetched))

	for _, fc := range fetched {
		config, ok := s.credentialIssuerMetadata.CredentialConfigurationsSupported[fc.credentialConfigurationId]
		if !ok || config.CredentialMetadata == nil {
			continue
		}

		// Use the first credential in the batch as source of attribute values.
		var payload sdjwtvc.ProcessedSdJwtPayload
		if len(fc.verifiedSdJwtVcs) > 0 {
			payload = fc.verifiedSdJwtVcs[0].ProcessedSdJwtPayload
		}

		displays := metadata.ToTranslateableList(config.CredentialMetadata.Display)
		name := metadata.ConvertDisplayToTranslatedString(displays)

		issuerDisplays := metadata.ToTranslateableList(s.credentialIssuerMetadata.Display)
		issuerName := metadata.ConvertDisplayToTranslatedString(issuerDisplays)

		var image *clientmodels.Image
		credentialLogoManager := s.storage.FileSystem().Credentials().LogoManager()
		for _, display := range config.CredentialMetadata.Display {
			if display.Logo != nil {
				image = eudi.LoadLogoImage(credentialLogoManager, display.Logo.Uri)
				break
			}
		}

		attrs := buildAttributesWithValues(config.CredentialMetadata.Claims, payload)

		var batchSize *uint
		if batch != nil {
			n := batch.BatchSize
			batchSize = &n
		}

		var issuanceDate, expiryDate int64
		if len(fc.verifiedSdJwtVcs) > 0 {
			jwt := fc.verifiedSdJwtVcs[0].IssuerSignedJwtPayload
			issuanceDate = jwt.IssuedAt
			expiryDate = jwt.Expiry
		}

		result = append(result, &clientmodels.Credential{
			CredentialId:          config.VerifiableCredentialType,
			Name:                  name,
			Issuer:                clientmodels.TrustedParty{Name: issuerName},
			Image:                 image,
			CredentialInstanceIds: map[clientmodels.CredentialFormat]string{},
			BatchInstanceCountsRemaining: map[clientmodels.CredentialFormat]*uint{
				clientmodels.Format_SdJwtVc: batchSize,
			},
			Attributes:   attrs,
			IssuanceDate: issuanceDate,
			ExpiryDate:   expiryDate,
		})
	}
	return result
}

// buildAttributesWithValues builds an attribute list directly from the credential
// payload. The claim metadata is consulted only for display-name translations and
// for ordering: claims declared in metadata appear in declared order, payload-only
// claims are appended alphabetically. Claims without a metadata display entry
// produce attributes with DisplayName: nil.
func buildAttributesWithValues(claims []metadata.ClaimsDescription, payload sdjwtvc.ProcessedSdJwtPayload) []clientmodels.Attribute {
	displayLookup := map[string]clientmodels.TranslatedString{}
	metadataOrder := map[string]int{}
	for i, c := range claims {
		key := clientmodels.ClaimPathKey(c.Path)
		metadataOrder[key] = i
		if len(c.Display) == 0 {
			continue
		}
		displayLookup[key] = claimDisplayToTranslatedString(c.Display)
	}

	return services.BuildAttributesFromPayload(&payload, displayLookup, metadataOrder)
}

func claimDisplayToTranslatedString(displays []metadata.Display) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	for _, d := range displays {
		locale := clientmodels.DefaultFallbackLanguage
		if d.Locale != nil {
			locale, _ = metadata.TryGetBaseLanguageFromLocale(*d.Locale)
		}
		result[locale] = d.Name
	}
	return result
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
					s.issuerSettings.credentialRequestContentEncryptionAlg = &alg
					break
				}
			}
			if s.issuerSettings.credentialRequestContentEncryptionAlg == nil {
				return fmt.Errorf("no supported encryption algorithm found for credential request encryption")
			}

			// Get a key from the JWKS to use for encryption
			for i := 0; i < requestEncryption.Jwks.Len(); i++ {
				if key, found := requestEncryption.Jwks.Key(i); found {
					keyUsage, keyUsagePresent := key.KeyUsage()

					if keyUsagePresent && keyUsage == "enc" {
						s.issuerSettings.credentialRequestEncryptionKey = &key
						break
					}
				}
			}
			if s.issuerSettings.credentialRequestEncryptionKey == nil {
				return fmt.Errorf("no suitable key found in jwks for credential request encryption")
			}
		}
	}

	return nil
}

func getCredentialRequestPreferences(c metadata.CredentialConfiguration) *sessionCredentialRequestPreferences {
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

// fetchCredential requests and verifies a credential for a given configuration
// ID without storing it. The caller stores via storeCredentials or cleans up
// via cleanupKeys.
func (s *session) obtainCredential(credentialConfigurationId string, cNonce *string, accessToken string) (*fetchedCredential, error) {
	if s.credentialIssuerMetadata.NonceEndpoint != "" && cNonce == nil {
		return nil, fmt.Errorf("credential request requires nonce but none was provided")
	}

	credentialConfig, ok := s.credentialIssuerMetadata.CredentialConfigurationsSupported[credentialConfigurationId]
	if !ok {
		return nil, fmt.Errorf("credential configuration %q not found in issuer metadata", credentialConfigurationId)
	}

	credentialConfigurationValidator := CredentialConfigurationValidator{}
	if err := credentialConfigurationValidator.ValidateSupportedFeatures(&credentialConfig); err != nil {
		return nil, fmt.Errorf("credential configuration %q is not supported: %v", credentialConfigurationId, err)
	}

	credentialRequestPreferences := getCredentialRequestPreferences(credentialConfig)
	requireCryptographicKeyBinding := credentialRequestPreferences.cryptographicBindingMethod != nil

	request := &CredentialRequest{
		CredentialConfigurationId: &credentialConfigurationId,
	}

	var publicKeyIdentifiers []models.PublicHolderBindingKey
	keyBindingService := services.NewHolderBindingKeyService(s.storage.Db())
	if requireCryptographicKeyBinding {
		num := uint(1)
		if s.credentialIssuerMetadata.BatchCredentialIssuance != nil {
			num = s.credentialIssuerMetadata.BatchCredentialIssuance.BatchSize
		}

		proofType := credentialConfig.ProofTypesSupported[metadata.ProofTypeIdentifier_JWT]

		// Determine the signing algorithm to use for the proofs, based on the supported algorithms in the credential metadata. We'll just pick the first supported algorithm that we also support, since we expect most issuers to only support one algorithm per proof type, and if they support multiple, it doesn't give us any indication of which one to prefer.
		var alg jwa.SignatureAlgorithm
		for _, algName := range proofType.ProofSigningAlgValuesSupported {
			if algName == "ES256K" {
				continue
			}
			foundAlg, ok := jwa.LookupSignatureAlgorithm(algName)
			if ok {
				alg = foundAlg
				break
			}
		}

		issuer := "org.irmacard.cardemu"
		proofBuilder := proofs.NewJwtProofBuilder(issuer, s.credentialIssuerMetadata.CredentialIssuer, alg, cNonce, eudi_jwt.NewSystemClock(), *credentialRequestPreferences.cryptographicBindingMethod)

		var proofs []string
		var err error

		publicKeyIdentifiers, proofs, err = keyBindingService.CreateKeyPairsWithProofs(num, proofBuilder)
		if err != nil {
			return nil, fmt.Errorf("could not create key pairs: %v", err)
		}

		x := make([]any, len(proofs))
		for i, v := range proofs {
			x[i] = v
		}

		request.Proofs = &metadata.Proofs{
			metadata.ProofTypeIdentifier_JWT: x,
		}
	}

	var requestBody []byte
	var contentType string
	if s.issuerSettings.useCredentialRequestEncryption {
		contentType = "application/jwt"

		alg, _ := (*s.issuerSettings.credentialRequestEncryptionKey).Algorithm()
		key, _ := (*s.issuerSettings.credentialRequestEncryptionKey).PublicKey()

		token, err := jwt.NewBuilder().
			Claim("credential_configuration_id", request.CredentialConfigurationId).
			Claim("proofs", request.Proofs).
			Build()

		if err != nil {
			return nil, fmt.Errorf("failed to build jwt for credential request: %v", err)
		}

		encryptedToken, err := jwt.NewSerializer().
			Encrypt(jwt.WithEncryptOption(jwe.WithKey(alg, key))).
			Serialize(token)

		requestBody = encryptedToken

		if err != nil {
			return nil, fmt.Errorf("failed to encrypt jwt for credential request: %v", err)
		}
	} else {
		jsonRequest, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}

		contentType = "application/json"
		requestBody = jsonRequest
	}

	req, err := http.NewRequest("POST", s.credentialIssuerMetadata.CredentialEndpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", contentType)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	deferredResponse := false
	if resp.StatusCode == http.StatusAccepted {
		return nil, fmt.Errorf("wallet does not accept deferred credential responses for now")
	} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		challengeHeader := resp.Header.Get("WWW-Authenticate")

		challenges, err := httpext.ParseWWWAuthenticate(challengeHeader)
		if err != nil {
			return nil, fmt.Errorf("failed to parse WWW-Authenticate header: %v", err)
		}

		// We'll assume only one challenge is present, and that it contains the error details as parameters. In practice, there should only be one challenge, since multiple challenges are typically used to indicate support for multiple authentication schemes, which is not the case here since the request already included an access token.
		if len(challenges) == 0 {
			return nil, fmt.Errorf("credential request unauthorized")
		}

		challenge := challenges[0]

		var errMsg, errDesc, errUri, scope string
		for key, value := range challenge.Params {
			switch strings.ToLower(key) {
			case "error":
				errMsg = value
			case "error_description":
				errDesc = value
			case "scope":
				scope = value
			case "error_uri":
				errUri = value
			}
		}

		if errMsg != "" {
			errLog := fmt.Sprintf("credential request failed with error %q", errMsg)
			if errDesc != "" {
				errLog += fmt.Sprintf(": %s", errDesc)
			}
			if errUri != "" {
				errLog += fmt.Sprintf(" (see %s)", errUri)
			}
			if scope != "" {
				errLog += fmt.Sprintf(" (required scope: %s)", scope)
			}
			return nil, fmt.Errorf("%s", errLog)
		}
		return nil, fmt.Errorf("credential request unauthorized")
	} else if resp.StatusCode == http.StatusBadRequest {
		var errorResponse CredentialErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errorResponse)
		if err != nil {
			return nil, fmt.Errorf("could not decode credential error response: %v", err)
		}
		return nil, fmt.Errorf("credential request failed with error %q: %s", errorResponse.Error, errorResponse.ErrorDescription)
	} else if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("credential request failed: %s", resp.Status)
	}

	var credentialResponse CredentialResponse
	err = json.NewDecoder(resp.Body).Decode(&credentialResponse)
	if err != nil {
		return nil, fmt.Errorf("could not decode credential response: %v", err)
	}

	err = credentialResponse.Validate(deferredResponse)
	if err != nil {
		return nil, fmt.Errorf("invalid credential response: %v", err)
	}

	verifiedSdJwtVcs := make([]*sdjwtvc.VerifiedSdJwtVc, len(credentialResponse.Credentials))
	for i, cred := range credentialResponse.Credentials {
		verifiedSdJwt, err := s.holderVerifier.ParseAndVerifySdJwtVc(sdjwtvc.SdJwtVcKb(cred.Credential))
		if err != nil {
			return nil, fmt.Errorf("failed to verify credential: %v", err)
		}
		verifiedSdJwtVcs[i] = verifiedSdJwt
	}

	err = sdjwtvc.CheckKeyBindingConfirmationUniqueness(verifiedSdJwtVcs)
	if err != nil {
		return nil, fmt.Errorf("key binding confirmation uniqueness check failed: %v", err)
	}

	return &fetchedCredential{
		credentialConfigurationId:      credentialConfigurationId,
		verifiedSdJwtVcs:               verifiedSdJwtVcs,
		requireCryptographicKeyBinding: requireCryptographicKeyBinding,
		publicKeyIdentifiers:           publicKeyIdentifiers,
		keyBindingService:              keyBindingService,
	}, nil
}

// requestNonce requests a fresh nonce from the issuer's nonce endpoint
func (s *session) requestNonce() (string, error) {
	// TODO: implement use of DPoP nonce
	req, err := http.NewRequest("POST", s.credentialIssuerMetadata.NonceEndpoint, bytes.NewBuffer([]byte{}))
	if err != nil {
		return "", err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

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
	// Start with the scopes which are supported by the AS in general, and then add any additional scopes that are needed for the specific credential configurations in the offer, which might not be included in the AS metadata as supported scopes, but are still needed to be included in the authorization request for the AS to issue the credentials.
	scopes := slices.Clone(s.issuerSettings.authorizationServerMetadata.ScopesSupported)
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
	authDetails := make([]oauth2.AuthorizationDetailsRequestRecord, 0, len(s.credentialOffer.CredentialConfigurationIds))
	for _, credential := range s.credentialOffer.CredentialConfigurationIds {
		authDetail := oauth2.AuthorizationDetailsRequestRecord{
			Type:                      "openid_credential",
			CredentialConfigurationId: credential,
		}

		if len(s.credentialIssuerMetadata.AuthorizationServers) > 0 {
			authDetail.Locations = []string{
				s.credentialOffer.CredentialIssuer,
			}
		}

		authDetails = append(authDetails, authDetail)
	}
	authDetailsJsonBytes, err := json.Marshal(authDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authorization details: %v", err)
	}

	authDetailsJson := string(authDetailsJsonBytes)
	return &authDetailsJson, nil
}
