package irmaclient

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/eudi/scheme"
)

type SdJwtVcStorageClient interface {
	VerifyAndStoreSdJwts(sdjwts []sdjwtvc.SdJwtVc, requestedCredentials []*irma.CredentialRequest) error
}

type OpenID4VciClient struct {
	eudiConf                   *eudi.Configuration
	httpClient                 *http.Client
	currentSession             *openid4vciSession
	sdJwtVcStorage             SdJwtVcStorage
	sdJwtVcVerificationContext sdjwtvc.SdJwtVcVerificationContext
}

func NewOpenID4VciClient(httpClient *http.Client, eudiConf *eudi.Configuration, sdJwtVcStorage SdJwtVcStorage, sdJwtVcVerificationContext sdjwtvc.SdJwtVcVerificationContext) *OpenID4VciClient {
	return &OpenID4VciClient{
		httpClient:                 httpClient,
		eudiConf:                   eudiConf,
		sdJwtVcStorage:             sdJwtVcStorage,
		sdJwtVcVerificationContext: sdJwtVcVerificationContext,
	}
}

func (client *OpenID4VciClient) NewSession(credentialEndpointUrl string, handler Handler) SessionDismisser {
	client.handleSessionAsync(credentialEndpointUrl, handler)
	return client
}

func (client *OpenID4VciClient) handleSessionAsync(credentialEndpointUrl string, handler Handler) {
	go func() {
		credentialOfferJson, err := client.validateCredentialOfferEndpointAndObtainCredentialOfferParameters(credentialEndpointUrl)

		if err != nil {
			handleFailure(handler, "openid4vci: failed to validate credential offer endpoint: %v", err)
			return
		}

		// Validate the Credential Offer parameters
		credentialOffer, err := client.ParseAndValidateCredentialOffer(credentialOfferJson)
		if err != nil {
			handleFailure(handler, "openid4vci: failed to parse and validate credential offer: %v", err)
			return
		}

		// Obtain Credential Issuer metadata
		credentialIssuerMetadata, err := client.GetAndVerifyCredentialIssuerMetadata(credentialOffer)
		if err != nil {
			handleFailure(handler, "openid4vci: failed to get and verify credential issuer metadata: %v", err)
			return
		}

		// Validate the Credential Offer against the Credential Issuer metadata
		if err = validateCredentialOfferAgainstIssuerMetadata(credentialOffer, credentialIssuerMetadata); err != nil {
			handleFailure(handler, "openid4vci: failed to validate credential offer against credential issuer metadata: %v", err)
			return
		}

		// TODO: Validate the Credential Offer against the Yivi scheme ?

		// Everything looks in order; handle the session by starting the Authorization flow (e.g. show UI to user, obtain authorization, etc)
		err = client.handleCredentialOffer(credentialOffer, credentialIssuerMetadata, handler)

		handleFailure(handler, "openid4vci: failed to handle credential offer: %v", err)
	}()
}

func (client *OpenID4VciClient) handleCredentialOffer(
	credentialOffer *openid4vci.CredentialOffer,
	credentialIssuerMetadata *openid4vci.CredentialIssuerMetadata,
	handler Handler,
) error {
	requestorInfo := convertToRequestorInfo(credentialIssuerMetadata)
	creds, err := convertToCredentialInfoList(credentialOffer.CredentialConfigurationIds, credentialIssuerMetadata)
	if err != nil {
		return fmt.Errorf("failed to convert credential info list: %v", err)
	}

	client.currentSession = &openid4vciSession{
		credentialOffer:          credentialOffer,
		credentialIssuerMetadata: credentialIssuerMetadata,
		requestorInfo:            requestorInfo,
		credentials:              creds,
		handler:                  handler,
		storageClient:            client,
		httpClient:               client.httpClient,
		// sdjwtvcStorage:           client.sdjwtvcStorage,
		// keyBinder:                client.keyBinder,
		// logsStorage:              client.logsStorage,
	}
	defer func() {
		client.currentSession = nil
	}()
	return client.currentSession.perform()
}

func (client *OpenID4VciClient) validateCredentialOfferEndpointAndObtainCredentialOfferParameters(credentialEndpointUrl string) (string, error) {
	parsedUrl, err := url.Parse(credentialEndpointUrl)

	if err != nil {
		return "", fmt.Errorf("failed to parse credential endpoint URI: %v", err)
	}

	// Find out if the Credential Offer is a URI pointing to the Offer parameters (in case of larger payloads), or the parameters itself
	credentialOffer := parsedUrl.Query().Get("credential_offer")
	credentialOfferUri := parsedUrl.Query().Get("credential_offer_uri")

	if credentialOffer == "" && credentialOfferUri == "" {
		return "", fmt.Errorf("no credential_offer or credential_offer_uri found in URI")
	} else if credentialOffer != "" && credentialOfferUri != "" {
		return "", fmt.Errorf("both credential_offer and credential_offer_uri found in URI, only one is allowed")
	} else if credentialOfferUri != "" {
		// Perform HTTP GET on the URI to obtain the Credential Offer parameters
		response, err := client.httpClient.Get(credentialOfferUri)
		defer func() {
			err = response.Body.Close()
			if err != nil {
				irma.Logger.Warnf("failed to close credential offer response body: %v", err)
			}
		}()

		if err != nil {
			return "", fmt.Errorf("failed to get credential offer from Credential Offer URI: %v", err)
		}

		credentialOfferBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read credential offer response body: %v", err)
		}
		credentialOffer = string(credentialOfferBytes)
	}

	return credentialOffer, nil
}

func (client *OpenID4VciClient) ParseAndValidateCredentialOffer(credentialOfferJson string) (*openid4vci.CredentialOffer, error) {
	var credentialOffer openid4vci.CredentialOffer
	err := json.Unmarshal([]byte(credentialOfferJson), &credentialOffer)

	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential offer: %v", err)
	}

	// Validate the Credential Issuer
	parsedCredentialIssuerUri, err := url.Parse(credentialOffer.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential issuer URI: %v", err)
	}

	if parsedCredentialIssuerUri.Scheme != "https" {
		return nil, fmt.Errorf("credential issuer URI (%s) is not HTTPS", credentialOffer.CredentialIssuer)
	}

	if parsedCredentialIssuerUri.RawQuery != "" || parsedCredentialIssuerUri.Fragment != "" {
		return nil, fmt.Errorf("credential issuer URI contains query or fragment, which is not allowed")
	}

	// Validate that at least one Credential Configuration ID is present
	if len(credentialOffer.CredentialConfigurationIds) == 0 {
		return nil, fmt.Errorf("no credential_configuration_ids found in credential offer")
	}

	// Validate the Grants; we only support authorization_code for now
	if credentialOffer.Grants != nil {
		if credentialOffer.Grants.AuthorizationCodeGrant == nil {
			return nil, fmt.Errorf("unsupported grant type in credential offer; only authorization_code is supported")
		}
	}

	return &credentialOffer, nil
}

func (client *OpenID4VciClient) GetAndVerifyCredentialIssuerMetadata(credentialOffer *openid4vci.CredentialOffer) (*openid4vci.CredentialIssuerMetadata, error) {
	parsedCredentialIssuerUri, err := url.Parse(credentialOffer.CredentialIssuer)
	credentialIssuerMetadataUrl := constructCredentialIssuerMetadataUrl(*parsedCredentialIssuerUri)

	req, err := http.NewRequest("GET", credentialIssuerMetadataUrl, nil)

	// Explicitly ask for JSON response, so we do not get signed JWT metadata response
	req.Header.Set("Accept", "application/json")

	// TODO: set Accept-Language as per user/app preference

	response, err := client.httpClient.Do(req)

	// TODO: add caching of metadata response (Cache-Control and Expires headers) ?

	defer func() {
		err = response.Body.Close()
		if err != nil {
			irma.Logger.Warnf("failed to close credential issuer metadata response body: %v", err)
		}
	}()

	if err != nil {
		return nil, fmt.Errorf("failed to get credential issuer metadata: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get credential issuer metadata: server returned status code %d", response.StatusCode)
	}

	if response.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("failed to get credential issuer metadata: server returned unexpected Content-Type %s", response.Header.Get("Content-Type"))
	}

	credentialIssuerMetadataBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential issuer metadata response body: %v", err)
	}

	var credentialIssuerMetadata openid4vci.CredentialIssuerMetadata
	err = json.Unmarshal(credentialIssuerMetadataBytes, &credentialIssuerMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential issuer metadata: %v", err)
	}

	// Validate the Credential Issuer metadata against the spec
	err = credentialIssuerMetadata.Verify(credentialOffer)
	if err != nil {
		return nil, fmt.Errorf("failed to validate credential issuer metadata: %v", err)
	}

	// Validate the metadata against our sub-set of supported features
	err = credentialIssuerMetadata.ValidateSupportedFeatures(credentialOffer)
	if err != nil {
		return nil, fmt.Errorf("credential issuer metadata contains unsupported features: %v", err)
	}

	// Valid metadata; download any logos, if present
	// TODO: check which language we are using first, so we have to download only one logo (if it is not already cached), or..
	// TODO: initiate parallel downloads of logos; but check for unique URLs first
	for _, display := range credentialIssuerMetadata.Display {
		if display.Logo != nil {
			// TODO: check if logo is already in cache first
			logoData, logoMimeType, err := client.downloadRemoteImage(*display.Logo)
			if err != nil {
				irma.Logger.Warnf("failed to download issuer logo from %q: %v", display.Logo.Uri, err)
			}
			// Store the issuer logo in the cache
			logo := scheme.Logo{
				MimeType: logoMimeType,
				Data:     logoData,
			}
			filename := getCredentialIssuerLogoFilenameWithoutExtension(credentialIssuerMetadata.CredentialIssuer, display.Locale)
			_, _, err = client.eudiConf.Issuers.CacheLogo(filename, &logo)
			if err != nil {
				// TODO: how to handle this error ? Proceed without logo ?
				//handleFailure(handler, "openid4vp: failed to store verifier logo: %v", err)
				//return
			}
		}
	}

	return &credentialIssuerMetadata, nil
}

func (client *OpenID4VciClient) downloadRemoteImage(remoteImage openid4vci.RemoteImage) ([]byte, string, error) {
	response, err := client.httpClient.Get(remoteImage.Uri)
	if err != nil {
		return nil, "", fmt.Errorf("failed to download image %s: %v", remoteImage.Uri, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("failed to download logo %s: server returned status code %d", remoteImage.Uri, response.StatusCode)
	}

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read logo %s: %v", remoteImage.Uri, err)
	}

	return bytes, response.Header.Get("Content-Type"), nil
}

func (client *OpenID4VciClient) VerifyAndStoreSdJwts(sdjwts []sdjwtvc.SdJwtVc, requestedCredentials []*irma.CredentialRequest) error {
	return verifyAndStoreSdJwts(sdjwts, client.sdJwtVcStorage, client.sdJwtVcVerificationContext)
}

func (client *OpenID4VciClient) Dismiss() {
	irma.Logger.Info("openid4vci: session dismissed")
}

func constructCredentialIssuerMetadataUrl(credentialIssuer url.URL) string {
	url := &url.URL{
		Scheme: credentialIssuer.Scheme,
		Host:   credentialIssuer.Host,
		Path:   path.Join("/.well-known/openid-credential-issuer", credentialIssuer.Path), // In case the Credential Issuer has multiple tenants, make sure to include the path
	}
	return url.String()
}

func validateCredentialOfferAgainstIssuerMetadata(credentialOffer *openid4vci.CredentialOffer, credentialIssuerMetadata *openid4vci.CredentialIssuerMetadata) error {
	// Validate that the Credential Issuer in the Credential Offer matches that in the Credential Issuer metadata
	if credentialOffer.CredentialIssuer != credentialIssuerMetadata.CredentialIssuer {
		return fmt.Errorf("credential offer credential_issuer does not match credential issuer metadata issuer")
	}

	// Validate that all Credential Configuration IDs in the Credential Offer are supported by the Credential Issuer
	var missingConfigurationId *string
	if !slices.ContainsFunc(credentialOffer.CredentialConfigurationIds, func(configurationId string) bool {
		for supportedConfigurationName := range credentialIssuerMetadata.CredentialConfigurationsSupported {
			if supportedConfigurationName == configurationId {
				return true
			}
		}
		missingConfigurationId = &configurationId
		return false
	}) {
		return fmt.Errorf("credential offer credential_configuration_id %q is not supported by credential issuer", *missingConfigurationId)
	}

	return nil
}

func getCredentialIssuerLogoFilenameWithoutExtension(credentialIssuer string, locale string) string {
	return fmt.Sprintf("%x_%s", sha256.Sum256([]byte(credentialIssuer)), locale)
}

func convertToCredentialInfoList(requestedCredentialConfigs []string, credentialIssuerMetadata *openid4vci.CredentialIssuerMetadata) ([]*irma.CredentialTypeInfo, error) {
	credentialInfoList := make([]*irma.CredentialTypeInfo, 0, len(requestedCredentialConfigs))
	for _, configID := range requestedCredentialConfigs {
		if config, ok := credentialIssuerMetadata.CredentialConfigurationsSupported[configID]; ok {
			if config.Format != openid4vci.CredentialFormatIdentifier_SdJwtVc {
				// We only support SD-JWT VCs for now
				continue
			}

			credentialInfoList = append(credentialInfoList, &irma.CredentialTypeInfo{
				CredentialFormat:         string(config.Format),
				VerifiableCredentialType: config.VerifiableCredentialType,
				Attributes:               convertToAttributeList(config.CredentialMetadata.Claims),
			})
		}
	}
	return credentialInfoList, nil
}

func convertToAttributeList(claims []openid4vci.ClaimsDescription) map[string]irma.TranslatedString {
	attrs := map[string]irma.TranslatedString{}
	for _, claim := range claims {
		for _, path := range claim.Path {
			if len(claim.Display) == 0 {
				attrs[path] = irma.NewTranslatedString(&path)
			} else {
				attrs[path] = convertDisplayToTranslatedString(claim.Display)
			}
		}
	}
	return attrs
}

func splitVct(vct string) (string, string, string, error) {
	components := strings.Split(vct, ".")
	if len(components) != 3 {
		return "", "", "", fmt.Errorf("credential type %q does not have exactly 3 components, separated by dots", vct)
	}
	return components[0], components[1], components[2], nil
}

func convertToRequestorInfo(credentialIssuerMetadata *openid4vci.CredentialIssuerMetadata) *irma.RequestorInfo {
	// TODO: we need to use the signed metadata here, so we can get the requestor data from our certificate (at least, everything that is missing in the metadata)
	// TODO: we need to know which language to use, in order to get the correct logo

	return &irma.RequestorInfo{
		//ID: credentialIssuerMetadata.CredentialIssuer,	//TODO: convert from Credential Issuer to ID
		Name:       convertDisplayToTranslatedString(credentialIssuerMetadata.Display),
		Languages:  credentialIssuerMetadata.GetAllBaseLanguages(),
		Wizards:    map[irma.IssueWizardIdentifier]*irma.IssueWizard{},
		Industry:   &irma.TranslatedString{},
		Unverified: true,
		Hostnames:  []string{credentialIssuerMetadata.CredentialIssuer},
		//Logo:       &filename,
		//LogoPath:   &path,
		//ValidUntil: (*irma.Timestamp)(&endEntityCert.NotAfter),
		//Description: credentialIssuerMetadata.Description,
	}
}
