package irmaclient

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/eudi/scheme"
)

type SdJwtVcStorageClient interface {
	VerifyAndStoreSdJwts(sdjwts []sdjwtvc.SdJwtVcKb, requestedCredentials []*irma.CredentialRequest) error
}

type OpenID4VciClient struct {
	eudiConf       *eudi.Configuration
	httpClient     *http.Client
	currentSession *openid4vciSession
	sdJwtVcStorage SdJwtVcStorage
	holderVerifier *sdjwtvc.HolderVerificationProcessor
	keyBinder      sdjwtvc.KeyBinder

	// Allow non-HTTPS for testing purposes
	allowInsecureHttp bool
}

func NewOpenID4VciClient(httpClient *http.Client,
	eudiConf *eudi.Configuration,
	sdJwtVcStorage SdJwtVcStorage,
	holderVerifier *sdjwtvc.HolderVerificationProcessor,
	keyBinder sdjwtvc.KeyBinder,
) *OpenID4VciClient {
	return &OpenID4VciClient{
		httpClient:     httpClient,
		eudiConf:       eudiConf,
		sdJwtVcStorage: sdJwtVcStorage,
		holderVerifier: holderVerifier,
		keyBinder:      keyBinder,
	}
}

func (client *OpenID4VciClient) AllowInsecureHttpForTesting() {
	client.allowInsecureHttp = true
}

func (client *OpenID4VciClient) NewSession(credentialOfferEndpointUrl string, handler Handler) SessionDismisser {
	client.handleSessionAsync(credentialOfferEndpointUrl, handler)
	return client
}

func (client *OpenID4VciClient) handleSessionAsync(credentialOfferEndpointUrl string, handler Handler) {
	go func() {
		credentialOfferJson, err := client.validateCredentialOfferEndpointAndObtainCredentialOfferParameters(credentialOfferEndpointUrl)

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

		// TODO: Validate the Credential Offer against the Yivi scheme ?

		// Everything looks in order; handle the session by starting the Authorization flow (e.g. show UI to user, obtain authorization, etc)
		err = client.handleCredentialOffer(credentialOffer, credentialIssuerMetadata, handler)

		if err != nil {
			handleFailure(handler, "openid4vci: failed to handle credential offer: %v", err)
		}
	}()
}

func (client *OpenID4VciClient) handleCredentialOffer(
	credentialOffer *openid4vci.CredentialOffer,
	credentialIssuerMetadata *openid4vci.CredentialIssuerMetadata,
	handler Handler,
) error {
	requestorInfo := convertToRequestorInfo(credentialIssuerMetadata)
	creds, err := convertToCredentialInfoList(credentialOffer.CredentialConfigurationIds, credentialIssuerMetadata, requestorInfo.Name)
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
		keyBinder:                client.keyBinder,
		// logsStorage:              client.logsStorage,
	}
	defer func() {
		client.currentSession = nil
	}()

	// For now; we only support requesting credentials based on the `scope` parameter

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

	if !client.allowInsecureHttp && parsedCredentialIssuerUri.Scheme != "https" {
		return nil, fmt.Errorf("credential issuer URI (%s) is not HTTPS", credentialOffer.CredentialIssuer)
	}

	if parsedCredentialIssuerUri.RawQuery != "" || parsedCredentialIssuerUri.Fragment != "" {
		return nil, fmt.Errorf("credential issuer URI contains query or fragment, which is not allowed")
	}

	// Validate that at least one Credential Configuration ID is present
	if len(credentialOffer.CredentialConfigurationIds) == 0 {
		return nil, fmt.Errorf("no credential_configuration_ids found in credential offer")
	}

	return &credentialOffer, nil
}

func (client *OpenID4VciClient) GetAndVerifyCredentialIssuerMetadata(credentialOffer *openid4vci.CredentialOffer) (*openid4vci.CredentialIssuerMetadata, error) {
	parsedCredentialIssuerUri, err := url.Parse(credentialOffer.CredentialIssuer)
	credentialIssuerMetadataUrl := constructCredentialIssuerMetadataUrl(*parsedCredentialIssuerUri)

	req, err := http.NewRequest("GET", credentialIssuerMetadataUrl, nil)

	irma.Logger.Infof("Fetching Credential Issuer metadata from %s", credentialIssuerMetadataUrl)

	// Explicitly ask for JSON response, so we do not get signed JWT metadata response
	req.Header.Set("Accept", "application/json")

	// TODO: set Accept-Language as per user/app preference

	response, err := client.httpClient.Do(req)

	// TODO: add caching of metadata response (Cache-Control and Expires headers) ?

	if err != nil {
		if err != nil {
			return nil, fmt.Errorf("failed to get credential issuer metadata from: %v", err)
		}
	}

	if response.StatusCode != http.StatusOK {
		// Retry on a different (non-compliant) well-known URL for Credential Issuer metadata
		irma.Logger.Infof("Fetching Credential Issuer metadata from %s", credentialOffer.CredentialIssuer+"/.well-known/openid-credential-issuer")
		response, err = client.httpClient.Get(credentialOffer.CredentialIssuer + "/.well-known/openid-credential-issuer")
		if err != nil {
			return nil, fmt.Errorf("failed to get credential issuer metadata: server returned status code %d", response.StatusCode)
		}
	}

	defer func() {
		err = response.Body.Close()
		if err != nil {
			irma.Logger.Warnf("failed to close credential issuer metadata response body: %v", err)
		}
	}()

	// TODO: handle charset in Content-Type header ?
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
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
	err = credentialIssuerMetadata.Verify()
	if err != nil {
		return nil, fmt.Errorf("failed to validate credential issuer metadata: %v", err)
	}

	// Validate the metadata against the Credential Offer
	err = credentialIssuerMetadata.ValidateAgainstCredentialOffer(credentialOffer)
	if err != nil {
		return nil, fmt.Errorf("failed to validate credential issuer metadata against credential offer: %v", err)
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

func (client *OpenID4VciClient) VerifyAndStoreSdJwts(sdjwts []sdjwtvc.SdJwtVcKb, requestedCredentials []*irma.CredentialRequest) error {
	return verifyAndStoreSdJwtVcKbs(sdjwts, client.sdJwtVcStorage, client.holderVerifier)
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

func getCredentialIssuerLogoFilenameWithoutExtension(credentialIssuer string, locale string) string {
	return fmt.Sprintf("%x_%s", sha256.Sum256([]byte(credentialIssuer)), locale)
}

func convertToCredentialInfoList(
	requestedCredentialConfigs []string,
	credentialIssuerMetadata *openid4vci.CredentialIssuerMetadata,
	issuerName irma.TranslatedString,
) ([]*irma.CredentialTypeInfo, error) {
	credentialInfoList := make([]*irma.CredentialTypeInfo, 0, len(requestedCredentialConfigs))
	for _, configID := range requestedCredentialConfigs {
		if config, ok := credentialIssuerMetadata.CredentialConfigurationsSupported[configID]; ok {
			if config.Format != openid4vci.CredentialFormatIdentifier_SdJwtVc {
				// We only support SD-JWT VCs for now
				continue
			}

			// Credential metadata is optional in the issuer metadata
			// TODO: we might be able to get it from the /.well-known/jwt-vc-issuer endpoint
			if config.CredentialMetadata == nil {
				return nil, nil
			}

			displays := ToTranslateableList(config.CredentialMetadata.Display)
			name := convertDisplayToTranslatedString(displays)

			credentialInfoList = append(credentialInfoList, &irma.CredentialTypeInfo{
				IssuerName:               issuerName,
				Name:                     name,
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
				displays := ToTranslateableList(claim.Display)
				attrs[path] = convertDisplayToTranslatedString(displays)
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
	displays := ToTranslateableList(credentialIssuerMetadata.Display)

	return &irma.RequestorInfo{
		//ID: credentialIssuerMetadata.CredentialIssuer,	//TODO: convert from Credential Issuer to ID
		Name:       convertDisplayToTranslatedString(displays),
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
