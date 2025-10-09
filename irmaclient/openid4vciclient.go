package irmaclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
)

type OpenID4VciClient struct {
	issuerValidator eudi.VerifierValidator
	httpClient      *http.Client
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

		// TODO: validate the Credential Offer parameters
		credentialOffer, err := client.ValidateCredentialOffer(credentialOfferJson)

		handleFailure(handler, "openid4vci: failed to handle credential offer: %v", err)
		return
	}()
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

func (client *OpenID4VciClient) ValidateCredentialOffer(credentialOfferJson string) (*openid4vci.CredentialOffer, error) {
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
		return nil, fmt.Errorf("credential issuer URI is not HTTPS")
	}

	if parsedCredentialIssuerUri.RawQuery != "" || parsedCredentialIssuerUri.Fragment != "" {
		return nil, fmt.Errorf("credential issuer URI contains query or fragment, which is not allowed")
	}

	// Obtain Credential Issuer metadata
	credentialIssuerMetadataUrl := ConstructCredentialIssuerMetadataUrl(*parsedCredentialIssuerUri)
	credentialIssuerMetadata, err := client.GetAndVerifyCredentialIssuerMetadata(credentialIssuerMetadataUrl, &credentialOffer)

	// TODO: validate the Credential Offer against the Credential Issuer metadata

	return &credentialOffer, nil
}

func (client *OpenID4VciClient) GetAndVerifyCredentialIssuerMetadata(credentialIssuerMetadataUrl string, credentialOffer *openid4vci.CredentialOffer) (*openid4vci.CredentialIssuerMetadata, error) {
	req, err := http.NewRequest("GET", credentialIssuerMetadataUrl, nil)

	// Explicitly ask for JSON response, so we do not get signed JWT metadata response
	req.Header.Set("Accept", "application/json")

	// TODO: set Accept-Language as per user preference

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

	return &credentialIssuerMetadata, nil
}

func (client *OpenID4VciClient) Dismiss() {
	irma.Logger.Info("openid4vci: session dismissed")
}

func ConstructCredentialIssuerMetadataUrl(credentialIssuer url.URL) string {
	url := &url.URL{
		Scheme: credentialIssuer.Scheme,
		Host:   credentialIssuer.Host,
		Path:   path.Join("/.well-known/openid-credential-issuer", credentialIssuer.Path), // In case the Credential Issuer has multiple tenants, make sure to include the path
	}
	return url.String()
}
