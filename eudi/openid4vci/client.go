package openid4vci

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/metadata"
)

// SdJwtVcStorageClient is the interface that the openid4vci client requires for
// verifying and storing SD-JWT VCs. Implementations are provided by the outer client layer.
type SdJwtVcStorageClient interface {
	VerifyAndStoreSdJwts(sdjwts []sdjwtvc.SdJwtVcKb, validateUniqueKeyBindingConfirmations bool) error
}

type Client struct {
	Configuration  *eudi.Configuration
	httpClient     *http.Client
	currentSession *session
	holderVerifier *sdjwtvc.HolderVerificationProcessor

	// Allow non-HTTPS for testing purposes
	allowInsecureHttp bool
}

func NewClient(httpClient *http.Client,
	config *eudi.Configuration,
	holderVerifier *sdjwtvc.HolderVerificationProcessor,
) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	return &Client{
		httpClient:     httpClient,
		Configuration:  config,
		holderVerifier: holderVerifier,
	}, nil
}

func (client *Client) AllowInsecureHttpForTesting() {
	client.allowInsecureHttp = true
	client.holderVerifier.SetAllowInsecureDidWeb(true)
}

// NewSession starts an OpenID4VCI issuance session. `redirectUri` is the OAuth
// `redirect_uri` value the wallet will send to the issuer's authorization
// server in both the authorize request (auth-code flow) and the token request
// (both auth-code and pre-authorized-code flows). The mobile wallet derives it
// from the host of the inbound universal link that started the session, so
// staging-host offers result in staging-host callbacks.
func (client *Client) NewSession(credentialOfferEndpointUrl string, redirectUri string, handler Handler) SessionDismisser {
	client.handleSessionAsync(credentialOfferEndpointUrl, redirectUri, handler)
	return client
}

func (client *Client) handleSessionAsync(credentialOfferEndpointUrl string, redirectUri string, handler Handler) {
	go func() {
		credentialOfferJson, err := client.validateCredentialOfferEndpointAndObtainCredentialOfferParameters(credentialOfferEndpointUrl)
		if err != nil {
			handleFailure(handler, "%s", err.Error())
			return
		}

		// Validate the Credential Offer parameters
		credentialOffer, err := client.ParseAndValidateCredentialOffer(credentialOfferJson)
		if err != nil {
			handleFailure(handler, "failed to parse and validate credential offer: %v", err)
			return
		}

		// Obtain Credential Issuer metadata
		credentialIssuerMetadata, err := client.GetAndVerifyCredentialIssuerMetadata(credentialOffer)
		if err != nil {
			handleFailure(handler, "failed to get and verify credential issuer metadata: %v", err)
			return
		}

		// Everything looks in order; handle the session by starting the Authorization flow (e.g. show UI to user, obtain authorization, etc)
		err = client.handleCredentialOffer(credentialOffer, credentialIssuerMetadata, redirectUri, handler)

		if err != nil {
			handleFailure(handler, "failed to handle credential offer: %v", err)
		}
	}()
}

func (client *Client) handleCredentialOffer(
	credentialOffer *CredentialOffer,
	credentialIssuerMetadata *metadata.CredentialIssuerMetadata,
	redirectUri string,
	handler Handler,
) error {
	requestorInfo := convertToTrustedParty(credentialIssuerMetadata)
	creds, err := client.convertToCredentialInfoList(credentialOffer.CredentialConfigurationIds, credentialIssuerMetadata, requestorInfo.Name)
	if err != nil {
		return fmt.Errorf("failed to convert credential info list: %v", err)
	}

	client.currentSession = &session{
		credentialOffer:          credentialOffer,
		credentialIssuerMetadata: credentialIssuerMetadata,
		requestorInfo:            requestorInfo,
		credentials:              creds,
		handler:                  handler,
		httpClient:               client.httpClient,
		holderVerifier:           client.holderVerifier,
		storage:                  client.Configuration.Storage,
		redirectUri:              redirectUri,
		// logsStorage:              client.logsStorage,
	}
	defer func() {
		client.currentSession = nil
	}()

	client.currentSession.perform()
	return nil
}

func (client *Client) validateCredentialOfferEndpointAndObtainCredentialOfferParameters(credentialEndpointUrl string) (string, error) {
	parsedUrl, err := url.Parse(credentialEndpointUrl)
	if err != nil {
		return "", fmt.Errorf("failed to parse credential endpoint URI: %v", err)
	}

	// Find out if the Credential Offer is a URI pointing to the Offer parameters (in case of larger payloads), or the parameters itself
	credentialOffer := parsedUrl.Query().Get("credential_offer")
	credentialOfferUri := parsedUrl.Query().Get("credential_offer_uri")

	if credentialOffer == "" && credentialOfferUri == "" {
		return "", fmt.Errorf("no credential_offer or credential_offer_uri parameter found in credential offer")
	} else if credentialOffer != "" && credentialOfferUri != "" {
		return "", fmt.Errorf("both credential_offer and credential_offer_uri parameters found in credential offer, only one is allowed")
	} else if credentialOfferUri != "" {
		// Perform HTTP GET on the URI to obtain the Credential Offer parameters
		response, err := client.httpClient.Get(credentialOfferUri)
		if err != nil {
			return "", fmt.Errorf("failed to get credential offer from URI: %v", err)
		}
		defer func() {
			if closeErr := response.Body.Close(); closeErr != nil {
				eudi.Logger.Warnf("failed to close credential offer response body: %v", closeErr)
			}
		}()

		if response.StatusCode != http.StatusOK {
			return "", errors.New("credential offer not found or expired")
		}

		credentialOfferBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read credential offer response body: %v", err)
		}
		credentialOffer = string(credentialOfferBytes)
	}

	return credentialOffer, nil
}

func (client *Client) ParseAndValidateCredentialOffer(credentialOfferJson string) (*CredentialOffer, error) {
	var credentialOffer CredentialOffer
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

	// Validate all requested Credential Configuration IDs are unique
	if !metadata.IsUniqueStrings(credentialOffer.CredentialConfigurationIds, true) {
		return nil, fmt.Errorf("credential_configuration_ids in credential offer are not unique")
	}

	return &credentialOffer, nil
}

func (client *Client) GetAndVerifyCredentialIssuerMetadata(credentialOffer *CredentialOffer) (*metadata.CredentialIssuerMetadata, error) {
	parsedCredentialIssuerUri, err := url.Parse(credentialOffer.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential issuer URI: %v", err)
	}

	credentialIssuerMetadataUrl := constructCredentialIssuerMetadataUrl(*parsedCredentialIssuerUri)

	req, err := http.NewRequest("GET", credentialIssuerMetadataUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for credential issuer metadata: %v", err)
	}

	eudi.Logger.Infof("Fetching Credential Issuer metadata from %s", credentialIssuerMetadataUrl)

	// Explicitly ask for JSON response, so we do not get signed JWT metadata response
	req.Header.Set("Accept", "application/json")

	// TODO: set Accept-Language as per user/app preference

	response, err := client.httpClient.Do(req)

	// TODO: add caching of metadata response (Cache-Control and Expires headers) ?
	if err != nil {
		return nil, fmt.Errorf("failed to get credential issuer metadata from: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		// Retry on a different (non-compliant) well-known URL for Credential Issuer metadata
		eudi.Logger.Infof("Fetching Credential Issuer metadata from %s", credentialOffer.CredentialIssuer+"/.well-known/openid-credential-issuer")
		response, err = client.httpClient.Get(credentialOffer.CredentialIssuer + "/.well-known/openid-credential-issuer")
		if err != nil {
			return nil, fmt.Errorf("failed to get credential issuer metadata: server returned status code %d", response.StatusCode)
		}
	}

	// TODO: handle charset in Content-Type header ?
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		return nil, fmt.Errorf("failed to get credential issuer metadata: server returned unexpected Content-Type %s", response.Header.Get("Content-Type"))
	}

	credentialIssuerMetadataBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential issuer metadata response body: %v", err)
	}

	var credentialIssuerMetadata metadata.CredentialIssuerMetadata
	err = json.Unmarshal(credentialIssuerMetadataBytes, &credentialIssuerMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential issuer metadata: %v", err)
	}

	// Validate the Credential Issuer metadata against the spec
	validator := CredentialIssuerMetadataValidator{}
	err = validator.Verify(credentialIssuerMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to validate credential issuer metadata: %v", err)
	}

	// Validate the metadata against the offered credentials in the Credential Offer
	// This way, any unsupported credential configurations will be filtered and don't raise a validation error
	err = validator.ValidateAgainstCredentialOffer(&credentialIssuerMetadata, credentialOffer)
	if err != nil {
		return nil, fmt.Errorf("failed to validate credential issuer metadata against credential offer: %v", err)
	}

	// TODO: parallelize the download of logos for the Credential Issuer and the offered credentials

	// Valid metadata; download any issuer logos, if present
	// TODO: check which language we are using first, so we have to download only one logo (if it is not already cached), or..
	// TODO: initiate parallel downloads of logos; but check for unique URLs first
	issuerLogoManager := client.Configuration.Storage.FileSystem().Issuers().LogoManager()
	for _, display := range credentialIssuerMetadata.Display {
		if display.Logo != nil {
			// TODO: check if logo is already in cache first
			logoData, _, err := client.downloadRemoteImage(*display.Logo)
			if err != nil {
				eudi.Logger.Warnf("failed to download issuer logo from %q: %v", display.Logo.Uri, err)
				continue
			}
			err = issuerLogoManager.Save(display.Logo.Uri, logoData)

			if err != nil {
				eudi.Logger.Warnf("failed to cache issuer logo from %q: %v", display.Logo.Uri, err)
			}

			break

			// TODO: how to handle this error ? Proceed without logo ?
			// if err != nil {
			// 	// handleFailure(handler, "openid4vp: failed to store verifier logo: %v", err)
			// 	// return
			// }
		}
	}

	// Also download the logos for the offered credentials, if present in the metadata
	credentialLogoManager := client.Configuration.Storage.FileSystem().Credentials().LogoManager()
	for _, offeredConfiguration := range credentialOffer.CredentialConfigurationIds {
		if config, ok := credentialIssuerMetadata.CredentialConfigurationsSupported[offeredConfiguration]; ok {
			if config.CredentialMetadata != nil {
				for _, display := range config.CredentialMetadata.Display {
					if display.Logo != nil {
						// TODO: check if logo is already in cache first
						logoData, _, err := client.downloadRemoteImage(*display.Logo)
						if err != nil {
							eudi.Logger.Warnf("failed to download credential logo from %q: %v", display.Logo.Uri, err)
							continue
						}
						err = credentialLogoManager.Save(display.Logo.Uri, logoData)
						if err != nil {
							eudi.Logger.Warnf("failed to cache credential logo from %q: %v", display.Logo.Uri, err)
						}

						break

						// TODO: how to handle this error ? Proceed without logo ?
						// if err != nil {
						// 	// handleFailure(handler, "openid4vp: failed to store verifier logo: %v", err)
						// 	// return
						// }
					}
				}
			}
		}
	}

	return &credentialIssuerMetadata, nil
}

func (client *Client) downloadRemoteImage(remoteImage metadata.RemoteImage) ([]byte, string, error) {
	// data URIs (e.g. "data:image/png;base64,...") carry the image inline — no HTTP request needed.
	if strings.HasPrefix(remoteImage.Uri, "data:") {
		// Expected format: data:<mediatype>[;base64],<data>
		rest := remoteImage.Uri[len("data:"):]
		commaIdx := strings.IndexByte(rest, ',')
		if commaIdx < 0 {
			return nil, "", fmt.Errorf("invalid data URI: missing comma in %q", remoteImage.Uri)
		}
		meta := rest[:commaIdx]
		payload := rest[commaIdx+1:]
		var imageBytes []byte
		if strings.HasSuffix(meta, ";base64") {
			decoded, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return nil, "", fmt.Errorf("invalid data URI: base64 decode failed: %v", err)
			}
			imageBytes = decoded
		} else {
			imageBytes = []byte(payload)
		}
		mediaType := strings.TrimSuffix(meta, ";base64")
		return imageBytes, mediaType, nil
	}

	response, err := client.httpClient.Get(remoteImage.Uri)
	if err != nil {
		return nil, "", fmt.Errorf("failed to download image %s: %v", remoteImage.Uri, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf(
			"failed to download logo %s: server returned status code %d",
			remoteImage.Uri,
			response.StatusCode,
		)
	}

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read logo %s: %v", remoteImage.Uri, err)
	}

	return bytes, response.Header.Get("Content-Type"), nil
}

func (client *Client) Dismiss() {
	eudi.Logger.Info("openid4vci: session dismissed")
}

func constructCredentialIssuerMetadataUrl(credentialIssuer url.URL) string {
	url := &url.URL{
		Scheme: credentialIssuer.Scheme,
		Host:   credentialIssuer.Host,
		Path:   path.Join("/.well-known/openid-credential-issuer", credentialIssuer.Path), // In case the Credential Issuer has multiple tenants, make sure to include the path
	}
	return url.String()
}

func (client *Client) convertToCredentialInfoList(
	requestedCredentialConfigs []string,
	credentialIssuerMetadata *metadata.CredentialIssuerMetadata,
	issuerName clientmodels.TranslatedString,
) ([]*clientmodels.CredentialDescriptor, error) {
	result := make([]*clientmodels.CredentialDescriptor, 0, len(requestedCredentialConfigs))
	for _, configID := range requestedCredentialConfigs {
		if config, ok := credentialIssuerMetadata.CredentialConfigurationsSupported[configID]; ok {
			if config.Format != metadata.CredentialFormatIdentifier_SdJwtVc {
				// We only support SD-JWT VCs for now
				continue
			}

			// Credential metadata is optional in the issuer metadata
			// TODO: we might be able to get it from the /.well-known/jwt-vc-issuer endpoint
			if config.CredentialMetadata == nil {
				return nil, nil
			}

			displays := metadata.ToTranslateableList(config.CredentialMetadata.Display)
			name := metadata.ConvertDisplayToTranslatedString(displays)
			var image *clientmodels.Image

			credentialLogoManager := client.Configuration.Storage.FileSystem().Credentials().LogoManager()
			for _, display := range config.CredentialMetadata.Display {
				if display.Logo != nil {
					image = eudi.LoadLogoImage(credentialLogoManager, display.Logo.Uri)
					// TODO: for now, we pick the first logo in a display we can find, but this needs to be based on the locale being used in the app
					break
				}
			}

			result = append(result, &clientmodels.CredentialDescriptor{
				CredentialId: config.VerifiableCredentialType,
				Name:         name,
				Issuer: clientmodels.TrustedParty{
					Name: issuerName,
				},
				Attributes: convertClaimsToAttributes(config.CredentialMetadata.Claims),
				Image:      image,
			})
		}
	}
	return result, nil
}

func convertClaimsToAttributes(claims []metadata.ClaimsDescription) []clientmodels.Attribute {
	var attrs []clientmodels.Attribute
	for _, claim := range claims {
		var displayName *clientmodels.TranslatedString
		if len(claim.Display) > 0 {
			displays := metadata.ToTranslateableList(claim.Display)
			dn := metadata.ConvertDisplayToTranslatedString(displays)
			displayName = &dn
		}

		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   claim.Path,
			DisplayName: displayName,
		})
	}
	return attrs
}

func convertToTrustedParty(credentialIssuerMetadata *metadata.CredentialIssuerMetadata) *clientmodels.TrustedParty {
	// TODO: we need to use the signed metadata here, so we can get the requestor data from our certificate (at least, everything that is missing in the metadata)
	// TODO: we need to know which language to use, in order to get the correct logo
	displays := metadata.ToTranslateableList(credentialIssuerMetadata.Display)

	return &clientmodels.TrustedParty{
		Name:     metadata.ConvertDisplayToTranslatedString(displays),
		Verified: false,
	}
}

func handleFailure(handler Handler, message string, fmtArgs ...any) {
	eudi.Logger.Errorf(message, fmtArgs...)
	handler.Failure(&clientmodels.SessionError{
		WrappedError: fmt.Sprintf(message, fmtArgs...),
	})
}
