package openid4vci

import (
	"context"
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
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
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

	// holderKeyBinder creates the holder binding keys and OpenID4VCI proofs of
	// possession during issuance. It is a required dependency (software or
	// WSCA-backed); see NewClient.
	holderKeyBinder HolderKeyBinder

	// currentLocale drives which translations are resolved into DTOs and
	// which logo is downloaded during issuance. Sessions snapshot it at flow
	// start, so a mid-flow locale change does not affect a running session.
	currentLocale *clientmodels.CurrentLocale

	// Allow non-HTTPS for testing purposes
	allowInsecureHttp bool
}

// NewClient builds an OpenID4VCI client. holderKeyBinder is required: pass
// services.NewHolderBindingKeyService(config.Storage.Db()) for the default
// software, storage-backed binder, or a WSCA-backed implementation to keep the
// holder private key out of this process.
func NewClient(httpClient *http.Client,
	config *eudi.Configuration,
	holderVerifier *sdjwtvc.HolderVerificationProcessor,
	holderKeyBinder HolderKeyBinder,
	currentLocale *clientmodels.CurrentLocale,
) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}
	if holderKeyBinder == nil {
		return nil, fmt.Errorf("holderKeyBinder cannot be nil")
	}
	if currentLocale == nil {
		currentLocale = clientmodels.NewCurrentLocale("")
	}

	return &Client{
		httpClient:      httpClient,
		Configuration:   config,
		holderVerifier:  holderVerifier,
		holderKeyBinder: holderKeyBinder,
		currentLocale:   currentLocale,
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
func (client *Client) NewSession(sessionId int, credentialOfferEndpointUrl string, redirectUri string, handler Handler) SessionDismisser {
	client.handleSessionAsync(sessionId, credentialOfferEndpointUrl, redirectUri, handler)
	return client
}

func (client *Client) handleSessionAsync(sessionId int, credentialOfferEndpointUrl string, redirectUri string, handler Handler) {
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

		// SD-JWT VC type metadata is the spec-preferred source for credential
		// display/claims (OID4VCI v1.0 § 12.2.4: format-specific mechanisms are
		// "always preferred" over credential_metadata). Snapshot the VCI
		// baseline before resolving so both the pre- and post-issuance merges
		// can fall back per-locale onto the original credential_metadata
		// instead of onto each other's outputs.
		baseline := snapshotCredentialMetadata(credentialIssuerMetadata)

		resolver := typemetadata.NewResolver(client.httpClient)
		client.resolveCredentialMetadataFromVct(context.Background(), credentialOffer, credentialIssuerMetadata, baseline, resolver)

		// Download credential logos now that CredentialMetadata is final — the
		// VCT enrichment above can introduce logos (e.g. via
		// rendering.simple.logo) that weren't present in the issuer document.
		client.downloadCredentialLogos(credentialOffer, credentialIssuerMetadata)

		// Everything looks in order; handle the session by starting the Authorization flow (e.g. show UI to user, obtain authorization, etc)
		err = client.handleCredentialOffer(sessionId, credentialOffer, credentialIssuerMetadata, baseline, resolver, redirectUri, handler)

		if err != nil {
			handleFailure(handler, "failed to handle credential offer: %v", err)
		}
	}()
}

func (client *Client) handleCredentialOffer(
	sessionId int,
	credentialOffer *CredentialOffer,
	credentialIssuerMetadata *metadata.CredentialIssuerMetadata,
	originalCredentialMetadata map[string]*metadata.CredentialMetadata,
	vctResolver *typemetadata.Resolver,
	redirectUri string,
	handler Handler,
) error {
	requestorInfo := client.convertToTrustedParty(credentialIssuerMetadata)
	creds, err := client.convertToCredentialInfoList(credentialOffer.CredentialConfigurationIds, credentialIssuerMetadata, requestorInfo.Name)
	if err != nil {
		return fmt.Errorf("failed to convert credential info list: %v", err)
	}

	client.currentSession = &session{
		id:                         sessionId,
		credentialOffer:            credentialOffer,
		credentialIssuerMetadata:   credentialIssuerMetadata,
		requestorInfo:              requestorInfo,
		credentials:                creds,
		handler:                    handler,
		httpClient:                 client.httpClient,
		holderVerifier:             client.holderVerifier,
		holderKeyBinder:            client.holderKeyBinder,
		storage:                    client.Configuration.Storage,
		vctResolver:                vctResolver,
		allowInsecureHttp:          client.allowInsecureHttp,
		originalCredentialMetadata: originalCredentialMetadata,
		locale:                     client.currentLocale.Get(),
		redirectUri:                redirectUri,
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

	// Valid metadata; download the issuer logo that resolves for the current
	// locale, if present and not already cached. Logos for other languages
	// are fetched lazily by the backfill sweep when the locale changes.
	issuerLogoManager := client.Configuration.Storage.FileSystem().Issuers().LogoManager()
	issuerLogoURI := clientmodels.Resolve(metadata.LogoURIsByLanguage(credentialIssuerMetadata.Display), client.currentLocale.Get())
	downloadLogoIfMissing(issuerLogoManager, client.httpClient, issuerLogoURI)

	return &credentialIssuerMetadata, nil
}

// downloadLogoIfMissing fetches and caches a logo unless the URI is empty or
// the logo is already cached.
func downloadLogoIfMissing(manager filesystem.LogoManager, httpClient *http.Client, uri string) {
	if uri == "" {
		return
	}
	if exists, err := manager.Exists(uri); err == nil && exists {
		return
	}
	logoData, _, err := helpers.DownloadRemoteImage(httpClient, uri)
	if err != nil {
		eudi.Logger.Warnf("failed to download logo from %q: %v", uri, err)
		return
	}
	if err := manager.Save(uri, logoData); err != nil {
		eudi.Logger.Warnf("failed to cache logo from %q: %v", uri, err)
	}
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
	issuerName string,
) ([]*clientmodels.CredentialDescriptor, error) {
	locale := client.currentLocale.Get()
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
			name := clientmodels.Resolve(metadata.ConvertDisplayToTranslatedString(displays), locale)

			credentialLogoManager := client.Configuration.Storage.FileSystem().Credentials().LogoManager()
			image := eudi.LoadLogoImage(credentialLogoManager,
				clientmodels.Resolve(metadata.LogoURIsByLanguage(config.CredentialMetadata.Display), locale))

			result = append(result, &clientmodels.CredentialDescriptor{
				CredentialId: config.VerifiableCredentialType,
				Name:         name,
				Issuer: clientmodels.TrustedParty{
					Name: issuerName,
				},
				Attributes: convertClaimsToAttributes(config.CredentialMetadata.Claims, locale),
				Image:      image,
			})
		}
	}
	return result, nil
}

func convertClaimsToAttributes(claims []metadata.ClaimsDescription, locale string) []clientmodels.Attribute {
	var attrs []clientmodels.Attribute
	for _, claim := range claims {
		var displayName *string
		if len(claim.Display) > 0 {
			displays := metadata.ToTranslateableList(claim.Display)
			if dn := clientmodels.Resolve(metadata.ConvertDisplayToTranslatedString(displays), locale); dn != "" {
				displayName = &dn
			}
		}

		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   claim.Path,
			DisplayName: displayName,
		})
	}
	return attrs
}

func (client *Client) convertToTrustedParty(credentialIssuerMetadata *metadata.CredentialIssuerMetadata) *clientmodels.TrustedParty {
	// TODO: we need to use the signed metadata here, so we can get the requestor data from our certificate (at least, everything that is missing in the metadata)
	locale := client.currentLocale.Get()
	displays := metadata.ToTranslateableList(credentialIssuerMetadata.Display)

	issuerLogoManager := client.Configuration.Storage.FileSystem().Issuers().LogoManager()
	issuerImage := eudi.LoadLogoImage(issuerLogoManager,
		clientmodels.Resolve(metadata.LogoURIsByLanguage(credentialIssuerMetadata.Display), locale))

	return &clientmodels.TrustedParty{
		Id:       credentialIssuerMetadata.CredentialIssuer,
		Name:     clientmodels.Resolve(metadata.ConvertDisplayToTranslatedString(displays), locale),
		Image:    issuerImage,
		Verified: false,
	}
}

func handleFailure(handler Handler, message string, fmtArgs ...any) {
	eudi.Logger.Errorf(message, fmtArgs...)
	handler.Failure(&clientmodels.SessionError{
		WrappedError: fmt.Sprintf(message, fmtArgs...),
	})
}

// snapshotCredentialMetadata captures the VCI-advertised
// credential_metadata pointer for each configuration so a later VCT
// merge can recover the pre-merge baseline. The values are pointer
// copies — VCT resolution replaces the live map entry's pointer with a
// new CredentialMetadata, leaving the snapshotted pointer untouched.
func snapshotCredentialMetadata(issuerMetadata *metadata.CredentialIssuerMetadata) map[string]*metadata.CredentialMetadata {
	snapshot := make(map[string]*metadata.CredentialMetadata, len(issuerMetadata.CredentialConfigurationsSupported))
	for configID, config := range issuerMetadata.CredentialConfigurationsSupported {
		snapshot[configID] = config.CredentialMetadata
	}
	return snapshot
}

// resolveCredentialMetadataFromVct fetches SD-JWT VC type metadata for each
// offered credential configuration whose vct value is an absolute HTTPS URL
// (or HTTP when allowInsecureHttp is set). On success, the config's
// CredentialMetadata is replaced with Merge(resolved, baseline[configID]) —
// VCT translations win per OID4VCI v1.0 § 12.2.4 while VCI fills the
// locales VCT does not cover. On any failure (URL not fetchable, network
// error, parse error, extends cycle, extends-integrity mismatch, depth
// overflow), the existing CredentialMetadata is left as-is so consumers
// fall back to the issuer metadata's credential_metadata.
func (client *Client) resolveCredentialMetadataFromVct(
	ctx context.Context,
	offer *CredentialOffer,
	issuerMetadata *metadata.CredentialIssuerMetadata,
	baseline map[string]*metadata.CredentialMetadata,
	resolver *typemetadata.Resolver,
) {
	for _, configID := range offer.CredentialConfigurationIds {
		config, ok := issuerMetadata.CredentialConfigurationsSupported[configID]
		if !ok {
			continue
		}
		if config.Format != metadata.CredentialFormatIdentifier_SdJwtVc &&
			config.Format != metadata.CredentialFormatIdentifier_SdJwtVc_Legacy {
			continue
		}
		// vct can legally be a non-URL string identifier; if so, there's
		// nothing to fetch — silently leave CredentialMetadata alone.
		if !vctLooksFetchable(config.VerifiableCredentialType, client.allowInsecureHttp) {
			continue
		}

		resolved, err := resolver.Resolve(ctx, config.VerifiableCredentialType, client.allowInsecureHttp)
		if err != nil {
			eudi.Logger.Infof("vct type metadata resolution failed for %q (vct=%q): %v; falling back to credential_metadata", configID, config.VerifiableCredentialType, err)
			continue
		}

		merged := Merge(resolved, baseline[configID])
		config.CredentialMetadata = &merged
		issuerMetadata.CredentialConfigurationsSupported[configID] = config
	}
}

// downloadCredentialLogos caches, for each offered credential configuration,
// the logo that resolves for the current locale. Called after
// resolveCredentialMetadataFromVct so VCT-derived logos (e.g. from
// rendering.simple.logo) are picked up too. Logos for other languages are
// fetched lazily by the backfill sweep when the locale changes.
func (client *Client) downloadCredentialLogos(
	offer *CredentialOffer,
	issuerMetadata *metadata.CredentialIssuerMetadata,
) {
	credentialLogoManager := client.Configuration.Storage.FileSystem().Credentials().LogoManager()
	locale := client.currentLocale.Get()
	for _, configID := range offer.CredentialConfigurationIds {
		config, ok := issuerMetadata.CredentialConfigurationsSupported[configID]
		if !ok || config.CredentialMetadata == nil {
			continue
		}
		uri := clientmodels.Resolve(metadata.LogoURIsByLanguage(config.CredentialMetadata.Display), locale)
		downloadLogoIfMissing(credentialLogoManager, client.httpClient, uri)
	}
}

// vctLooksFetchable returns true if vct uses a scheme this wallet will attempt
// to fetch. Avoids spurious Resolve() error logs for non-URL vct identifiers.
func vctLooksFetchable(vct string, allowInsecureHttp bool) bool {
	if strings.HasPrefix(vct, "https://") {
		return true
	}
	if allowInsecureHttp && strings.HasPrefix(vct, "http://") {
		return true
	}
	return false
}
