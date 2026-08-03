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
	"runtime/debug"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/trust"
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

	credentialService services.CredentialService

	// holderKeyBinder creates the holder binding keys and OpenID4VCI proofs of
	// possession during issuance. It is a required dependency (software or
	// WSCA-backed); see NewClient.
	holderKeyBinder HolderKeyBinder

	// currentLocale drives which translations are resolved into DTOs and
	// which logo is downloaded during issuance. Sessions snapshot it at flow
	// start, so a mid-flow locale change does not affect a running session.
	currentLocale *clientmodels.CurrentLocale

	// trustEvaluator ranks the issuer a session talks to. Each session pins one
	// view from it, for the same reason it pins the locale.
	trustEvaluator trust.Evaluator

	// Allow non-HTTPS for testing purposes
	allowInsecureHttp bool
}

// NewClient builds an OpenID4VCI client. holderKeyBinder is required: pass
// services.NewHolderBindingKeyService(config.Storage.Db()) for the default
// software, storage-backed binder, or a WSCA-backed implementation to keep the
// holder private key out of this process. trustEvaluator is required too: every
// session pins a trust view from it to rank the issuer it talks to.
func NewClient(httpClient *http.Client,
	config *eudi.Configuration,
	holderVerifier *sdjwtvc.HolderVerificationProcessor,
	credentialService services.CredentialService,
	holderKeyBinder HolderKeyBinder,
	currentLocale *clientmodels.CurrentLocale,
	trustEvaluator trust.Evaluator,
) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}
	if holderKeyBinder == nil {
		return nil, fmt.Errorf("holderKeyBinder cannot be nil")
	}
	if trustEvaluator == nil {
		return nil, fmt.Errorf("trustEvaluator cannot be nil")
	}
	return &Client{
		httpClient:        httpClient,
		Configuration:     config,
		holderVerifier:    holderVerifier,
		credentialService: credentialService,
		holderKeyBinder:   holderKeyBinder,
		currentLocale:     currentLocale,
		trustEvaluator:    trustEvaluator,
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
		// This goroutine is owned by irmago, so the app bridge's own recover
		// does not cover it: an unrecovered panic here aborts the whole host
		// process instead of ending the session. Turn it into a session failure.
		defer recoverSessionPanic(handler)

		// The locale is fixed for the whole flow. This goroutine spans several
		// network round trips (issuer metadata, VCT resolution, logo downloads);
		// re-reading the live locale at each step would let a SetLocale landing
		// in that window produce a half-translated permission screen, and a logo
		// downloaded for one locale but looked up for another. Read it once here
		// and thread it through — this is the only currentLocale read in the file.
		locale := client.currentLocale.Get()
		ctx := context.Background()

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

		// One pinned trust view for the whole flow, for the same reason the
		// locale is pinned above: what this session decided about the issuer
		// must not shift halfway through.
		trustView := client.trustEvaluator.Snapshot(ctx)

		// SD-JWT VC type metadata is the spec-preferred source for credential
		// display/claims (OID4VCI v1.0 § 12.2.4: format-specific mechanisms are
		// "always preferred" over credential_metadata). Snapshot the VCI
		// baseline before resolving so both the pre- and post-issuance merges
		// can fall back per-locale onto the original credential_metadata
		// instead of onto each other's outputs.
		baseline := snapshotCredentialMetadata(credentialIssuerMetadata)

		resolver := typemetadata.NewResolver(client.httpClient)
		client.resolveCredentialMetadataFromVct(ctx, credentialOffer, credentialIssuerMetadata, baseline, resolver)

		// After the VCT enrichment above, which can introduce logos (e.g. via
		// rendering.simple.logo) that weren't in the issuer document.
		client.downloadLogos(ctx, credentialOffer, credentialIssuerMetadata, locale)

		// Everything looks in order; handle the session by starting the Authorization flow (e.g. show UI to user, obtain authorization, etc)
		err = client.handleCredentialOffer(sessionId, credentialOffer, credentialIssuerMetadata, baseline, resolver, redirectUri, locale, trustView, handler)

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
	locale string,
	trustView trust.View,
	handler Handler,
) error {
	requestorInfo := client.convertToTrustedParty(credentialIssuerMetadata, locale, trustView)
	creds, err := client.convertToCredentialInfoList(credentialOffer.CredentialConfigurationIds, credentialIssuerMetadata, requestorInfo, locale)
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
		credentialService:          client.credentialService,
		vctResolver:                vctResolver,
		allowInsecureHttp:          client.allowInsecureHttp,
		originalCredentialMetadata: originalCredentialMetadata,
		locale:                     locale,
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

	// grants is OPTIONAL per OID4VCI v1.0 § 4.1.1, so an absent, null or empty
	// member is not a validation error: the grant type is then derived from the
	// authorization server metadata in configureIssuerSettings, which is the
	// first point where that metadata is available.

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

	return &credentialIssuerMetadata, nil
}

// Dismiss only logs: it does not stop the issuance it claims to stop, and reports
// no terminal state. client/session_handler.go's dismissal backstop reports
// Dismissed on its behalf, and finish there deliberately lets the later Success
// through, because issuance runs on and stores the credential regardless.
//
// TODO: actually cancel. Unlike openid4vp this cannot be one channel send — the
// session parks at three separate channels and spends long stretches in HTTP
// round trips, so it needs a context threaded through the grant handlers plus a
// decision on what a mid-flight dismissal does with credentials already fetched.
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
	issuer *clientmodels.TrustedParty,
	locale string,
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
			name := clientmodels.Resolve(metadata.ConvertDisplayToTranslatedString(displays), locale)

			credentialLogoManager := client.Configuration.Storage.FileSystem().Credentials().LogoManager()
			image := services.LoadResolvedLogo(credentialLogoManager,
				metadata.LogoURIsByLanguage(config.CredentialMetadata.Display), locale)

			result = append(result, &clientmodels.CredentialDescriptor{
				CredentialId: config.VerifiableCredentialType,
				Name:         name,
				Issuer: clientmodels.TrustedParty{
					Name:       issuer.Name,
					TrustLevel: issuer.TrustLevel,
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
		displays := metadata.ToTranslateableList(claim.Display)
		displayName := clientmodels.ResolvePtr(metadata.ConvertDisplayToTranslatedString(displays), locale)

		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   claim.Path,
			DisplayName: displayName,
		})
	}
	return attrs
}

func (client *Client) convertToTrustedParty(credentialIssuerMetadata *metadata.CredentialIssuerMetadata, locale string, trustView trust.View) *clientmodels.TrustedParty {
	// TODO: we need to use the signed metadata here, so we can get the requestor data from our certificate (at least, everything that is missing in the metadata)
	displays := metadata.ToTranslateableList(credentialIssuerMetadata.Display)

	// The issuer's own certificate is not surfaced by the holder verification
	// path yet, so the only evidence available here is its identifier and the
	// certificate channel has nothing to say: a `x5c`-identified issuer ranks
	// low along with everyone else until that lands.
	verdict := trustView.Issuer(trust.Evidence{
		Identifiers: []string{credentialIssuerMetadata.CredentialIssuer},
	})

	display := trust.PartyDisplay{
		Id: credentialIssuerMetadata.CredentialIssuer,
		// Credential-issuer metadata is served from the issuer's own well-known
		// endpoint over TLS, which says the issuer really published it — not
		// that anybody besides the issuer stands behind what it says. Until the
		// issuer's certificate is surfaced (#660), everything here is its own
		// word, logo included, and only the name of it reaches the user.
		SelfAssertedName: clientmodels.Resolve(metadata.ConvertDisplayToTranslatedString(displays), locale),
	}
	if verdict.Listing != nil {
		display.CuratedLogo = services.LoadCuratedLogo(
			context.Background(),
			client.Configuration.Storage.FileSystem().Issuers().LogoManager(),
			client.httpClient,
			verdict.Listing.LogoURI,
		)
	}

	return display.TrustedParty(verdict, locale)
}

func handleFailure(handler Handler, message string, fmtArgs ...any) {
	eudi.Logger.Errorf(message, fmtArgs...)
	handler.Failure(&clientmodels.SessionError{
		WrappedError: fmt.Sprintf(message, fmtArgs...),
	})
}

// recoverSessionPanic reports a panic on the session goroutine as a session
// failure. It has to be deferred from the goroutine's own function body, since
// recover only sees panics of the goroutine it runs on.
func recoverSessionPanic(handler Handler) {
	e := recover()
	if e == nil {
		return
	}

	stack := string(debug.Stack())
	eudi.Logger.Errorf("recovering from panic: %v\nstack trace:\n%v", e, stack)
	message := fmt.Sprintf("openid4vci session panicked: %v", e)
	handler.Failure(&clientmodels.SessionError{
		// Same shape the legacy irmaclient session uses for a recovered panic:
		// error type irma.ErrorPanic (the string "panic"), and the message
		// followed by the stack in Info (irma/irmaclient/session.go). Info is
		// filled as well as Stack so the app's panic screen shows the same detail
		// for both paths, whichever of the two fields it reads.
		ErrorType:    "panic",
		WrappedError: message,
		Info:         message + "\n\n" + stack,
		Stack:        stack,
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

// downloadLogos caches the issuer logo and, for each offered credential
// configuration, the credential logo that resolves for the given locale. Call
// it after resolveCredentialMetadataFromVct so VCT-derived logos (e.g. from
// rendering.simple.logo) are picked up too. Logos for other languages are
// fetched lazily by the backfill sweep when the locale changes.
func (client *Client) downloadLogos(
	ctx context.Context,
	offer *CredentialOffer,
	issuerMetadata *metadata.CredentialIssuerMetadata,
	locale string,
) {
	fs := client.Configuration.Storage.FileSystem()
	services.FetchLogoIfMissing(ctx, fs.Issuers().LogoManager(), client.httpClient,
		clientmodels.Resolve(metadata.LogoURIsByLanguage(issuerMetadata.Display), locale))

	for _, configID := range offer.CredentialConfigurationIds {
		config, ok := issuerMetadata.CredentialConfigurationsSupported[configID]
		if !ok || config.CredentialMetadata == nil {
			continue
		}
		services.FetchLogoIfMissing(ctx, fs.Credentials().LogoManager(), client.httpClient,
			clientmodels.Resolve(metadata.LogoURIsByLanguage(config.CredentialMetadata.Display), locale))
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
