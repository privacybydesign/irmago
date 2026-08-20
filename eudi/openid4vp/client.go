package openid4vp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/internal/common"
)

// Handler is the callback interface for the OpenID4VP client session lifecycle.
type Handler interface {
	Failure(err *clientmodels.SessionError)
	Cancelled()
	Success(result string, credentialLogs []clientmodels.LogCredential)
	// DeliverDcApiResponse hands the Authorization Response back to the platform
	// that delivered the request through the Digital Credentials API. It is only
	// called for sessions started with NewDcApiSession, and always before Success.
	DeliverDcApiResponse(response string)
	RequestVerificationPermission(
		disclosurePlan *clientmodels.DisclosurePlan,
		requestor *clientmodels.TrustedParty,
		hashToQueryId map[string]string,
		callback PermissionHandler,
	)
}

// PermissionHandler is the callback the UI invokes after the user grants or denies permission.
type PermissionHandler func(proceed bool, selections []dcql.DisclosureSelection)

// SessionDismisser allows dismissing the session it was obtained for.
type SessionDismisser interface {
	Dismiss()
}

// ========================================================================

// Client drives OpenID4VP disclosure sessions.
type Client struct {
	Configuration     *eudi.Configuration
	dcqlHandler       *dcql.DcqlHandler
	verifierValidator VerifierValidator
	currentLocale     *clientmodels.CurrentLocale
	trustEvaluator    trust.Evaluator

	// Sessions currently performing, each on its own goroutine. Sessions may
	// overlap: a second disclosure can arrive while one is parked awaiting
	// permission, so a single pointer would misroute answers between them.
	// Registered/deregistered by the session goroutines, read by
	// RefreshPendingPermissionRequest on its caller's goroutine.
	mu       sync.Mutex
	sessions map[*openid4vpSession]struct{}
}

// RefreshPendingPermissionRequest re-asks every awaiting session for permission with
// a freshly built plan, so issuance-during-disclosure re-shows a plan containing the
// obtained credential. Called on every completed IRMA session (see
// IrmaClient.SetOnSessionDoneCallback), hence silent unless someone is actually
// parked waiting for an answer.
func (client *Client) RefreshPendingPermissionRequest() {
	client.mu.Lock()
	sessions := make([]*openid4vpSession, 0, len(client.sessions))
	for session := range client.sessions {
		sessions = append(sessions, session)
	}
	client.mu.Unlock()

	for _, session := range sessions {
		if session.awaiting.Load() {
			session.requestPermission()
		}
	}
}

func (client *Client) register(session *openid4vpSession) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.sessions == nil {
		client.sessions = map[*openid4vpSession]struct{}{}
	}
	client.sessions[session] = struct{}{}
}

func (client *Client) deregister(session *openid4vpSession) {
	client.mu.Lock()
	defer client.mu.Unlock()
	delete(client.sessions, session)
}

// NewClient creates a new OpenID4VP client. trustEvaluator must not be nil:
// every session pins a trust view from it to rank the verifier it talks to.
func NewClient(
	eudiConf *eudi.Configuration,
	handlers []dcql.DcqlCredentialQueryHandler,
	verifierValidator VerifierValidator,
	currentLocale *clientmodels.CurrentLocale,
	trustEvaluator trust.Evaluator,
) (*Client, error) {
	// The session path dereferences it without a guard, so a nil one would panic
	// on a goroutine no caller can recover from. Fail here instead.
	if trustEvaluator == nil {
		return nil, fmt.Errorf("trustEvaluator cannot be nil")
	}
	return &Client{
		Configuration:     eudiConf,
		dcqlHandler:       dcql.NewDcqlHandler(handlers),
		verifierValidator: verifierValidator,
		currentLocale:     currentLocale,
		trustEvaluator:    trustEvaluator,
	}, nil
}

// NewSession starts a new OpenID4VP session from the given URL and returns a
// SessionDismisser bound to that session. Sessions may overlap, and each dismisser
// dismisses only its own session, so dismissing one never cancels another.
func (client *Client) NewSession(fullUrl string, handler Handler) SessionDismisser {
	session := client.newSession(handler)
	client.handleSessionAsync(fullUrl, session)
	return session
}

// NewDcApiSession starts a new OpenID4VP session from a request the platform
// delivered through the W3C Digital Credentials API, and returns a
// SessionDismisser bound to that session. The Authorization Response is handed
// back to the platform via Handler.DeliverDcApiResponse instead of being
// transmitted by the wallet.
func (client *Client) NewDcApiSession(request *DcApiRequest, handler Handler) SessionDismisser {
	session := client.newSession(handler)
	client.handleDcApiSessionAsync(request, session)
	return session
}

func (client *Client) newSession(handler Handler) *openid4vpSession {
	return &openid4vpSession{
		handler:     handler,
		dcqlHandler: client.dcqlHandler,
		answers:     make(chan *permissionResponse, 1),
	}
}

func handleFailure(handler Handler, message string, fmtArgs ...any) {
	eudi.Logger.Errorf(message, fmtArgs...)
	handler.Failure(&clientmodels.SessionError{
		WrappedError: fmt.Sprintf(message, fmtArgs...),
	})
}

// verifierIdentifiers turns a client_id into the identifiers a recognized list
// keys entries on, most specific first. A client_id is prefixed with how the
// verifier authenticates, so a DID one contributes the bare DID: a list entry
// names the party, not the wallet's protocol. The full client_id is carried
// alongside for entries keyed on whatever else a prefix may introduce.
func verifierIdentifiers(clientId string) []string {
	if did, found := strings.CutPrefix(clientId, string(ClientIdentifierPrefix_DecentralizedDid)); found && did != "" {
		return []string{did, clientId}
	}
	return []string{clientId}
}

// isDidClientId reports whether the client_id identifies the verifier by a DID. A
// DID party keeps its DID as its displayed identifier even once a certificate
// attests its key.
func isDidClientId(clientId string) bool {
	return strings.HasPrefix(clientId, string(ClientIdentifierPrefix_DecentralizedDid))
}

// handleVerificationFailure ends the session with the code that fits what went
// wrong: a rejection by the identity gate tells the app the verifier itself was
// not trustworthy, anything else is a generic failure. Both entry points report
// through it.
func handleVerificationFailure(handler Handler, err error) {
	message := fmt.Sprintf("openid4vp: %v", err)
	eudi.Logger.Errorf("%s", message)
	handler.Failure(&clientmodels.SessionError{
		ErrorType:    eudi.SessionErrorType(err),
		WrappedError: message,
	})
}

func (client *Client) handleSessionAsync(fullUrl string, session *openid4vpSession) {
	go func() {
		handler := session.handler
		parsedUrl, err := url.Parse(fullUrl)

		if err != nil {
			handleFailure(handler, "openid4vp: failed to parse request: %v", err)
			return
		}

		requestUri := parsedUrl.Query().Get("request_uri")
		if requestUri == "" {
			handleFailure(handler, "openid4vp: request missing required request_uri")
			return
		}

		eudi.Logger.Infof("starting openid4vp session: %v", requestUri)
		response, err := common.HTTPClient.Get(requestUri)
		if err != nil {
			handleFailure(handler, "openid4vp: failed to get authorization request: %v", err)
			return
		}

		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			handleFailure(handler, "openid4vp: authorization request returned HTTP %d", response.StatusCode)
			return
		}

		authRequestJwt, err := io.ReadAll(response.Body)
		if err != nil {
			handleFailure(handler, "openid4vp: failed to read authorization request body: %v", err)
			return
		}

		request, requestor, err := client.verifySignedAuthorizationRequest(string(authRequestJwt))
		if err != nil {
			handleVerificationFailure(handler, err)
			return
		}

		if err := validateNonce(request.Nonce); err != nil {
			handleFailure(handler, "openid4vp: invalid authorization request: %v", err)
			return
		}

		// A session started from a URL has no platform to hand the response to, so the
		// DC API response modes cannot be honoured here. Rejecting them keeps the
		// response-delivery branch in perform() out of reach from this entry point:
		// without this check the session would report success while nothing had been
		// transmitted to the verifier.
		if isDcApiResponseMode(request.ResponseMode) {
			handleFailure(handler, "openid4vp: response_mode %s is only valid for a session started over the digital credentials api", request.ResponseMode)
			return
		}

		// Without the DC API the response is bound to the client identifier.
		err = client.handleAuthorizationRequest(session, request, requestor, request.ClientId)

		if err != nil {
			handleFailure(handler, "openid4vp: failed to handle authorization request: %v", err)
		}
	}()
}

func (client *Client) handleDcApiSessionAsync(request *DcApiRequest, session *openid4vpSession) {
	go func() {
		handler := session.handler
		authRequest, requestor, err := client.parseDcApiRequest(request)
		if err != nil {
			handleVerificationFailure(handler, err)
			return
		}

		eudi.Logger.Infof("dc api auth request: %#v", authRequest)

		// Over the DC API the response is bound to the origin the platform
		// authenticated, never to the client identifier (Appendix A.4).
		err = client.handleAuthorizationRequest(session, authRequest, requestor, OriginAudience(request.Origin))

		if err != nil {
			handleFailure(handler, "openid4vp: failed to handle authorization request: %v", err)
		}
	}()
}

// verifySignedAuthorizationRequest runs a signed authorization request JWT past
// the identity gate, ranks the verifier behind it, caches its logo, and builds the
// party to show to the user. Both entry points compose through it. A gate
// rejection is returned marked, so the caller can report it as a party validation
// failure.
func (client *Client) verifySignedAuthorizationRequest(authRequestJwt string) (
	*AuthorizationRequest,
	*clientmodels.TrustedParty,
	error,
) {
	request, verifiedRequestor, err := client.verifierValidator.
		ParseAndVerifyAuthorizationRequest(authRequestJwt)

	if err != nil {
		// The wallet does not know who it is talking to, and the app has to be
		// able to say so rather than show a generic error.
		return nil, nil, eudi.PartyValidationFailed(fmt.Errorf("failed to verify authorization request: %v", err))
	}

	// Only an attested logo is ever cached: a logo is believed rather than judged,
	// so nothing the party asserts about itself may supply one.
	if logoManager := client.verifierLogoManager(); logoManager != nil &&
		verifiedRequestor.Attested != nil && verifiedRequestor.Attested.Organization.Logo != nil {
		err = logoManager.Save(
			verifiedRequestor.Certificate.SerialNumber.String(),
			verifiedRequestor.Attested.Organization.Logo.Data,
			verifiedRequestor.Attested.Organization.Logo.MimeType,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to store verifier logo: %v", err)
		}
	}

	// One pinned view for the whole session, so a list refresh landing mid-session
	// cannot change what it decided about the verifier.
	verdict := client.trustEvaluator.Snapshot().Verifier(trust.Evidence{
		Certificate: verifiedRequestor.Certificate,
		Identifiers: verifierIdentifiers(request.ClientId),
	})

	return request, client.composeRequestor(verdict, verifiedRequestor, request.ClientId), nil
}

// composeRequestor reduces what the wallet knows about the verifier to the party
// the app renders, in display precedence: the curated list entry first, what an
// anchored certificate attests second, what the verifier says about itself last.
// The validator hands the attested and self-asserted accounts over separately, so
// an unanchored certificate's contents render under the warn state like any other
// self-asserted name.
func (client *Client) composeRequestor(
	verdict trust.Verdict,
	requestor *VerifiedRequestor,
	clientId string,
) *clientmodels.TrustedParty {
	locale := client.currentLocale.Get()

	var display trust.PartyDisplay
	if requestor.Attested != nil {
		display.Attested = trust.PartyMetadata{
			Name: clientmodels.Resolve(clientmodels.TranslatedString(requestor.Attested.Organization.LegalName), locale),
			Logo: logoImage(requestor.Attested.Organization.Logo),
		}
	}

	// A party is known by the most stable identifier in its own protocol: a DID
	// party by its DID, even once a certificate attests its key; an attested
	// certificate-only party by the serial number, the one identity document it
	// cannot have written itself; and an unattested one by the party half of its
	// client_id.
	display.Id = verifierIdentifiers(clientId)[0]
	if requestor.Attested != nil && !isDidClientId(clientId) {
		display.Id = requestor.Certificate.SerialNumber.String()
	}
	display.SelfAssertedName = requestor.SelfAssertedName

	display.CuratedLogo = services.LoadCuratedLogo(
		context.Background(),
		client.verifierLogoManager(),
		common.HTTPClient,
		verdict.CuratedLogoURI(),
	)

	return display.TrustedParty(verdict, locale)
}

// verifierLogoManager is the wallet's verifier logo cache, or nil when the client
// was built without storage, which leaves a party without its logo.
func (client *Client) verifierLogoManager() filesystem.LogoManager {
	if client.Configuration == nil || client.Configuration.Storage == nil {
		return nil
	}
	return client.Configuration.Storage.FileSystem().Verifiers().LogoManager()
}

func logoImage(logo *scheme.Logo) *clientmodels.Image {
	if logo == nil {
		return nil
	}
	return clientmodels.NewImage(logo.Data, logo.MimeType)
}

func (client *Client) handleAuthorizationRequest(
	session *openid4vpSession,
	request *AuthorizationRequest,
	requestor *clientmodels.TrustedParty,
	audience string,
) error {
	session.request = request
	session.requestor = requestor
	session.audience = audience
	client.register(session)
	defer client.deregister(session)
	return session.perform()
}

// ========================================================================
// Session
// ========================================================================

type openid4vpSession struct {
	request     *AuthorizationRequest
	requestor   *clientmodels.TrustedParty
	handler     Handler
	dcqlHandler *dcql.DcqlHandler
	// audience is the value the disclosed presentations are bound to (the aud of
	// a Key Binding JWT): the client identifier for a URL-invoked session, the
	// origin-prefixed caller origin for a Digital Credentials API session.
	audience   string
	lastPlan   *clientmodels.DisclosurePlan
	lastResult *dcql.DcqlResult
	// preExistingHashes tracks owned credential hashes at session start,
	// used to detect newly issued credentials for WrongCredentialIssued.
	preExistingHashes map[string]struct{}
	// True only while the session goroutine is parked in awaitPermission, i.e. only
	// while an answer has somewhere to go. Claiming it by CAS is what makes an
	// answer exclusive. Also read by [Client.RefreshPendingPermissionRequest].
	awaiting atomic.Bool
	// Latched by Dismiss. A dismissal can arrive before the permission window opens
	// — the session is still fetching and verifying the authorization request —
	// where answer would discard it; requestPermission reads the latch and delivers
	// the denial itself once there is a parked goroutine to receive it.
	dismissed atomic.Bool
	// Carries the verdict to the parked goroutine. Buffered, so nobody blocks.
	answers chan *permissionResponse
}

type permissionResponse struct {
	selections []dcql.DisclosureSelection
}

// Dismiss dismisses this session. A dismissal is a denial, so it travels the same
// channel the user's own "no" does: one path unwinds the session and reports
// Cancelled. Without it the session goroutine stayed parked in awaitPermission
// forever, so every later refresh re-asked the dismissed session for permission.
func (session *openid4vpSession) Dismiss() {
	// Latched before answering: if the goroutine is not parked yet, the ordering
	// against requestPermission's arm-then-check guarantees exactly one delivery.
	session.dismissed.Store(true)
	// This log is the only diagnostic for the path, so report what happened: a
	// dismissal racing the user's own answer, or following one, delivers nothing.
	if session.answer(nil) {
		eudi.Logger.Info("openid4vp: session dismissed")
	} else {
		eudi.Logger.Info("openid4vp: dismissal latched, session was not awaiting an answer")
	}
}

// answer hands a verdict to the goroutine parked in awaitPermission and reports
// whether it was delivered. Only the first answer per parked window is, so a second
// Dismiss — or the callback of a permission request a refresh has superseded — is a
// no-op instead of a stray value the next await picks up.
func (session *openid4vpSession) answer(response *permissionResponse) bool {
	if !session.awaiting.CompareAndSwap(true, false) {
		return false
	}
	session.answers <- response
	return true
}

func (session *openid4vpSession) awaitPermission() *permissionResponse {
	return <-session.answers
}

func (session *openid4vpSession) requestPermission() error {
	plan, err := session.buildDisclosurePlan()
	if err != nil {
		return err
	}
	session.lastPlan = plan

	// Armed before dispatching: a handler may answer synchronously, and an answer
	// arriving before the window opens is discarded.
	session.awaiting.Store(true)
	// Arm first, then read the latch: a dismissal that ran in between delivered its
	// own answer, and this one is dropped by answer's CAS; one that ran before found
	// the window closed, so deliver its denial now instead of asking the UI for
	// permission on a session the user already dismissed.
	if session.dismissed.Load() {
		session.answer(nil)
		return nil
	}
	session.handler.RequestVerificationPermission(
		plan,
		session.requestor,
		session.lastResult.HashToQueryId,
		func(proceed bool, selections []dcql.DisclosureSelection) {
			if proceed {
				session.answer(&permissionResponse{selections: selections})
			} else {
				session.answer(nil)
			}
		},
	)
	return nil
}

// buildDisclosurePlan builds a DisclosurePlan by delegating to the DcqlHandler.
func (session *openid4vpSession) buildDisclosurePlan() (*clientmodels.DisclosurePlan, error) {
	result, err := session.dcqlHandler.FindCandidates(session.request.DcqlQuery)
	if err != nil {
		return nil, err
	}
	session.lastResult = result

	// Snapshot pre-existing hashes on first call
	if session.preExistingHashes == nil {
		session.preExistingHashes = dcql.CollectOwnedHashes(result.QueryResults)
	}

	return session.dcqlHandler.BuildDisclosurePlan(
		session.request.DcqlQuery, result, session.lastPlan, session.preExistingHashes,
	)
}

func (session *openid4vpSession) perform() error {
	err := session.requestPermission()
	if err != nil {
		return fmt.Errorf("failed to request permission: %v", err)
	}
	permResp := session.awaitPermission()

	// Nothing to disclose: the user picked nothing, or the session was dismissed.
	if permResp == nil {
		eudi.Logger.Info("openid4vp: nothing to disclose, cancelling")
		session.handler.Cancelled()
		return nil
	}

	logMarshalled("selections:", permResp.selections)

	// Group selections by format
	queryResponses, credLogs, err := session.prepareDisclosures(permResp.selections)
	if err != nil {
		return err
	}

	responseConfig := authorizationResponseConfig{
		State:          session.request.State,
		QueryResponses: queryResponses,
		ResponseUri:    session.request.ResponseUri,
		ResponseType:   session.request.ResponseType,
		ResponseMode:   session.request.ResponseMode,
	}

	if session.request.ResponseMode == ResponseMode_DirectPostJwt || session.request.ResponseMode == ResponseMode_DcApiJwt {
		if session.request.ClientMetadata == nil || session.request.ClientMetadata.Jwks == nil {
			return fmt.Errorf("client metadata jwks was nil while response_mode %s was used", session.request.ResponseMode)
		}
		responseConfig.EncryptionKeys = &session.request.ClientMetadata.Jwks.Set
		responseConfig.EncryptedResponseEncValuesSupported = session.request.ClientMetadata.EncryptedResponseEncValuesSupported
	}

	// Over the DC API the platform, not the wallet, transports the response back
	// to the verifier, so there is nothing to POST.
	if isDcApiResponseMode(session.request.ResponseMode) {
		dcApiResponse, err := createDcApiResponse(responseConfig)
		if err != nil {
			return err
		}
		session.handler.DeliverDcApiResponse(dcApiResponse)
		session.handler.Success("managed to complete openid4vp session over the digital credentials api", credLogs)
		return nil
	}

	responseReq, err := createAuthorizationResponseHttpRequest(responseConfig)
	if err != nil {
		return err
	}

	response, err := common.HTTPClient.Do(responseReq)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("response status was not ok, status code %d", response.StatusCode)
	}

	session.handler.Success("managed to complete openid4vp session", credLogs)
	return nil
}

// prepareDisclosures delegates to the DcqlHandler to prepare credentials for the VP token.
func (session *openid4vpSession) prepareDisclosures(
	selections []dcql.DisclosureSelection,
) ([]dcql.QueryResponse, []clientmodels.LogCredential, error) {
	prepared, err := session.dcqlHandler.PrepareDisclosure(
		session.request.DcqlQuery, selections, session.request.Nonce, session.audience,
	)
	if err != nil {
		return nil, nil, err
	}
	return prepared.QueryResponses, prepared.CredentialLogs, nil
}

// ========================================================================
// Helpers
// ========================================================================

func logMarshalled(message string, value any) {
	jsonBytes, err := json.MarshalIndent(value, "", "   ")
	if err != nil {
		eudi.Logger.Errorf("%s: failed to marshal: %v", message, err)
	} else {
		eudi.Logger.Infof("\n%s\n%s\n", message, string(jsonBytes))
	}
}
