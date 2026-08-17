package openid4vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
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

	// requireUnencryptedDirectPost is the deployment policy set by
	// RequireUnencryptedDirectPost. Read on the session goroutines, written once
	// at wallet construction before any session exists.
	requireUnencryptedDirectPost bool

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

// RequireUnencryptedDirectPost restricts URL-invoked sessions to
// response_mode=direct_post, refusing direct_post.jwt.
//
// This is deployment policy, not protocol: OpenID4VP and ISO 18013-7 both allow
// the encrypted variant, and the wallet implements it correctly (mso_mdoc's
// session transcript commits to the response encryption key's thumbprint, see
// mdoc_dcql). The EU Age Verification profile is narrower than the specs it
// builds on and permits only plain direct_post on the redirect path, so a
// deployment serving that profile can hold the wallet to it here rather than
// discovering the mismatch at a verifier.
//
// Off by default: enabling it unconditionally would refuse ordinary
// 18013-7 verifiers that do nothing wrong. It deliberately does not touch the
// Digital Credentials API modes, which the AV profile makes the primary path and
// where encrypted responses are expected.
func (client *Client) RequireUnencryptedDirectPost(required bool) {
	client.requireUnencryptedDirectPost = required
}

func (client *Client) checkRedirectResponseModeAllowed(mode ResponseMode) error {
	if !client.requireUnencryptedDirectPost {
		return nil
	}
	if mode == ResponseMode_DirectPostJwt {
		return fmt.Errorf(
			"response_mode %s is not accepted by this wallet deployment: only %s is allowed for a URL-invoked session",
			ResponseMode_DirectPostJwt, ResponseMode_DirectPost)
	}
	return nil
}

// NewClient creates a new OpenID4VP client.
func NewClient(
	eudiConf *eudi.Configuration,
	handlers []dcql.DcqlCredentialQueryHandler,
	verifierValidator VerifierValidator,
	currentLocale *clientmodels.CurrentLocale,
) (*Client, error) {
	return &Client{
		Configuration:     eudiConf,
		dcqlHandler:       dcql.NewDcqlHandler(handlers),
		verifierValidator: verifierValidator,
		currentLocale:     currentLocale,
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
			handleFailure(handler, "openid4vp: %v", err)
			return
		}

		if err := validateRedirectAuthorizationRequest(request); err != nil {
			handleFailure(handler, "openid4vp: invalid authorization request: %v", err)
			return
		}

		if err := validateResponseUriBinding(request); err != nil {
			handleFailure(handler, "openid4vp: refusing to answer this request: %v", err)
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

		if err := client.checkRedirectResponseModeAllowed(request.ResponseMode); err != nil {
			handleFailure(handler, "openid4vp: %v", err)
			return
		}

		eudi.Logger.Infof("auth request: %#v", request)

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
			handleFailure(handler, "openid4vp: %v", err)
			return
		}

		eudi.Logger.Infof("dc api auth request: %#v", authRequest)

		// Over the DC API the response is bound to the origin the platform
		// authenticated, never to the client identifier (Appendix A.4).
		session.origin = request.Origin
		err = client.handleAuthorizationRequest(session, authRequest, requestor, OriginAudience(request.Origin))

		if err != nil {
			handleFailure(handler, "openid4vp: failed to handle authorization request: %v", err)
		}
	}()
}

// verifySignedAuthorizationRequest verifies a signed authorization request JWT
// against the configured trust models, caches the verifier logo, and builds the
// requestor to show to the user.
func (client *Client) verifySignedAuthorizationRequest(authRequestJwt string) (
	*AuthorizationRequest,
	*clientmodels.TrustedParty,
	error,
) {
	request, endEntityCert, requestorSchemeData, err := client.verifierValidator.
		ParseAndVerifyAuthorizationRequest(authRequestJwt)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify authorization request: %v", err)
	}

	// The verifier is identified by its client_id, not by its certificate.
	//
	// Both are authenticated: the validator binds the leaf to the client_id,
	// by SAN for the x509_san_dns: prefix and by leaf hash for x509_hash:,
	// and rejects a request whose client_id carries neither. But a serial
	// number names one certificate rather than the party holding it, so a
	// routine re-issue filed the same organization under a second identity --
	// splitting its disclosure history in two and orphaning the logo cached
	// under the retired serial. A client_id also exists in the DID trust
	// model, which has no certificate at all and so left the id empty,
	// collapsing every DID verifier onto one blank key.
	//
	// Note that x509_hash: is a digest of the leaf and so still rotates with
	// the certificate; only x509_san_dns: survives a re-issue. This is no
	// worse than the serial in that case, and better in the other two.
	requestorId := request.ClientId

	// Store the verifier logo in the cache. The storage layer hashes a key
	// into its on-disk filename, so the prefix and its colon need no
	// escaping here.
	if requestorId != "" && requestorSchemeData.Organization.Logo != nil {
		err = client.Configuration.Storage.FileSystem().Verifiers().LogoManager().Save(
			requestorId,
			requestorSchemeData.Organization.Logo.Data,
			requestorSchemeData.Organization.Logo.MimeType,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to store verifier logo: %v", err)
		}
	}

	requestor := &clientmodels.TrustedParty{
		Id:       requestorId,
		Name:     clientmodels.Resolve(clientmodels.TranslatedString(requestorSchemeData.Organization.LegalName), client.currentLocale.Get()),
		Verified: endEntityCert != nil,
	}

	if requestorSchemeData.Organization.Logo != nil && len(requestorSchemeData.Organization.Logo.Data) > 0 {
		requestor.Image = &clientmodels.Image{
			Base64: base64.StdEncoding.EncodeToString(requestorSchemeData.Organization.Logo.Data),
		}
	}

	return request, requestor, nil
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
	audience string
	// origin is the bare caller origin the platform authenticated, set only for a
	// Digital Credentials API session. mso_mdoc's DC API handover signs this
	// value, which is the audience without its "origin:" prefix; keeping it
	// rather than stripping the prefix back off keeps one representation
	// authoritative.
	origin     string
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

	// The response encryption key is chosen before anything is disclosed, not
	// when the response is built: mso_mdoc's deviceAuth signs over a session
	// transcript carrying this key's thumbprint, so the choice has to be made
	// while the signature is still ahead of us. Formats whose holder binding is
	// not transcript-bound ignore the thumbprint entirely.
	var encryptionKey jwk.Key
	var encryptionKeyThumbprint []byte
	if session.request.ResponseMode == ResponseMode_DirectPostJwt || session.request.ResponseMode == ResponseMode_DcApiJwt {
		if session.request.ClientMetadata == nil || session.request.ClientMetadata.Jwks == nil {
			return fmt.Errorf("client metadata jwks was nil while response_mode %s was used", session.request.ResponseMode)
		}
		var err error
		encryptionKey, encryptionKeyThumbprint, err = selectResponseEncryptionKey(session.request.ClientMetadata.Jwks.Set)
		if err != nil {
			return err
		}
	}

	binding := dcql.ResponseBinding{
		ResponseUri:             session.request.ResponseUri,
		EncryptionKeyThumbprint: encryptionKeyThumbprint,
		OverDcApi:               isDcApiResponseMode(session.request.ResponseMode),
		Origin:                  session.origin,
	}

	// Logged together, and only once the binding exists. The transport-bound
	// fields of a DisclosureSelection are still zero when the user answers the
	// permission request -- they are filled in from the binding further down --
	// so logging the selections alone printed an empty response_uri and a null
	// encryption key thumbprint even for a direct_post.jwt session that had both.
	// Those are the first values anyone reads when an mdoc's deviceAuth fails to
	// verify, and reading them as empty sends the search in the wrong direction.
	logMarshalled("disclosure:", struct {
		Selections []dcql.DisclosureSelection `json:"selections"`
		Binding    dcql.ResponseBinding       `json:"response_binding"`
	}{permResp.selections, binding})

	// Group selections by format
	queryResponses, credLogs, err := session.prepareDisclosures(permResp.selections, binding)
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

	if encryptionKey != nil {
		responseConfig.EncryptionKey = encryptionKey
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
	binding dcql.ResponseBinding,
) ([]dcql.QueryResponse, []clientmodels.LogCredential, error) {
	prepared, err := session.dcqlHandler.PrepareDisclosure(
		session.request.DcqlQuery, selections, session.request.Nonce, session.audience, binding,
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
