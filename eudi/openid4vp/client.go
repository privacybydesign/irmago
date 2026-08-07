package openid4vp

import (
	"context"
	"crypto/x509"
	"encoding/base64"
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
// keys entries on, most specific first.
//
// A client_id is a prefixed identifier: the prefix says how the verifier
// authenticates, the rest is who it is. A trust list names the party, so a DID
// client_id contributes the bare DID — an entry that had to spell out
// "decentralized_identifier:did:web:..." would be writing the wallet's protocol
// into the scheme operator's data. The client_id is carried alongside it for
// entries keyed on whatever else a prefix may introduce.
func verifierIdentifiers(clientId string) []string {
	if did, found := strings.CutPrefix(clientId, string(ClientIdentifierPrefix_DecentralizedDid)); found && did != "" {
		return []string{did, clientId}
	}
	return []string{clientId}
}

// handlePartyValidationFailure ends the session the same way handleFailure
// does, but with the code that tells the app the verifier itself was rejected
// rather than that the network or the protocol misbehaved.
func handlePartyValidationFailure(handler Handler, message string, fmtArgs ...any) {
	eudi.Logger.Errorf(message, fmtArgs...)
	handler.Failure(&clientmodels.SessionError{
		ErrorType:    clientmodels.ErrorType_PartyValidationFailed,
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

		request, endEntityCert, requestorSchemeData, err := client.verifierValidator.
			ParseAndVerifyAuthorizationRequest(string(authRequestJwt))

		if err != nil {
			// The identity gate rejected the verifier: its chain, its signature
			// or its DID did not hold up, or it identified itself in a way the
			// wallet cannot authenticate at all. Either way the wallet does not
			// know who it is talking to and nothing was disclosed, and the app
			// has to be able to say so rather than show a generic error.
			handlePartyValidationFailure(handler, "openid4vp: failed to verify authorization request: %v", err)
			return
		}

		if err := validateNonce(request.Nonce); err != nil {
			handleFailure(handler, "openid4vp: invalid authorization request: %v", err)
			return
		}

		// Store the verifier logo in the cache (only when a certificate is available, e.g. X.509 trust model)
		if endEntityCert != nil && requestorSchemeData.Organization.Logo != nil {
			err = client.Configuration.Storage.FileSystem().Verifiers().LogoManager().Save(
				endEntityCert.SerialNumber.String(),
				requestorSchemeData.Organization.Logo.Data,
				requestorSchemeData.Organization.Logo.MimeType,
			)
			if err != nil {
				handleFailure(handler, "openid4vp: failed to store verifier logo: %v", err)
				return
			}
		}

		// One pinned view for the whole session, taken before the first party is
		// ranked, so a list refresh landing mid-session cannot change what this
		// session decided about the verifier.
		verdict := client.trustEvaluator.Snapshot(context.Background()).Verifier(trust.Evidence{
			Certificate: endEntityCert,
			Identifiers: verifierIdentifiers(request.ClientId),
		})

		requestor := client.composeRequestor(verdict, requestorSchemeData, endEntityCert, request.ClientId)

		eudi.Logger.Infof("auth request: %#v", request)
		err = client.handleAuthorizationRequest(session, request, requestor)

		if err != nil {
			handleFailure(handler, "openid4vp: failed to handle authorization request: %v", err)
		}
	}()
}

// composeRequestor reduces what the wallet knows about the verifier to the party
// the app renders, through the display precedence every party is composed by.
//
// Where the verifier's own material belongs depends on how it authenticated.
// Without a certificate — a bare DID — the wallet has nothing but what the
// request claims, so the material is the verifier's own word for itself. With
// one, it is counted as attested, because the validator hands the requestor info
// over already collapsed: the certificate's own account of the party (the Yivi
// extension, or the subject's common name) and what the request asserts through
// client_metadata arrive in the same field, and this side cannot tell them
// apart. Separating them means changing what the validator surfaces, which is
// where the issuer's x5c work lands too.
func (client *Client) composeRequestor(
	verdict trust.Verdict,
	requestorSchemeData *scheme.RelyingPartyRequestor,
	endEntityCert *x509.Certificate,
	clientId string,
) *clientmodels.TrustedParty {
	locale := client.currentLocale.Get()
	name := clientmodels.Resolve(clientmodels.TranslatedString(requestorSchemeData.Organization.LegalName), locale)

	var display trust.PartyDisplay
	if endEntityCert != nil {
		display = trust.PartyDisplay{
			Id: endEntityCert.SerialNumber.String(),
			Attested: trust.PartyMetadata{
				Name: name,
				Logo: logoImage(requestorSchemeData.Organization.Logo),
			},
		}
	} else {
		display = trust.PartyDisplay{
			// A verifier that did not authenticate with a certificate has no
			// serial number to be known by, so it is identified by the party
			// half of its client_id: the DID or hostname a user can recognize,
			// and at low the only thing on the screen it did not choose itself.
			Id:               verifierIdentifiers(clientId)[0],
			SelfAssertedName: name,
		}
	}

	if verdict.Listing != nil {
		display.CuratedLogo = services.LoadCuratedLogo(
			context.Background(),
			client.verifierLogoManager(),
			common.HTTPClient,
			verdict.Listing.LogoURI,
		)
	}

	return display.TrustedParty(verdict, locale)
}

// verifierLogoManager is the wallet's verifier logo cache, or nil when the
// client was built without storage — which a test doing without one may, and
// which then simply leaves a party without its logo.
func (client *Client) verifierLogoManager() filesystem.LogoManager {
	if client.Configuration == nil || client.Configuration.Storage == nil {
		return nil
	}
	return client.Configuration.Storage.FileSystem().Verifiers().LogoManager()
}

// logoImage wraps a scheme logo for the app, or returns nil when there is none.
func logoImage(logo *scheme.Logo) *clientmodels.Image {
	if logo == nil || len(logo.Data) == 0 {
		return nil
	}
	image := &clientmodels.Image{Base64: base64.StdEncoding.EncodeToString(logo.Data)}
	if mimeType := logo.MimeType; mimeType != "" {
		image.MimeType = &mimeType
	}
	return image
}

func (client *Client) handleAuthorizationRequest(
	session *openid4vpSession,
	request *AuthorizationRequest,
	requestor *clientmodels.TrustedParty,
) error {
	session.request = request
	session.requestor = requestor
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
	lastPlan    *clientmodels.DisclosurePlan
	lastResult  *dcql.DcqlResult
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

	if session.request.ResponseMode == ResponseMode_DirectPostJwt {
		if session.request.ClientMetadata == nil || session.request.ClientMetadata.Jwks == nil {
			return fmt.Errorf("client metadata jwks was nil while response_mode %s was used", ResponseMode_DirectPostJwt)
		}
		responseConfig.EncryptionKeys = &session.request.ClientMetadata.Jwks.Set
		responseConfig.EncryptedResponseEncValuesSupported = session.request.ClientMetadata.EncryptedResponseEncValuesSupported
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
		session.request.DcqlQuery, selections, session.request.Nonce, session.request.ClientId,
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
