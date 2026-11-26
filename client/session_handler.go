package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

type session struct {
	State                       *clientmodels.SessionState
	handler                     clientmodels.SessionHandler
	permissionHandler           irmaclient.PermissionHandler
	pinHandler                  irmaclient.PinHandler
	client                      *Client
	dismisser                   irmaclient.SessionDismisser
	chained                     bool
	authCodeHandler             openid4vci.AuthCodeHandler
	preAuthorizedCodeHandler    openid4vci.TokenPermissionHandler
	openid4vciPermissionHandler openid4vci.PermissionHandler
	openid4vpPermissionHandler  openid4vp.PermissionHandler
	// Hashes of credentials that already existed when the disclosure plan was first created.
	// Used to exclude pre-existing credentials from WrongCredentialIssued detection.
	preExistingCredentialHashes map[string]struct{}
	// Terminal state finish last dispatched, so a repeat of it can be dropped.
	dispatched clientmodels.SessionStatus
	// IRMA disclosure/signature request we're currently asking the user to satisfy.
	// The answer is built from its cons (answerToIrmaChoice): the IRMA proof
	// verifier matches the j-th disclosed against the j-th requested attribute.
	irmaDiscloseRequest irma.AttributeConDisCon
	// IRMA: the follow-up of a chained session that succeeded, waiting for
	// UI_ContinueNextSession or UI_DismissSession.
	pendingNext *irmaclient.PendingSession
	// Set when an answer was refused: the session ended with an error, and the
	// protocol's own report of being dismissed afterwards is not dispatched.
	answerRejected bool
}

func (s *session) dispatchState() {
	s.handler.UpdateSession(*s.State)
}

// snapshotPreExistingCredentials records the hashes of all credentials that exist
// before issuance-during-disclosure begins. Only called once per session; subsequent
// calls are no-ops so the snapshot reflects the state at plan creation time.
func (s *session) snapshotPreExistingCredentials(credentials []*clientmodels.Credential) {
	if s.preExistingCredentialHashes != nil {
		return
	}
	s.preExistingCredentialHashes = make(map[string]struct{}, len(credentials))
	for _, c := range credentials {
		s.preExistingCredentialHashes[c.Hash] = struct{}{}
		// A slot's candidates carry the hash of the instance per format.
		for _, hash := range c.CredentialInstanceIds {
			s.preExistingCredentialHashes[hash] = struct{}{}
		}
	}
}

func (s *session) error(err error) {
	s.State.Status = clientmodels.Status_Error
	if irmaErr, ok := errors.AsType[*irma.SessionError](err); ok {
		s.State.Error = newSessionError(irmaErr)
	} else {
		s.State.Error = newSessionError(&irma.SessionError{Err: err, ErrorType: irma.ErrorApi, Info: err.Error()})
	}
	s.finish()
}

// finish dispatches the session's final state and evicts the session from the
// manager, so the Sessions map does not grow unboundedly. A repeat of the same
// state is dropped: HandleUserInteraction's dismissal backstop and a protocol's
// own Cancelled both report Dismissed. Best-effort, not a guarantee — dispatched,
// like the State.Status it is compared against, is written from both the UI and
// protocol goroutines without synchronisation. A *different* later state is not — the
// backstop is a guess, and OpenID4VCI's Dismiss only logs, so issuance runs on
// and stores the credential. Swallowing that Success would tell the user their
// wallet did nothing.
func (s *session) finish() {
	if s.dispatched == s.State.Status {
		return
	}
	if s.answerRejected && s.State.Status != clientmodels.Status_Error {
		return
	}
	s.dispatched = s.State.Status
	s.dispatchState()
	s.client.sessionManager.DeleteSession(s.State.Id)
}

func newSessionError(err *irma.SessionError) *clientmodels.SessionError {
	var remoteError *clientmodels.RemoteError
	if err.RemoteError != nil {
		remoteError = &clientmodels.RemoteError{
			Status:      err.RemoteError.Status,
			ErrorName:   err.RemoteError.ErrorName,
			Description: err.RemoteError.Description,
			Message:     err.RemoteError.Message,
			Stacktrace:  err.RemoteError.Stacktrace,
		}
	}
	return &clientmodels.SessionError{
		ErrorType:    string(err.ErrorType),
		WrappedError: err.WrappedError(),
		Info:         err.Info,
		RemoteError:  remoteError,
		RemoteStatus: err.RemoteStatus,
		Stack:        err.Stack(),
	}
}

type sessionManager struct {
	mu             sync.Mutex
	Sessions       map[int]*session
	SessionHandler clientmodels.SessionHandler
	Client         *Client
}

func (m *sessionManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Sessions = map[int]*session{}
}

func (m *sessionManager) DeleteSession(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Sessions, id)
}

func (m *sessionManager) GetSession(id int) (*session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Sessions[id]
	return s, ok
}

// NewSession registers a session under the caller-supplied id. The id is
// allocated by the Dart client so the mobile UI can route state events to the
// right screen without waiting for Go to respond. If the id is already in use
// — which happens on Flutter hot-reload, where the Dart isolate's counter
// resets while the Go-side Sessions map still holds prior ids — the existing
// entry is evicted and replaced; its handlers reference the now-dead Dart
// isolate, so dropping it is the correct behavior. Panics on id == 0, which
// the old auto-incrementer never produced and which downstream code may treat
// as a sentinel.
func (m *sessionManager) NewSession(id int) *session {
	if id == 0 {
		panic("client: session id must be non-zero")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.Sessions[id]; exists {
		irma.Logger.Warnf("client: session id %d already in use; evicting stale entry", id)
	}
	s := &session{
		State: &clientmodels.SessionState{
			Id: id,
		},
		handler: m.SessionHandler,
		client:  m.Client,
	}
	m.Sessions[id] = s
	return s
}

func requestorInfoToTrustedParty(info *irma.RequestorInfo, locale string) clientmodels.TrustedParty {
	var image *clientmodels.Image
	if info.LogoPath != nil {
		image = clientmodels.ImageFromFile(*info.LogoPath)
	}
	party := clientmodels.TrustedParty{
		Id:       info.ID.String(),
		Name:     clientmodels.Resolve(clientmodels.TranslatedString(info.Name), locale),
		Image:    image,
		Parent:   nil,
		Verified: !info.Unverified,
	}
	// A verified IRMA requestor is one registered in a Yivi requestor scheme.
	if party.Verified {
		party.TrustSource = clientmodels.TrustSource_YiviScheme
		party.Evidence = &clientmodels.TrustEvidence{RegistrationId: info.ID.String()}
	}
	return party
}

func requestorInfoToTrustedPartyPtr(info *irma.RequestorInfo, locale string) *clientmodels.TrustedParty {
	if info == nil {
		return nil
	}
	tp := requestorInfoToTrustedParty(info, locale)
	return &tp
}

// filterRandomBlindAttributes removes random blind attributes from offered credentials.
// These attributes are generated by the issuance protocol and have no user-meaningful value
// at issuance permission time.
func filterRandomBlindAttributes(irmaConfig *irma.Configuration, credentials []*clientmodels.Credential) {
	for _, cred := range credentials {
		credTypeID := irma.NewCredentialTypeIdentifier(cred.CredentialId)
		credType, ok := irmaConfig.CredentialTypes[credTypeID]
		if !ok {
			continue
		}
		randomBlindIDs := make(map[string]struct{})
		for _, at := range credType.AttributeTypes {
			if at.RandomBlind {
				randomBlindIDs[clientmodels.ClaimPathKey([]any{at.ID})] = struct{}{}
			}
		}
		if len(randomBlindIDs) == 0 {
			continue
		}
		filtered := make([]clientmodels.Attribute, 0, len(cred.Attributes))
		for _, attr := range cred.Attributes {
			if _, isBlind := randomBlindIDs[clientmodels.ClaimPathKey(attr.ClaimPath)]; !isBlind {
				filtered = append(filtered, attr)
			}
		}
		cred.Attributes = filtered
	}
}

func findCredential(credentials []*clientmodels.Credential, hash string) *clientmodels.SelectableCredentialInstance {
	for _, c := range credentials {
		// each format has its own hash for the corresponding instance
		for format, h := range c.CredentialInstanceIds {
			if h == hash {
				return &clientmodels.SelectableCredentialInstance{
					CredentialId:                c.CredentialId,
					Hash:                        h,
					Image:                       c.Image,
					Name:                        c.Name,
					Issuer:                      c.Issuer,
					Format:                      format,
					BatchInstanceCountRemaining: c.BatchInstanceCountsRemaining[format],
					Attributes:                  c.Attributes,
					IssuanceDate:                c.IssuanceDate,
					ExpiryDate:                  c.ExpiryDate,
					Revoked:                     c.Revoked,
					RevocationSupported:         c.RevocationSupported,
					IssueURL:                    c.IssueURL,
					IsSingleton:                 c.IsSingleton,
				}
			}
		}
	}
	return nil
}

// sortAttributesBySchema returns attrs reordered to follow credType's declared
// display order. Precedence matches sortedAttributeTypes: DisplayIndex first
// when every type has one, else XML-position Index. Attributes whose first
// claim-path element doesn't resolve to a schema attribute are kept after the
// known ones in their original order.
func sortAttributesBySchema(
	attrs []clientmodels.Attribute,
	credType *irma.CredentialType,
) []clientmodels.Attribute {
	if credType == nil || len(attrs) <= 1 {
		return attrs
	}
	sortedTypes := sortedAttributeTypes(credType.AttributeTypes)
	position := make(map[string]int, len(sortedTypes))
	for i, at := range sortedTypes {
		position[at.ID] = i
	}
	unknown := len(sortedTypes)
	posOf := func(a clientmodels.Attribute) int {
		if len(a.ClaimPath) == 0 {
			return unknown
		}
		name, ok := a.ClaimPath[0].(string)
		if !ok {
			return unknown
		}
		if p, ok := position[name]; ok {
			return p
		}
		return unknown
	}
	out := make([]clientmodels.Attribute, len(attrs))
	copy(out, attrs)
	slices.SortStableFunc(out, func(a, b clientmodels.Attribute) int {
		return posOf(a) - posOf(b)
	})
	return out
}

// filterCredentialToMismatchedAttributes returns a copy of the credential containing only
// the attributes that have a pre-defined requested value that doesn't match the credential's
// actual value. Each included attribute gets the RequestedValue from the option so the
// frontend can show both the actual and expected values side by side.
func filterCredentialToMismatchedAttributes(cred *clientmodels.Credential, requestedAttrs []clientmodels.Attribute) *clientmodels.Credential {
	requestedByID := make(map[string]*clientmodels.Attribute, len(requestedAttrs))
	for i := range requestedAttrs {
		requestedByID[clientmodels.ClaimPathKey(requestedAttrs[i].ClaimPath)] = &requestedAttrs[i]
	}

	filtered := []clientmodels.Attribute{}
	for _, attr := range cred.Attributes {
		req, ok := requestedByID[clientmodels.ClaimPathKey(attr.ClaimPath)]
		if !ok || req.RequestedValue == nil || !req.RequestedValue.HasValue() {
			continue
		}
		// Check if the actual value doesn't match the requested value
		satisfied, _ := SatisfiesRequestedAttributes(
			[]clientmodels.Attribute{attr},
			[]clientmodels.Attribute{*req},
		)
		if !satisfied {
			filtered = append(filtered, clientmodels.Attribute{
				ClaimPath:       attr.ClaimPath,
				DisplayName:     attr.DisplayName,
				Description:     attr.Description,
				Value:           attr.Value,
				RequestedValue:  req.RequestedValue,
				RequestedValues: req.RequestedValues,
			})
		}
	}

	result := *cred
	result.Attributes = filtered
	return &result
}

// createDisclosurePlan builds the plan for an IRMA request from what the wallet
// holds per slot (irmaclient.SlotCandidates). oldDisclosurePlan is the plan last
// sent for this request, nil the first time; with the cards held when the
// request arrived it says what was issued for it since, and which issued card
// does not fit.
func createDisclosurePlan(
	oldDisclosurePlan *clientmodels.DisclosurePlan,
	irmaConfig *irma.Configuration,
	credentials []*clientmodels.Credential,
	slots []irmaclient.DisconSlots,
	preExistingCredentialHashes map[string]struct{},
	locale string,
) (*clientmodels.DisclosurePlan, error) {
	choices, err := createIrmaChoices(irmaConfig, credentials, slots, locale)
	if err != nil {
		return nil, fmt.Errorf("failed to create disclosure choices: %w", err)
	}
	plan := &clientmodels.DisclosurePlan{Choices: choices}
	clientmodels.TrackIssued(plan, oldDisclosurePlan, preExistingCredentialHashes)
	plan.WrongCredentialIssued = detectWrongCredentialIssued(plan, oldDisclosurePlan, credentials, preExistingCredentialHashes)
	return plan, nil
}

func lookupAttrValue(orig *clientmodels.SelectableCredentialInstance, id *irma.AttributeIdentifier) (clientmodels.Attribute, bool) {
	index := slices.IndexFunc(orig.Attributes, func(att clientmodels.Attribute) bool {
		return clientmodels.ClaimPathKey(att.ClaimPath) == clientmodels.ClaimPathKey([]any{id.Type.Name()})
	})
	if index >= 0 {
		return orig.Attributes[index], true
	}
	return clientmodels.Attribute{}, false
}

// =====================================================================================

// sortAttrsToMatchRequestCon reorders attrs so that, for some con in discon
// they fully satisfy, position matches that con's. If no con matches (the
// frontend selected something unsatisfiable, or the discon is empty), attrs
// is returned unchanged — the verifier will reject it, which is the right
// failure mode.
func sortAttrsToMatchRequestCon(attrs []*irma.AttributeIdentifier, discon irma.AttributeDisCon) []*irma.AttributeIdentifier {
	if len(attrs) == 0 || len(discon) == 0 {
		return attrs
	}
	for _, con := range discon {
		if len(con) != len(attrs) {
			continue
		}
		// Try to map each request entry to a disclosed attr (by Type).
		used := make([]bool, len(attrs))
		ordered := make([]*irma.AttributeIdentifier, 0, len(attrs))
		matched := true
		for _, ar := range con {
			found := -1
			for i, a := range attrs {
				if used[i] {
					continue
				}
				if a.Type == ar.Type {
					found = i
					break
				}
			}
			if found < 0 {
				matched = false
				break
			}
			used[found] = true
			ordered = append(ordered, attrs[found])
		}
		if matched {
			return ordered
		}
	}
	return attrs
}

// =====================================================================================

// answerPermission handles a permission given as an answer per slot. A refusal
// needs no answer. A granted answer that does not fit the plan last sent ends
// the session with an error, rather than sending the requestor a response it
// would reject or leaving the session waiting.
func (session *session) answerPermission(payload clientmodels.SessionPermissionInteractionPayload) error {
	if !payload.Granted {
		switch {
		case session.openid4vpPermissionHandler != nil:
			session.openid4vpPermissionHandler(false, nil)
		case session.permissionHandler != nil:
			session.permissionHandler(false, nil)
		}
		return nil
	}

	if err := clientmodels.ValidateAnswer(session.State.DisclosurePlan, payload.Choices); err != nil {
		return session.rejectAnswer(err)
	}
	if session.openid4vpPermissionHandler != nil {
		session.openid4vpPermissionHandler(true, answerToOpenID4VPSelections(payload.Choices))
		return nil
	}

	choice := &irma.DisclosureChoice{Attributes: [][]*irma.AttributeIdentifier{}}
	// A chained issuance can come without a plan; what it discloses then is
	// the previous session's attributes, added by irmaclient.
	if session.State.DisclosurePlan != nil {
		var err error
		if choice, err = answerToIrmaChoice(payload.Choices, session.irmaDiscloseRequest); err != nil {
			return session.rejectAnswer(err)
		}
	}
	session.permissionHandler(true, choice)
	return nil
}

func (session *session) rejectAnswer(err error) error {
	err = fmt.Errorf("answer refused: %w", err)
	irma.Logger.Warn(err)
	session.answerRejected = true
	session.error(err)
	session.dismisser.Dismiss()
	return err
}

func (client *Client) HandleUserInteraction(userInteraction clientmodels.SessionUserInteraction) error {
	session, ok := client.sessionManager.GetSession(userInteraction.SessionId)
	if !ok {
		return fmt.Errorf("no session with id %v", userInteraction.SessionId)
	}
	switch userInteraction.Type {
	case clientmodels.UI_Permission:
		payload := userInteraction.Payload.(clientmodels.SessionPermissionInteractionPayload)
		if session.openid4vciPermissionHandler != nil {
			// OpenID4VCI: an issuance offer has no disclosure to answer.
			session.openid4vciPermissionHandler(payload.Granted)
			return nil
		}
		return session.answerPermission(payload)
	case clientmodels.UI_EnteredPin:
		payload := userInteraction.Payload.(clientmodels.PinInteractionPayload)
		session.pinHandler(payload.Proceed, payload.Pin)
	case clientmodels.UI_ContinueNextSession:
		next := session.pendingNext
		if next == nil {
			return fmt.Errorf("session %v has no follow-up session waiting", userInteraction.SessionId)
		}
		session.pendingNext = nil
		session.State.NextSessionPending = false
		next.Start()
	case clientmodels.UI_DismissSession:
		if next := session.pendingNext; next != nil {
			// The session itself is done; only its follow-up is given up.
			session.pendingNext = nil
			next.Drop()
			session.State.NextSessionPending = false
			session.finish()
			return nil
		}
		session.dismisser.Dismiss()
		// Mark dismissed regardless of protocol: OpenID4VCI's Dismiss does not report
		// it at all, OpenID4VP's only once its goroutine unwinds. finish drops the repeat.
		session.State.Status = clientmodels.Status_Dismissed
		session.finish()
	case clientmodels.UI_PreAuthorizedCode:
		payload := userInteraction.Payload.(clientmodels.SessionPreAuthorizedCodeInteractionPayload)
		session.preAuthorizedCodeHandler(payload.Proceed, payload.TransactionCode)
	case clientmodels.UI_AuthorizationCode:
		payload := userInteraction.Payload.(clientmodels.SessionAuthCodeInteractionPayload)
		// The openid4vci client parses the callback URL; a denial (Proceed=false)
		// passes a nil URL and is handled there before any parsing.
		session.authCodeHandler(payload.Proceed, payload.CallbackURL)
	}

	return nil
}

// NewSession starts a new session, using a caller-supplied id so that the
// mobile UI can mount its session screen synchronously without waiting for
// the first state event.
func (client *Client) NewSession(id int, sessionrequest string) {
	session := client.sessionManager.NewSession(id)
	state := session.State

	var sessionReq SessionRequestData
	err := json.Unmarshal([]byte(sessionrequest), &sessionReq)
	if err != nil {
		irma.Logger.Errorf("failed to parse session request: %v\n", err)
		session.error(err)
		return
	}

	state.Protocol = sessionReq.Protocol
	state.ContinueOnSecondDevice = sessionReq.ContinueOnSecondDevice

	switch sessionReq.Type {
	case irma.ActionDisclosing:
		state.Type = clientmodels.Type_Disclosure
	case irma.ActionIssuing:
		state.Type = clientmodels.Type_Issuance
	case irma.ActionSigning:
		state.Type = clientmodels.Type_Signature
	}

	switch sessionReq.Protocol {
	case clientmodels.Protocol_OpenID4VP:
		if sessionReq.DcApi != nil {
			session.dismisser = client.openid4vpClient.NewDcApiSession(sessionReq.DcApi, &openid4vpSessionAdapter{session: session})
		} else {
			session.dismisser = client.openid4vpClient.NewSession(sessionReq.URL, &openid4vpSessionAdapter{session: session})
		}
	case clientmodels.Protocol_OpenID4VCI:
		if sessionReq.OpenID4VCIRedirectUri == "" {
			session.error(fmt.Errorf("OpenID4VCI session request is missing openid4vci_redirect_uri"))
			return
		}
		session.dismisser = client.openid4vciClient.NewSession(id, sessionReq.URL, sessionReq.OpenID4VCIRedirectUri, &openid4vciSessionAdapter{session: session})
	default:
		session.dismisser = client.irmaClient.NewSession(sessionrequest, &irmaSessionAdapter{session: session})
	}
}
