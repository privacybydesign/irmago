package client

import (
	"fmt"

	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

type UserInteractionType string

const (
	UI_EnteredPin UserInteractionType = "entered_pin"
	UI_Permission UserInteractionType = "permission"
)

type SessionUserInteraction struct {
	// The ID corresponding to the session this interaction belongs to
	SessionID int
	// The type of interaction performed by the user
	Type UserInteractionType
	// The payload for this interaction
	Payload any
}

type IssuancePermissionInteractionPayload struct {
	Granted bool
}

type PinInteractionPayload struct {
	Pin     string
	Proceed bool
}

type SessionStatus string
type SessionType string

const (
	Status_AskingIssuancePermission   SessionStatus = "issuance_permission"
	Status_AskingDisclosurePermission SessionStatus = "disclosure_permission"
	Status_ShowPairingCode            SessionStatus = "pairing_code"
	Status_Success                    SessionStatus = "success"
	Status_Error                      SessionStatus = "error"
	Status_Dismissed                  SessionStatus = "dismissed"
	Status_RequestPin                 SessionStatus = "pin"

	Type_Disclosure SessionType = "disclosure"
	Type_Issuance   SessionType = "issuance"
	Type_Signature  SessionType = "signature"
)

type DisclosurePlan struct {
	// What to show during issuance during disclosure.
	// If this is nil then no issuances are required before a valid choice can be made.
	// The disclosure flow then only has one step.
	// When it is present it contains both the credentials that have been added during this flow,
	// as well as the credentials left to issuer in order to proceed. This is done to make it possible to
	// show a correct stepper, even after the session state gets updated.
	// When all are satisfied, the value should still be present in updates to the session state, so the stepper is shown correctly.
	IssueDuringDislosure *IssueDuringDislosure
	// What the user can pick for disclosure. This is nil during the issuance step.
	DisclosureMakeChoices *DisclosureMakeChoices
}

type DisclosureChoice struct {
	// The (default) selected choice
	Selected *Credential
	// the user can pick one of these without having to issue
	OwnedOptions []Credential
	// The user can issue one of these and then use it
	ObtainableOptions []CredentialDescriptor
}

type DisclosureMakeChoices struct {
	// The list of choices the user has to make.
	// For each of the choices the user has to pick how to satisfy it.
	Required []DisclosureChoice
}

// What to show during issuance during disclosure
type IssueDuringDislosure struct {
	// What has been issued during this disclosure flow
	IssuedDuringSession []Credential
	// What still has to be issued during this flow before we can continue to the next step
	LeftToIssue []CredentialDescriptor
}

// Snapshot of the state of this session.
// When the session state changes it should create a new instance.
// It has been setup in such a way that it contains all relevant state for
// displaying all stages for this session to the user
type SessionState struct {
	// The identifier for this session
	Id int
	// The protocol used for this session
	Protocol irmaclient.Protocol
	// The type of session this is
	Type SessionType
	// In what stage this session currently is
	Status SessionStatus
	// Who started this session
	Requestor TrustedParty
	// The pairing code to show to the user when the status is pairing
	PairingCode string
	// The list of credentials offered to the user. The user has no choice other than accepting or denying them.
	OfferedCredentials []*Credential
	// The plan for disclosing credentials to satisfy this disclosure session
	// Nil when no disclosure has to be done. Can also be present during issuance session.
	DisclosurePlan *DisclosurePlan
	// The message that should be signed during this session, if any
	MessageToSign string
	// The error when this session has an error
	Error error
	// The client return url when the app should redirect to after the session, if any
	ClientReturnUrl string
}

type Session struct {
	State             *SessionState
	Handler           SessionHandler
	PermissionHandler irmaclient.PermissionHandler
	PinHanler         irmaclient.PinHandler
	client            *Client
}

func (s *Session) dispatchState() {
	s.Handler.UpdateSession(*s.State)
}

func (s *Session) error(err error) {
	s.State.Status = Status_Error
	s.State.Error = err
}

type SessionManager struct {
	Sessions       map[int]*Session
	NextId         int
	SessionHandler SessionHandler
	Client         *Client
}

func (m *SessionManager) DeleteSession(id int) {
	delete(m.Sessions, id)
}

func (m *SessionManager) NewSession() *Session {
	m.NextId += 1
	s := &Session{
		State: &SessionState{
			Id: m.NextId,
		},
		Handler: m.SessionHandler,
		client:  m.Client,
	}
	m.Sessions[m.NextId] = s
	return s
}

type SessionHandler interface {
	UpdateSession(session SessionState)
}

func (s *Session) StatusUpdate(action irma.Action, status irma.ClientStatus) {
	fmt.Printf("status update: %v, status: %v\n", action, status)
}
func (s *Session) ClientReturnURLSet(clientReturnURL string) {
	s.State.ClientReturnUrl = clientReturnURL
	s.dispatchState()
}

func (s *Session) PairingRequired(pairingCode string) {
	s.State.Status = Status_ShowPairingCode
	s.State.PairingCode = pairingCode
	s.dispatchState()
}

func (s *Session) Success(result string) {
	s.State.Status = Status_Success
	s.dispatchState()
}

func (s *Session) Cancelled() {
	s.State.Status = Status_Dismissed
	s.dispatchState()
}

func (s *Session) Failure(err *irma.SessionError) {
	s.error(err)
}

func (s *Session) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	fmt.Println("Keyshare blocked")
}

func (s *Session) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	fmt.Println("Keyshare incomplete")
}

func (s *Session) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	fmt.Println("Keyshare missing")
}

func (s *Session) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	fmt.Println("Keyshare deleted")
}

func (s *Session) RequestIssuancePermission(
	request *irma.IssuanceRequest,
	satisfiable bool,
	candidates [][]irmaclient.DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback irmaclient.PermissionHandler,
) {
	irmaConfig := s.client.GetIrmaConfiguration()
	creds := request.CredentialInfoList

	offeredCredentials, err := credentialInfoListToSchemaless(irmaConfig, creds)

	if err != nil {
		s.error(err)
		return
	}

	s.State.OfferedCredentials = offeredCredentials
	s.State.Status = Status_AskingIssuancePermission
	s.PermissionHandler = callback
	s.State.Protocol = irmaclient.Protocol_Irma

	s.dispatchState()
}

func (s *Session) RequestVerificationPermission(
	request *irma.DisclosureRequest,
	satisfiable bool,
	candidates [][]irmaclient.DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback irmaclient.PermissionHandler,
) {
	s.State.Status = Status_AskingDisclosurePermission
	s.State.Type = Type_Disclosure
	s.dispatchState()
}

func (s *Session) RequestSignaturePermission(request *irma.SignatureRequest,
	satisfiable bool,
	candidates [][]irmaclient.DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback irmaclient.PermissionHandler) {
}

func (s *Session) RequestPermissionAndPerformAuthCodeWithTokenExchange(
	request *irma.AuthorizationCodeFlowAndTokenExchangeRequest,
	requestorInfo *irma.RequestorInfo,
	callback irmaclient.TokenHandler) {
}

func (s *Session) RequestPreAuthorizedCodeFlowPermission(
	request *irma.PreAuthorizedCodeFlowPermissionRequest,
	requestorInfo *irma.RequestorInfo,
	callback irmaclient.TokenPermissionHandler,
) {
}

func (s *Session) RequestPin(remainingAttempts int, callback irmaclient.PinHandler) {
	s.State.Status = Status_RequestPin
	s.PinHanler = callback
	s.dispatchState()
}
