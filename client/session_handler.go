package client

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

type UserInteractionType string

const (
	UI_EnteredPin UserInteractionType = "entered_pin"
	UI_Permission UserInteractionType = "permission"
)

// Any interaction the user has to do with a session, like entering a pin code or giving permission
type SessionUserInteraction struct {
	// The ID corresponding to the session this interaction belongs to
	SessionId int
	// The type of interaction performed by the user
	Type UserInteractionType
	// The payload for this interaction
	Payload any
}

type SessionPermissionInteractionPayload struct {
	// Whether or not the user agreed to either sharing, siging or disclosing
	Granted bool
	// The list of discons for each outer con, where each discon contains a list of credentials corresponding to the inner con
	DisclosureChoices []DisclosureDisconSelection
}

// A reference to a credential the user has picked for disclosure, including exactly which attributes will be shared
type SelectedCredential struct {
	// The ID for this credential (idemix id or vct)
	CredentialId string
	// The hash for the specific credential instance for which attributes will be shared
	CredentialHash string
	// List of claim path pointers to the attributes the user will share for this credential
	// When it's Idemix these paths should have a length of only one
	AttributePaths [][]any
}

// The list of selected credentials and attributes for a discon
type DisclosureDisconSelection struct {
	Credentials []SelectedCredential
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

type SelectableCredentialInstance struct {
	// The id for this credential. For irma/idemix credentials this would look like
	// `pbdf.sidn-pbdf.email`, for Eudi credentials this would be in the form of `https://example.credential.com`
	CredentialId string
	// Hash over all attribute values and the credential id.
	Hash string
	// Absolute path to the image for this credential stored on disk
	ImagePath string
	// The display name for this credential
	Name TranslatedString
	// All information about the credential issuer
	Issuer TrustedParty
	// The credential format for this instance
	Format CredentialFormat
	// The number of credential instances left for this credential instance
	BatchInstanceCountRemaining *uint
	// All the attributes and their values in this credential that are selectable
	Attributes []Attribute
	// The date and time (unix format) at which this credential was issued
	IssuanceDate int64
	// The date and time (unix format) when this credential expires
	ExpiryDate int64
	// Whether or not this credential has been revoked
	Revoked bool
	// Whether or not revocation is supported for this credential
	RevocationSupported bool
	// Url at which this credential can be issued (if any)
	IssueURL *TranslatedString
}

type DisclosurePlan struct {
	// What to show during issuance during disclosure.
	// If this is nil then no issuances are required before a valid choice can be made.
	// The disclosure flow then only has one step.
	// When it is present it contains both the credentials that have been added during this flow,
	// as well as the credentials left to issuer in order to proceed. This is done to make it possible to
	// show a correct stepper, even after the session state gets updated.
	// When all are satisfied, the value should still be present in updates to the session state, so the stepper is shown correctly.
	IssueDuringDislosure *IssueDuringDislosure
	// What the user can pick for disclosure. This should never be nil.
	DisclosureOptions []DisclosurePickOne
}

// A discon where the user needs to pick only one credential
// TODO: What to do when there's multiple credentials in the inner con?
// This is possible for singletons in irma condiscon and for anything in DCQL (resulting in condiscondis)
// E.g.: you can ask for both personal data and address in the inner con, because they're both singletons and will always result in a single choice.
// But you can't ask for both email and mobilenumber in the inner con, because they're not singletons and they could be multiple options,
// resulting in condiscondis.
type DisclosurePickOne struct {
	// The (default) selected choice
	Selected *SelectableCredentialInstance
	// the user can pick one of these without having to issue
	OwnedOptions []*SelectableCredentialInstance
	// The user can issue one of these and then use it
	ObtainableOptions []*CredentialDescriptor
}

// What to show during issuance during disclosure
type IssueDuringDislosure struct {
	// What has been issued during this disclosure flow
	IssuedDuringSession []*Credential
	// What still has to be issued during this flow before we can continue to the next step
	LeftToIssue []*CredentialDescriptor
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
	s.dispatchState()
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

func findCredentialsForId(credentials []*Credential, id string) []*Credential {
	result := []*Credential{}
	for _, c := range credentials {
		if c.CredentialId == id {
			result = append(result, c)
		}
	}
	return result
}

func findCredential(credentials []*Credential, hash string) *SelectableCredentialInstance {
	for _, c := range credentials {
		// each format has its own hash for the corresponding instance
		for format, h := range c.CredentialInstanceIds {
			if h == hash {
				return &SelectableCredentialInstance{
					CredentialId:                c.CredentialId,
					Hash:                        h,
					ImagePath:                   c.ImagePath,
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
				}
			}
		}
	}
	return nil
}

func condisconToDisclosurePlan(
	config *irma.Configuration,
	credentials []*Credential,
	candidates [][]irmaclient.DisclosureCandidates,
) (*DisclosurePlan, error) {
	plan := &DisclosurePlan{
		IssueDuringDislosure: &IssueDuringDislosure{
			IssuedDuringSession: []*Credential{},
			LeftToIssue:         []*CredentialDescriptor{},
		},
		DisclosureOptions: []DisclosurePickOne{},
	}

	for _, discon := range candidates {
		choice := DisclosurePickOne{}
		for _, con := range discon {
			conCredInstances := map[string]*SelectableCredentialInstance{}
			conCredToIssue := map[string]*CredentialDescriptor{}
			for _, attr := range con {
				hash := attr.AttributeIdentifier.CredentialHash

				// attribute not currently present
				if hash == "" {
					t := attr.CredentialIdentifier().Type
					_, contains := conCredToIssue[t.String()]
					if !contains {
						descriptor, err := getCredentialDescriptor(config, t)
						if err != nil {
							return nil, err
						}
						plan.IssueDuringDislosure.LeftToIssue = append(plan.IssueDuringDislosure.LeftToIssue, descriptor)
						choice.ObtainableOptions = append(choice.ObtainableOptions, descriptor)
						conCredToIssue[t.String()] = descriptor
					}
				} else {
					cred := findCredential(credentials, hash)
					if cred == nil {
						return nil, fmt.Errorf("failed to find credential for hash: %v", hash)
					}
					_, contains := conCredInstances[hash]
					if !contains {
						choice.OwnedOptions = append(choice.OwnedOptions, cred)
						conCredInstances[hash] = cred
					}
				}
			}
		}
		plan.DisclosureOptions = append(plan.DisclosureOptions, choice)
	}
	return plan, nil
}

func (s *Session) issuedDuringDisclosure(
	allCredentials []*Credential,
	newPlan *DisclosurePlan,
) *DisclosurePlan {
	if oldPlan := s.State.DisclosurePlan; oldPlan != nil {
		for _, oldToIssue := range oldPlan.IssueDuringDislosure.LeftToIssue {
			// if the new disclosure plan doesn't contain the credential from the old plan anymore
			// the credential must have been issued and so we add it to the list of credentials
			// that have been issued during this session
			hasBeenIssued := !slices.ContainsFunc(
				newPlan.IssueDuringDislosure.LeftToIssue,
				func(x *CredentialDescriptor) bool {
					return x.CredentialId == oldToIssue.CredentialId
				},
			)

			if hasBeenIssued {
				newPlan.IssueDuringDislosure.IssuedDuringSession = append(
					newPlan.IssueDuringDislosure.IssuedDuringSession,
					findCredentialsForId(allCredentials, oldToIssue.CredentialId)...,
				)
			}
		}
	}
	return newPlan
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
	s.PermissionHandler = callback

	creds, err := s.client.GetCredentials()
	if err != nil {
		s.error(err)
		return
	}

	plan, err := condisconToDisclosurePlan(s.client.irmaClient.Configuration, creds, candidates)
	if err != nil {
		s.error(err)
		return
	}

	s.State.DisclosurePlan = s.issuedDuringDisclosure(creds, plan)

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

// =====================================================================================

func choicesToAnswer(choices []DisclosureDisconSelection) (*irma.DisclosureChoice, error) {
	result := &irma.DisclosureChoice{
		Attributes: [][]*irma.AttributeIdentifier{},
	}

	for _, choice := range choices {
		attrs := []*irma.AttributeIdentifier{}
		for _, cred := range choice.Credentials {
			for _, attr := range cred.AttributePaths {
				attrs = append(attrs, &irma.AttributeIdentifier{
					// this for now assumes only a single claim path item
					Type: irma.NewAttributeTypeIdentifier(
						fmt.Sprintf("%s.%s", cred.CredentialId, attr[0].(string)),
					),
					CredentialHash: cred.CredentialHash,
				})
			}
		}
		result.Attributes = append(result.Attributes, attrs)
	}

	return result, nil
}

// =====================================================================================

func (client *Client) HandleUserInteraction(userInteraction SessionUserInteraction) error {
	session, ok := client.SessionManager.Sessions[userInteraction.SessionId]
	if !ok {
		return fmt.Errorf("no session with id %v", userInteraction.SessionId)
	}
	switch userInteraction.Type {
	case UI_Permission:
		payload := userInteraction.Payload.(SessionPermissionInteractionPayload)
		choices, err := choicesToAnswer(payload.DisclosureChoices)
		if err != nil {
			return err
		}
		session.PermissionHandler(payload.Granted, choices)
	case UI_EnteredPin:
		payload := userInteraction.Payload.(PinInteractionPayload)
		session.PinHanler(payload.Proceed, payload.Pin)
	}

	return nil
}

func (client *Client) NewNewSession(sessionrequest string) irmaclient.SessionDismisser {
	session := client.SessionManager.NewSession()
	state := session.State

	var sessionReq SessionRequestData
	err := json.Unmarshal([]byte(sessionrequest), &sessionReq)
	if err != nil {
		irma.Logger.Errorf("failed to parse session request: %v\n", err)
		session.error(err)
		client.SessionManager.DeleteSession(session.State.Id)
		return nil
	}

	state.Protocol = sessionReq.Protocol

	switch sessionReq.Type {
	case irma.ActionDisclosing:
		state.Type = Type_Disclosure
	case irma.ActionIssuing:
		state.Type = Type_Issuance
	case irma.ActionSigning:
		state.Type = Type_Signature
	}

	return client.NewSession(sessionrequest, session)
}
