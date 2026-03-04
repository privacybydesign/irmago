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
	UI_EnteredPin     UserInteractionType = "entered_pin"
	UI_Permission     UserInteractionType = "permission"
	UI_DismissSession UserInteractionType = "dismiss"
)

// SessionUserInteraction is any interaction the user has to do with a session, like entering a pin code or giving permission
type SessionUserInteraction struct {
	// The ID corresponding to the session this interaction belongs to
	SessionId int `json:"session_id"`
	// The type of interaction performed by the user
	Type UserInteractionType `json:"type"`
	// The payload for this interaction
	Payload any `json:"payload"`
}

type SessionPermissionInteractionPayload struct {
	// Whether or not the user agreed to either sharing, siging or disclosing
	Granted bool `json:"granted"`
	// The list of discons for each outer con, where each discon contains a list of credentials corresponding to the inner con
	DisclosureChoices []DisclosureDisconSelection `json:"disclosure_choices"`
}

// SelectedCredential is a reference to a credential the user has picked for disclosure, including exactly which attributes will be shared
type SelectedCredential struct {
	// The ID for this credential (idemix id or vct)
	CredentialId string `json:"credential_id"`
	// The hash for the specific credential instance for which attributes will be shared
	CredentialHash string `json:"credential_hash"`
	// List of claim path pointers to the attributes the user will share for this credential
	// When it's Idemix these paths should have a length of only one
	AttributePaths [][]any `json:"attribute_paths"`
}

// DisclosureDisconSelection is the list of selected credentials and attributes for a discon
type DisclosureDisconSelection struct {
	Credentials []SelectedCredential `json:"credentials"`
}

type PinInteractionPayload struct {
	Pin     string `json:"pin"`
	Proceed bool   `json:"proceed"`
}

type SessionStatus string
type SessionType string

const (
	Status_RequestPermission SessionStatus = "request_permission"
	Status_ShowPairingCode   SessionStatus = "show_pairing_code"
	Status_Success           SessionStatus = "success"
	Status_Error             SessionStatus = "error"
	Status_Dismissed         SessionStatus = "dismissed"
	Status_RequestPin        SessionStatus = "request_pin"

	Type_Disclosure SessionType = "disclosure"
	Type_Issuance   SessionType = "issuance"
	Type_Signature  SessionType = "signature"
)

type SelectableCredentialInstance struct {
	// The id for this credential. For irma/idemix credentials this would look like
	// `pbdf.sidn-pbdf.email`, for Eudi credentials this would be in the form of `https://example.credential.com`
	CredentialId string `json:"credential_id"`
	// Hash over all attribute values and the credential id.
	Hash string `json:"hash"`
	// Absolute path to the image for this credential stored on disk
	ImagePath string `json:"image_path"`
	// The display name for this credential
	Name TranslatedString `json:"name"`
	// All information about the credential issuer
	Issuer TrustedParty `json:"issuer"`
	// The credential format for this instance
	Format CredentialFormat `json:"format"`
	// The number of credential instances left for this credential instance
	BatchInstanceCountRemaining *uint `json:"batch_instance_count_remaining"`
	// All the attributes and their values in this credential that are selectable
	Attributes []Attribute `json:"attributes"`
	// The date and time (unix format) at which this credential was issued
	IssuanceDate int64 `json:"issuance_date"`
	// The date and time (unix format) when this credential expires
	ExpiryDate int64 `json:"expiry_date"`
	// Whether or not this credential has been revoked
	Revoked bool `json:"revoked"`
	// Whether or not revocation is supported for this credential
	RevocationSupported bool `json:"revocation_supported"`
	// Url at which this credential can be issued (if any)
	IssueURL *TranslatedString `json:"issue_url"`
}

type DisclosurePlan struct {
	// What to show during issuance during disclosure.
	// If this is nil then no issuances are required before a valid choice can be made.
	// The disclosure flow then only has one step.
	// When it is present it contains both the credentials that have been added during this flow,
	// as well as the credentials left to issuer in order to proceed. This is done to make it possible to
	// show a correct stepper, even after the session state gets updated.
	// When all are satisfied, the value should still be present in updates to the session state, so the stepper is shown correctly.
	IssueDuringDislosure *IssueDuringDislosure `json:"issue_during_dislosure"`
	// What the user can pick for disclosure. This should never be nil.
	DisclosureChoicesOverview []DisclosurePickOne `json:"disclosure_choices_overview"`
}

// DisclosurePickOne is a discon where the user needs to pick only one credential
// TODO: What to do when there's multiple credentials in the inner con?
// This is possible for singletons in irma condiscon and for anything in DCQL (resulting in condiscondis)
// E.g.: you can ask for both personal data and address in the inner con,
// because they're both singletons and will always result in a single choice.
// But you can't ask for both email and mobilenumber in the inner con,
// because they're not singletons and they could be multiple options, resulting in condiscondis.
type DisclosurePickOne struct {
	// if this is set to true the user can decide to pick none of the options
	// because it isn't required to satisfy the disclosure
	Optional bool `json:"optional"`
	// the user can pick one of these without having to issue
	OwnedOptions []*SelectableCredentialInstance `json:"owned_options"`
	// The user can issue one of these and then use it
	ObtainableOptions []*CredentialDescriptor `json:"obtainable_options"`
}

// IssuanceStep is one step in the issuance wizard during disclosure flow
type IssuanceStep struct {
	// the list of options for the given discon
	// the user can choose which one to issue, but only has to issue one
	Options []*CredentialDescriptor `json:"options"`
}

// IssueDuringDislosure is what to show during issuance during disclosure
type IssueDuringDislosure struct {
	// The steps to fulfill before we can continue the disclosure
	Steps []IssuanceStep `json:"steps"`
	// The set of credential ids that have been issued during this session
	// in order to satisfy the issuance steps.
	IssuedCredentialIds map[string]struct{} `json:"issued_credential_ids"`
}

// SessionState is a snapshot of the state of this session.
// When the session state changes it should create a new instance.
// It has been setup in such a way that it contains all relevant state for
// displaying all stages for this session to the user
type SessionState struct {
	// The identifier for this session
	Id int `json:"id"`
	// The protocol used for this session
	Protocol irmaclient.Protocol `json:"protocol"`
	// The type of session this is
	Type SessionType `json:"type"`
	// In what stage this session currently is
	Status SessionStatus `json:"status"`
	// Who started this session
	Requestor TrustedParty `json:"requestor"`
	// The pairing code to show to the user when the status is pairing
	PairingCode string `json:"pairing_code"`
	// The list of credentials offered to the user. The user has no choice other than accepting or denying them.
	OfferedCredentials []*Credential `json:"offered_credentials"`
	// The plan for disclosing credentials to satisfy this disclosure session
	// Nil when no disclosure has to be done. Can also be present during issuance session.
	DisclosurePlan *DisclosurePlan `json:"disclosure_plan"`
	// The message that should be signed during this session, if any
	MessageToSign string `json:"message_to_sign"`
	// The error when this session has an error
	Error error `json:"error"`
	// The client return url when the app should redirect to after the session, if any
	ClientReturnUrl string `json:"client_return_url"`
	// If this is true then the frontend should not return to the browser after the session is done
	ContinueOnSecondDevice bool `json:"continue_on_second_device"`
	// The number of attempts the user still has to enter a correct pin
	RemainingPinAttempts  int `json:"remaining_pin_attempts"`
	PinBlockedTimeSeconds int `json:"pin_blocked_time_seconds"`
}

type session struct {
	State             *SessionState
	handler           SessionHandler
	permissionHandler irmaclient.PermissionHandler
	pinHandler        irmaclient.PinHandler
	client            *Client
	dismisser         irmaclient.SessionDismisser
	chained           bool
}

func (s *session) dispatchState() {
	s.handler.UpdateSession(*s.State)
}

func (s *session) error(err error) {
	s.State.Status = Status_Error
	s.State.Error = err
	s.dispatchState()
}

type SessionManager struct {
	Sessions       map[int]*session
	NextId         int
	SessionHandler SessionHandler
	Client         *Client
}

func (m *SessionManager) DeleteSession(id int) {
	delete(m.Sessions, id)
}

func (m *SessionManager) NewSession() *session {
	m.NextId += 1
	s := &session{
		State: &SessionState{
			Id: m.NextId,
		},
		handler: m.SessionHandler,
		client:  m.Client,
	}
	m.Sessions[m.NextId] = s
	return s
}

type SessionHandler interface {
	UpdateSession(session SessionState)
}

func (s *session) StatusUpdate(action irma.Action, status irma.ClientStatus) {}

func (s *session) ClientReturnURLSet(clientReturnURL string) {
	s.State.ClientReturnUrl = clientReturnURL
	s.dispatchState()
}

func (s *session) PairingRequired(pairingCode string) {
	s.State.Status = Status_ShowPairingCode
	s.State.PairingCode = pairingCode
	s.dispatchState()
}

func (s *session) Success(result string) {
	s.State.Status = Status_Success
	s.dispatchState()
}

func (s *session) Cancelled() {
	s.State.Status = Status_Dismissed
	s.dispatchState()
}

func (s *session) Failure(err *irma.SessionError) {
	s.error(err)
}

func (s *session) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	s.State.PinBlockedTimeSeconds = duration
	s.error(fmt.Errorf("session blocked for %v seconds for scheme '%s'", duration, manager))
}

func (s *session) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	s.error(fmt.Errorf("keyshare enrollment is missing for scheme: '%s'", manager))
}

func requestorInfoToTrustedParty(info *irma.RequestorInfo) TrustedParty {
	return TrustedParty{
		Id:        info.ID.String(),
		Name:      TranslatedString(info.Name),
		ImagePath: info.Logo,
		Parent:    nil,
		Verified:  !info.Unverified,
	}
}

func (s *session) RequestIssuancePermission(
	request *irma.IssuanceRequest,
	satisfiable bool,
	candidates [][]irmaclient.DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback irmaclient.PermissionHandler,
) {
	// if the session type wasn't an issuance session before
	// we can assume this session to be chained and we can cache that for future permission requests
	if s.State.Type != "" && s.State.Type != Type_Issuance {
		s.chained = true
	}

	irmaConfig := s.client.GetIrmaConfiguration()
	creds := request.CredentialInfoList

	offeredCredentials, err := credentialInfoListToSchemaless(irmaConfig, creds)

	if err != nil {
		s.error(err)
		return
	}

	credentials, err := s.client.GetCredentials()
	if err != nil {
		s.error(err)
		return
	}

	// if the session is a chained session and the previous type was disclosure
	// we don't want to update the disclosure plan and instead make a new one
	// if the current (issuance) session has any disclosures
	if s.chained && s.State.Type != Type_Issuance {
		s.State.DisclosurePlan = nil
	} else {
		newPlan, err := createDisclosurePlan(s.State.DisclosurePlan, s.client.irmaClient.Configuration, credentials, candidates)
		if err != nil {
			s.error(err)
			return
		}

		s.State.DisclosurePlan = newPlan
	}

	s.State.OfferedCredentials = offeredCredentials
	s.State.Status = Status_RequestPermission
	s.permissionHandler = callback
	s.State.Protocol = irmaclient.Protocol_Irma
	s.State.Requestor = requestorInfoToTrustedParty(requestorInfo)
	s.State.Type = Type_Issuance

	s.dispatchState()
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

func createIssuanceSteps(
	irmaConfig *irma.Configuration,
	credentials []*Credential,
	candidates [][]irmaclient.DisclosureCandidates,
) ([]IssuanceStep, error) {
	// for each disjunction that is not satisfiable we need to give the user the option to select
	// from any of the options (inner cons) beloning to that disjunction
	unsatisfiedDisjunctionIndices := []int{}
	result := []IssuanceStep{}

	for i, discon := range candidates {
		disconSatisfied := false
		for _, con := range discon {
			conSatisfied := true
			for _, attr := range con {
				if findCredential(credentials, attr.CredentialHash) == nil {
					conSatisfied = false
				}
			}
			if conSatisfied {
				disconSatisfied = true
			}
		}
		if !disconSatisfied {
			unsatisfiedDisjunctionIndices = append(unsatisfiedDisjunctionIndices, i)
		}
	}

	for _, i := range unsatisfiedDisjunctionIndices {
		discon := candidates[i]
		options := []*CredentialDescriptor{}
		for _, con := range discon {
			descriptor, err := createCredentialDescriptor(irmaConfig, con)
			if err != nil {
				return nil, err
			}
			options = append(options, descriptor)
		}
		result = append(result, IssuanceStep{
			Options: options,
		})
	}

	return result, nil
}

func createDisclosureChoicesOverview(
	irmaConfig *irma.Configuration,
	credentials []*Credential,
	candidates [][]irmaclient.DisclosureCandidates,
) ([]DisclosurePickOne, error) {
	result := []DisclosurePickOne{}
	// for each discon we create a disclosure pick one
	for _, discon := range candidates {
		choice := DisclosurePickOne{}

		choiceTemplates := map[string]*CredentialDescriptor{}        // key: credentialId
		filteredByHash := map[string]*SelectableCredentialInstance{} // key: credentialHash

		for _, con := range discon {
			// if at least one of the cons inside of a discon is empty
			// then the discon is satisfiable by picking no credentials at all
			// therefore the choice is optional
			if len(con) == 0 {
				choice.Optional = true
			}
			for _, attr := range con {
				hash := attr.AttributeIdentifier.CredentialHash

				if hash == "" {
					t := attr.CredentialIdentifier().Type
					id := t.String()

					// Ensure template exists once per type in this choice
					if _, ok := choiceTemplates[id]; !ok {
						descriptor, err := getCredentialDescriptor(irmaConfig, t)
						if err != nil {
							return nil, err
						}
						choiceTemplates[id] = descriptor
						choice.ObtainableOptions = append(choice.ObtainableOptions, descriptor)
					}
				} else {
					// Present attribute => owned credential instance (but we filter attributes)
					orig := findCredential(credentials, hash)
					if orig == nil {
						return nil, fmt.Errorf("failed to find credential for hash: %v", hash)
					}

					// Get or create filtered instance for this credential hash
					f, ok := filteredByHash[hash]
					if !ok {
						cp := *orig
						f = &cp
						f.Attributes = []Attribute{}
						filteredByHash[hash] = f
					}

					// TODO: make this more independent and compatible with more complex claim paths
					attrID := attr.AttributeIdentifier
					val, ok := lookupAttrValue(orig, attrID)
					if !ok {
						return nil, fmt.Errorf("credential %s does not contain attribute %v", hash, attrID)
					}

					f.Attributes = append(f.Attributes, val)
				}
			}
		}
		// Replace OwnedOptions with the filtered instances (only requested attrs)
		for _, inst := range filteredByHash {
			choice.OwnedOptions = append(choice.OwnedOptions, inst)
		}
		result = append(result, choice)
	}

	return result, nil
}

// returns the list of issued credential ids compared to the steps
// and whether the steps are satisfied
func getIssuedSinceOriginalPlan(
	steps []IssuanceStep,
	allCredentials []*Credential,
) (issued map[string]struct{}, satisfied bool) {
	issued = map[string]struct{}{}
	numSatisfiedSteps := 0

	for _, step := range steps {
		for _, option := range step.Options {
			index := slices.IndexFunc(
				allCredentials,
				func(c *Credential) bool {
					if c.CredentialId != option.CredentialId {
						return false
					}
					// now check if it satisfies the values specified in the previous issuance step
					attsStatisfied, _ := SatisfiesRequestedAttributes(c.Attributes, option.Attributes)
					return attsStatisfied
				},
			)
			// credential has been issued
			if index >= 0 {
				issued[option.CredentialId] = struct{}{}
				numSatisfiedSteps += 1
				continue
			}
		}
	}

	satisfied = numSatisfiedSteps == len(steps)
	return
}

func createDisclosurePlan(
	oldDisclosurePlan *DisclosurePlan,
	irmaConfig *irma.Configuration,
	credentials []*Credential,
	candidates [][]irmaclient.DisclosureCandidates,
) (*DisclosurePlan, error) {
	newPlan := &DisclosurePlan{}
	// there's no plan yet, so make a new one
	if oldDisclosurePlan == nil {
		issuanceSteps, err := createIssuanceSteps(irmaConfig, credentials, candidates)
		if err != nil {
			return nil, fmt.Errorf("failed to create issuance steps: %w", err)
		}

		// the current disclosure flow is not satisfyable without issuance
		if len(issuanceSteps) != 0 {
			return &DisclosurePlan{
				IssueDuringDislosure: &IssueDuringDislosure{
					IssuedCredentialIds: map[string]struct{}{},
					Steps:               issuanceSteps,
				},
			}, nil
		}
	} else {
		// update the existing issuance plan if it exists
		lastIssuancePlan := oldDisclosurePlan.IssueDuringDislosure
		if lastIssuancePlan != nil {
			issued, satisfied := getIssuedSinceOriginalPlan(lastIssuancePlan.Steps, credentials)
			newPlan.IssueDuringDislosure = &IssueDuringDislosure{
				Steps:               lastIssuancePlan.Steps,
				IssuedCredentialIds: issued,
			}

			// still not satisfied, so no disclosure overview should be made
			// return the old issuance steps with the credentials issued since starting the session
			if !satisfied {
				return newPlan, nil
			}
		}
	}

	// if the request is satisfiable we can continue to the next stage: picking disclosure choices
	disclosureChoices, err := createDisclosureChoicesOverview(irmaConfig, credentials, candidates)
	if err != nil {
		return nil, fmt.Errorf("failed to create disclosure choices overview: %w", err)
	}
	newPlan.DisclosureChoicesOverview = disclosureChoices
	return newPlan, nil
}

func lookupAttrValue(orig *SelectableCredentialInstance, id *irma.AttributeIdentifier) (Attribute, bool) {
	index := slices.IndexFunc(orig.Attributes, func(att Attribute) bool {
		return att.Id == id.Type.Name()
	})
	if index >= 0 {
		return orig.Attributes[index], true
	}
	return Attribute{}, false
}

func (s *session) RequestVerificationPermission(
	request *irma.DisclosureRequest,
	satisfiable bool,
	candidates [][]irmaclient.DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback irmaclient.PermissionHandler,
) {
	s.State.Status = Status_RequestPermission
	s.State.Type = Type_Disclosure
	s.permissionHandler = callback
	s.State.Requestor = requestorInfoToTrustedParty(requestorInfo)
	s.State.OfferedCredentials = nil

	creds, err := s.client.GetCredentials()
	if err != nil {
		s.error(err)
		return
	}

	newPlan, err := createDisclosurePlan(s.State.DisclosurePlan, s.client.irmaClient.Configuration, creds, candidates)
	if err != nil {
		s.error(err)
		return
	}

	s.State.DisclosurePlan = newPlan

	s.dispatchState()
}

func (s *session) RequestSignaturePermission(request *irma.SignatureRequest,
	satisfiable bool,
	candidates [][]irmaclient.DisclosureCandidates,
	requestorInfo *irma.RequestorInfo,
	callback irmaclient.PermissionHandler) {
	s.State.Status = Status_RequestPermission
	s.State.Type = Type_Signature
	s.State.Requestor = requestorInfoToTrustedParty(requestorInfo)
	s.permissionHandler = callback
	s.State.OfferedCredentials = nil

	creds, err := s.client.GetCredentials()
	if err != nil {
		s.error(err)
		return
	}

	newPlan, err := createDisclosurePlan(s.State.DisclosurePlan, s.client.irmaClient.Configuration, creds, candidates)
	if err != nil {
		s.error(err)
		return
	}

	s.State.DisclosurePlan = newPlan
	s.State.MessageToSign = request.Message

	s.dispatchState()
}

func (s *session) RequestAuthorizationCodeFlowPermission(
	request *irma.AuthorizationCodeFlowRequest,
	requestorInfo *irma.RequestorInfo,
	callback irmaclient.CodeHandler,
) {
}

func (s *session) RequestPreAuthorizedCodeFlowPermission(
	request *irma.PreAuthorizedCodeFlowPermissionRequest,
	requestorInfo *irma.RequestorInfo,
	callback irmaclient.TokenPermissionHandler,
) {
}

func (s *session) RequestPin(remainingAttempts int, callback irmaclient.PinHandler) {
	s.State.Status = Status_RequestPin
	s.State.RemainingPinAttempts = remainingAttempts
	s.pinHandler = callback
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
		session.permissionHandler(payload.Granted, choices)
	case UI_EnteredPin:
		payload := userInteraction.Payload.(PinInteractionPayload)
		session.pinHandler(payload.Proceed, payload.Pin)
	case UI_DismissSession:
		session.dismisser.Dismiss()
	}

	return nil
}

func (client *Client) NewSession(sessionrequest string) {
	session := client.SessionManager.NewSession()
	state := session.State

	var sessionReq SessionRequestData
	err := json.Unmarshal([]byte(sessionrequest), &sessionReq)
	if err != nil {
		irma.Logger.Errorf("failed to parse session request: %v\n", err)
		session.error(err)
		client.SessionManager.DeleteSession(session.State.Id)
		return
	}

	state.Protocol = sessionReq.Protocol
	state.ContinueOnSecondDevice = sessionReq.ContinueOnSecondDevice

	switch sessionReq.Type {
	case irma.ActionDisclosing:
		state.Type = Type_Disclosure
	case irma.ActionIssuing:
		state.Type = Type_Issuance
	case irma.ActionSigning:
		state.Type = Type_Signature
	}

	session.dismisser = client.newSession(sessionrequest, session)
}
