package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	openid4vpclient "github.com/privacybydesign/irmago/eudi/openid4vp/client"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

// Interaction type aliases: canonical definitions live in common/clientmodels.
type UserInteractionType = clientmodels.UserInteractionType
type SessionUserInteraction = clientmodels.SessionUserInteraction
type SessionPermissionInteractionPayload = clientmodels.SessionPermissionInteractionPayload
type SelectedCredential = clientmodels.SelectedCredential
type DisclosureDisconSelection = clientmodels.DisclosureDisconSelection
type PinInteractionPayload = clientmodels.PinInteractionPayload
type SessionAuthCodeInteractionPayload = clientmodels.SessionAuthCodeInteractionPayload
type SessionPreAuthorizedCodeInteractionPayload = clientmodels.SessionPreAuthorizedCodeInteractionPayload

const (
	UI_EnteredPin        = clientmodels.UI_EnteredPin
	UI_Permission        = clientmodels.UI_Permission
	UI_DismissSession    = clientmodels.UI_DismissSession
	UI_AuthorizationCode = clientmodels.UI_AuthorizationCode
	UI_PreAuthorizedCode = clientmodels.UI_PreAuthorizedCode
)

// Type aliases: canonical definitions live in common/clientmodels.
type SessionStatus = clientmodels.SessionStatus
type SessionType = clientmodels.SessionType
type SelectableCredentialInstance = clientmodels.SelectableCredentialInstance
type DisclosurePlan = clientmodels.DisclosurePlan
type DisclosurePickOne = clientmodels.DisclosurePickOne
type IssuanceStep = clientmodels.IssuanceStep
type IssueDuringDislosure = clientmodels.IssueDuringDislosure
type SessionState = clientmodels.SessionState
type SessionError = clientmodels.SessionError
type SessionHandler = clientmodels.SessionHandler

const (
	Status_RequestPermission        = clientmodels.Status_RequestPermission
	Status_ShowPairingCode          = clientmodels.Status_ShowPairingCode
	Status_Success                  = clientmodels.Status_Success
	Status_Error                    = clientmodels.Status_Error
	Status_Dismissed                = clientmodels.Status_Dismissed
	Status_RequestPin               = clientmodels.Status_RequestPin
	Status_RequestPreAuthorizedCode = clientmodels.Status_RequestPreAuthorizedCode
	Status_RequestAuthorizationCode = clientmodels.Status_RequestAuthorizationCode

	Type_Disclosure = clientmodels.Type_Disclosure
	Type_Issuance   = clientmodels.Type_Issuance
	Type_Signature  = clientmodels.Type_Signature
)

type session struct {
	State                      *SessionState
	handler                    SessionHandler
	permissionHandler          irmaclient.PermissionHandler
	pinHandler                 irmaclient.PinHandler
	client                     *Client
	dismisser                  irmaclient.SessionDismisser
	chained                    bool
	authCodeHandler            openid4vci.AuthCodeHandler
	preAuthorizedCodeHandler   openid4vci.TokenPermissionHandler
	openid4vpPermissionHandler openid4vpclient.PermissionHandler
	// Hashes of credentials that already existed when the disclosure plan was first created.
	// Used to exclude pre-existing credentials from WrongCredentialIssued detection.
	preExistingCredentialHashes map[string]struct{}
}

func (s *session) dispatchState() {
	s.handler.UpdateSession(*s.State)
}

// snapshotPreExistingCredentials records the hashes of all credentials that exist
// before issuance-during-disclosure begins. Only called once per session; subsequent
// calls are no-ops so the snapshot reflects the state at plan creation time.
func (s *session) snapshotPreExistingCredentials(credentials []*Credential) {
	if s.preExistingCredentialHashes != nil {
		return
	}
	s.preExistingCredentialHashes = make(map[string]struct{}, len(credentials))
	for _, c := range credentials {
		s.preExistingCredentialHashes[c.Hash] = struct{}{}
	}
}

func (s *session) error(err error) {
	s.State.Status = Status_Error
	var irmaErr *irma.SessionError
	if errors.As(err, &irmaErr) {
		s.State.Error = clientmodels.NewSessionError(irmaErr)
	} else {
		s.State.Error = clientmodels.NewSessionError(&irma.SessionError{Err: err, ErrorType: irma.ErrorApi, Info: err.Error()})
	}
	s.dispatchState()
}

type sessionManager struct {
	Sessions       map[int]*session
	NextId         int
	SessionHandler SessionHandler
	Client         *Client
}

func (m *sessionManager) Clear() {
	m.Sessions = map[int]*session{}
	m.NextId = 0
}

func (m *sessionManager) DeleteSession(id int) {
	delete(m.Sessions, id)
}

func (m *sessionManager) NewSession() *session {
	// TODO: use locking here to update the session ID
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
	s.State.PinBlockedTimeSeconds = &duration
	s.State.Status = Status_RequestPin
	s.dispatchState()
}

func (s *session) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	s.error(fmt.Errorf("keyshare enrollment is missing for scheme: '%s'", manager))
}

func requestorInfoToTrustedParty(info *irma.RequestorInfo) TrustedParty {
	return TrustedParty{
		Id:        info.ID.String(),
		Name:      TranslatedString(info.Name),
		ImagePath: info.LogoPath,
		Parent:    nil,
		Verified:  !info.Unverified,
	}
}

func requestorInfoToTrustedPartyPtr(info *irma.RequestorInfo) *TrustedParty {
	if info == nil {
		return nil
	}
	tp := requestorInfoToTrustedParty(info)
	return &tp
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

	irmaConfig := s.client.irmaClient.Configuration
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

	// if the session is a chained session and the previous type was disclosure or signature
	// we don't want to update the disclosure plan and instead make a new one
	// if the current (issuance) session has any disclosures
	if s.chained && s.State.Type != Type_Issuance {
		s.State.DisclosurePlan = nil
	} else {
		s.snapshotPreExistingCredentials(credentials)
		newPlan, err := createDisclosurePlan(s.State.DisclosurePlan, irmaConfig, credentials, candidates, s.preExistingCredentialHashes)
		if err != nil {
			s.error(err)
			return
		}

		s.State.DisclosurePlan = newPlan
	}

	// Filter out random blind attributes from offered credentials,
	// as they are generated by the protocol and not meaningful to the user during issuance permission.
	filterRandomBlindAttributes(irmaConfig, offeredCredentials)

	s.State.OfferedCredentials = offeredCredentials
	s.State.Status = Status_RequestPermission
	s.permissionHandler = callback
	s.State.Protocol = irmaclient.Protocol_Irma
	s.State.Requestor = requestorInfoToTrustedParty(requestorInfo)
	s.State.Type = Type_Issuance

	s.dispatchState()
}

// filterRandomBlindAttributes removes random blind attributes from offered credentials.
// These attributes are generated by the issuance protocol and have no user-meaningful value
// at issuance permission time.
func filterRandomBlindAttributes(irmaConfig *irma.Configuration, credentials []*Credential) {
	for _, cred := range credentials {
		credTypeID := irma.NewCredentialTypeIdentifier(cred.CredentialId)
		credType, ok := irmaConfig.CredentialTypes[credTypeID]
		if !ok {
			continue
		}
		randomBlindIDs := make(map[string]struct{})
		for _, at := range credType.AttributeTypes {
			if at.RandomBlind {
				randomBlindIDs[at.ID] = struct{}{}
			}
		}
		if len(randomBlindIDs) == 0 {
			continue
		}
		filtered := make([]Attribute, 0, len(cred.Attributes))
		for _, attr := range cred.Attributes {
			if _, isBlind := randomBlindIDs[attr.Id]; !isBlind {
				filtered = append(filtered, attr)
			}
		}
		cred.Attributes = filtered
	}
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
		ownedOrder := []string{}                                     // preserves insertion order of hashes

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

					// Populate RequestedValue for the requested attribute
					attrName := attr.AttributeIdentifier.Type.Name()
					for i := range choiceTemplates[id].Attributes {
						if choiceTemplates[id].Attributes[i].Id == attrName {
							requestedValue := &AttributeValue{
								Type: AttributeType_TranslatedString,
							}
							if attr.Value != nil {
								requestedValue.TranslatedString = convertOptionalTranslatedString(&attr.Value)
							}
							choiceTemplates[id].Attributes[i].RequestedValue = requestedValue
							break
						}
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
						ownedOrder = append(ownedOrder, hash)
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
		// Collect OwnedOptions in the order candidates were encountered.
		for _, hash := range ownedOrder {
			choice.OwnedOptions = append(choice.OwnedOptions, filteredByHash[hash])
		}
		result = append(result, choice)
	}

	return result, nil
}

// returns the list of issued credential ids compared to the steps,
// the most recently issued credential with the right type but wrong attribute values
// (only for unsatisfied steps), and whether the steps are satisfied.
// preExistingHashes contains hashes of credentials that existed before the disclosure session,
// which are excluded from wrong credential detection.
// previousWrongHash is the hash of the wrong credential from the previous plan update,
// used to prefer a newer wrong credential when issuance dates are equal.
func getIssuedSinceOriginalPlan(
	steps []IssuanceStep,
	allCredentials []*Credential,
	preExistingHashes map[string]struct{},
	previousWrongHash string,
) (issued map[string]struct{}, lastWrongCredential *Credential, satisfied bool) {
	issued = map[string]struct{}{}
	numSatisfiedSteps := 0

	for _, step := range steps {
		stepSatisfied := false
		for _, option := range step.Options {
			hasSatisfyingMatch := false
			for _, c := range allCredentials {
				if c.CredentialId != option.CredentialId {
					continue
				}
				// now check if it satisfies the values specified in the previous issuance step
				attsStatisfied, _ := SatisfiesRequestedAttributes(c.Attributes, option.Attributes)
				if attsStatisfied {
					hasSatisfyingMatch = true
					break
				}
				// Skip credentials that existed before the disclosure session started;
				// only credentials issued during this session should be reported as wrong.
				if _, preExisting := preExistingHashes[c.Hash]; preExisting {
					continue
				}
				// A credential with the right type exists but has wrong attribute values.
				// Keep the most recently issued one so the frontend can show it.
				// When issuance dates are equal, prefer a credential that differs from the
				// previously reported wrong credential, as it is more likely to be newly issued.
				if lastWrongCredential == nil || c.IssuanceDate > lastWrongCredential.IssuanceDate {
					lastWrongCredential = filterCredentialToMismatchedAttributes(c, option.Attributes)
				} else if c.IssuanceDate == lastWrongCredential.IssuanceDate &&
					lastWrongCredential.Hash == previousWrongHash && c.Hash != previousWrongHash {
					lastWrongCredential = filterCredentialToMismatchedAttributes(c, option.Attributes)
				}
			}
			if hasSatisfyingMatch {
				issued[option.CredentialId] = struct{}{}
				stepSatisfied = true
			}
		}
		if stepSatisfied {
			numSatisfiedSteps += 1
			// Clear the wrong credential if this step is now satisfied
			lastWrongCredential = nil
		}
	}

	satisfied = numSatisfiedSteps == len(steps)
	return
}

// filterCredentialToMismatchedAttributes returns a copy of the credential containing only
// the attributes that have a pre-defined requested value that doesn't match the credential's
// actual value. Each included attribute gets the RequestedValue from the option so the
// frontend can show both the actual and expected values side by side.
func filterCredentialToMismatchedAttributes(cred *Credential, requestedAttrs []Attribute) *Credential {
	requestedByID := make(map[string]*Attribute, len(requestedAttrs))
	for i := range requestedAttrs {
		requestedByID[requestedAttrs[i].Id] = &requestedAttrs[i]
	}

	var filtered []Attribute
	for _, attr := range cred.Attributes {
		req, ok := requestedByID[attr.Id]
		if !ok || req.RequestedValue == nil || !req.RequestedValue.HasValue() {
			continue
		}
		// Check if the actual value doesn't match the requested value
		satisfied, _ := SatisfiesRequestedAttributes(
			[]Attribute{attr},
			[]Attribute{*req},
		)
		if !satisfied {
			filtered = append(filtered, Attribute{
				Id:             attr.Id,
				DisplayName:    attr.DisplayName,
				Description:    attr.Description,
				Value:          attr.Value,
				RequestedValue: req.RequestedValue,
			})
		}
	}

	result := *cred
	result.Attributes = filtered
	return &result
}

func createDisclosurePlan(
	oldDisclosurePlan *DisclosurePlan,
	irmaConfig *irma.Configuration,
	credentials []*Credential,
	candidates [][]irmaclient.DisclosureCandidates,
	preExistingCredentialHashes map[string]struct{},
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
			var previousWrongHash string
			if lastIssuancePlan.WrongCredentialIssued != nil {
				previousWrongHash = lastIssuancePlan.WrongCredentialIssued.Hash
			}
			issued, lastWrongCredential, satisfied := getIssuedSinceOriginalPlan(
				lastIssuancePlan.Steps, credentials, preExistingCredentialHashes, previousWrongHash,
			)
			newPlan.IssueDuringDislosure = &IssueDuringDislosure{
				Steps:                 lastIssuancePlan.Steps,
				IssuedCredentialIds:   issued,
				WrongCredentialIssued: lastWrongCredential,
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

	s.snapshotPreExistingCredentials(creds)
	newPlan, err := createDisclosurePlan(s.State.DisclosurePlan, s.client.irmaClient.Configuration, creds, candidates, s.preExistingCredentialHashes)
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
	callback irmaclient.PermissionHandler,
) {
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

	s.snapshotPreExistingCredentials(creds)
	newPlan, err := createDisclosurePlan(s.State.DisclosurePlan, s.client.irmaClient.Configuration, creds, candidates, s.preExistingCredentialHashes)
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
	callback openid4vci.AuthCodeHandler,
) {
	s.setPseudoRandomOpenIdState()

	// Add the state to the authorization parameters so it will be send to the authorization server and back to us, to verify the response belongs to this session
	request.AuthorizationParameters.Add("state", s.State.Oid4VciState)

	// Construct the URL that the client should open in the browser to start the authorization code flow
	authRequestUrl, err := url.Parse(request.AuthorizationEndpoint)
	if err != nil {
		panic(fmt.Errorf("failed to parse authorization endpoint URL: %v", err))
	}
	authRequestUrl.RawQuery = request.AuthorizationParameters.Encode()

	s.State.Status = Status_RequestAuthorizationCode
	s.State.Type = Type_Issuance
	s.State.OfferedCredentialTypes = credentialTypeInfoListToSchemaless(request.CredentialTypeInfoList)
	s.State.Requestor = requestorInfoToTrustedParty(requestorInfo)
	s.State.AuthorizationRequestUrl = authRequestUrl.String()
	s.authCodeHandler = callback

	// Quick fix for OID4VCI flow, to open the correct success-screen after issuance
	s.State.ContinueOnSecondDevice = true

	s.dispatchState()
}

func (s *session) setPseudoRandomOpenIdState() {
	if len(s.State.StateSalt) == 0 {
		salt := [16]byte{}
		_, err := rand.Read(salt[:])
		if err != nil {
			panic(fmt.Sprintf("failed to generate random state salt: %v", err))
		}

		s.State.StateSalt = salt[:]
	}

	stateBytes := append(s.State.StateSalt, []byte(strconv.Itoa(s.State.Id))...)

	s.State.Oid4VciState = fmt.Sprintf("%x", sha256.Sum256(stateBytes))
}

func (s *session) RequestPreAuthorizedCodeFlowPermission(
	request *irma.PreAuthorizedCodeFlowPermissionRequest,
	requestorInfo *irma.RequestorInfo,
	callback openid4vci.TokenPermissionHandler,
) {
	s.State.Status = Status_RequestPreAuthorizedCode
	s.State.Type = Type_Issuance
	s.State.OfferedCredentialTypes = credentialTypeInfoListToSchemaless(request.CredentialTypeInfoList)
	s.State.Requestor = requestorInfoToTrustedParty(requestorInfo)
	s.State.TransactionCodeParameters = request.TransactionCodeParameters
	s.preAuthorizedCodeHandler = callback

	// Quick fix for OID4VCI flow, to open the correct success-screen after issuance
	s.State.ContinueOnSecondDevice = true

	s.dispatchState()
}

func (s *session) RequestPin(remainingAttempts int, callback irmaclient.PinHandler) {
	s.State.Status = Status_RequestPin
	if remainingAttempts >= 0 {
		s.State.RemainingPinAttempts = &remainingAttempts
	} else {
		s.State.RemainingPinAttempts = nil
	}
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
	session, ok := client.sessionManager.Sessions[userInteraction.SessionId]
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
		// Ensure the session is always marked as dismissed, regardless of protocol.
		// Some protocol implementations (e.g. OpenID4VP) don't call Cancelled() from Dismiss().
		if session.State.Status != Status_Dismissed {
			session.State.Status = Status_Dismissed
			session.dispatchState()
		}
	case UI_PreAuthorizedCode:
		payload := userInteraction.Payload.(SessionPreAuthorizedCodeInteractionPayload)
		session.preAuthorizedCodeHandler(payload.Proceed, payload.TransactionCode)
	case UI_AuthorizationCode:
		payload := userInteraction.Payload.(SessionAuthCodeInteractionPayload)
		session.authCodeHandler(payload.Proceed, payload.Code)
	}

	return nil
}

func (client *Client) NewSession(sessionrequest string) {
	session := client.sessionManager.NewSession()
	state := session.State

	var sessionReq SessionRequestData
	err := json.Unmarshal([]byte(sessionrequest), &sessionReq)
	if err != nil {
		irma.Logger.Errorf("failed to parse session request: %v\n", err)
		session.error(err)
		client.sessionManager.DeleteSession(session.State.Id)
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

	switch sessionReq.Protocol {
	case irmaclient.Protocol_OpenID4VP:
		session.dismisser = client.openid4vpClient.NewSession(sessionReq.URL, &openid4vpSessionAdapter{session: session})
	case irmaclient.Protocol_OpenID4VCI:
		session.dismisser = client.openid4vciClient.NewSession(sessionReq.URL, session)
	default:
		session.dismisser = client.irmaClient.NewSession(sessionrequest, session)
	}
}
