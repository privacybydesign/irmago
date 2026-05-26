package client

import (
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
)

// openid4vpSessionAdapter adapts the session struct to the openid4vp client's Handler interface.
type openid4vpSessionAdapter struct {
	session *session
}

func (a *openid4vpSessionAdapter) Failure(err *clientmodels.SessionError) {
	a.session.State.Status = clientmodels.Status_Error
	a.session.State.Error = err
	a.session.dispatchState()
}

func (a *openid4vpSessionAdapter) Cancelled() {
	a.session.State.Status = clientmodels.Status_Dismissed
	a.session.dispatchState()
}

func (a *openid4vpSessionAdapter) Success(result string, credentialLogs []clientmodels.LogCredential) {
	eudi.Logger.Infof("openid4vp session success: %s", result)

	// Store the disclosure log in the EUDI SQLCipher database. We log even when
	// no credentials were shared (all-optional sets skipped by the user) so the
	// user can still see which verifier they had a session with.
	logService := services.NewEudiLogService(a.session.client.eudiStorage)
	if err := logService.AddDisclosureLog(a.session.State.Requestor, credentialLogs); err != nil {
		eudi.Logger.Errorf("failed to store openid4vp disclosure log: %v", err)
	}

	a.session.State.Status = clientmodels.Status_Success
	a.session.dispatchState()
}

func (a *openid4vpSessionAdapter) RequestVerificationPermission(
	disclosurePlan *clientmodels.DisclosurePlan,
	requestor *clientmodels.TrustedParty,
	hashToQueryId map[string]string,
	callback openid4vp.PermissionHandler,
) {
	a.session.State.Status = clientmodels.Status_RequestPermission
	a.session.State.Type = clientmodels.Type_Disclosure
	a.session.State.Protocol = clientmodels.Protocol_OpenID4VP
	if requestor != nil {
		a.session.State.Requestor = *requestor
	}
	// Detect WrongCredentialIssued if issuance-during-disclosure is active
	if disclosurePlan.IssueDuringDisclosure != nil {
		detectWrongCredentialIssued(a.session, disclosurePlan)
	}

	a.session.State.DisclosurePlan = disclosurePlan
	a.session.openid4vpPermissionHandler = callback
	a.session.openid4vpHashToQueryId = hashToQueryId
	a.session.dispatchState()
}

// disclosureChoicesToOpenID4VPSelections converts UI disclosure choices to OpenID4VP selections.
func disclosureChoicesToOpenID4VPSelections(choices []clientmodels.DisclosureDisconSelection, hashToQueryId map[string]string) []dcql.DisclosureSelection {
	var selections []dcql.DisclosureSelection
	for _, discon := range choices {
		for _, cred := range discon.Credentials {
			claimPaths := make([][]any, 0, len(cred.AttributePaths))
			for _, path := range cred.AttributePaths {
				if len(path) > 0 {
					claimPaths = append(claimPaths, path)
				}
			}
			queryId := hashToQueryId[cred.CredentialHash]
			selections = append(selections, dcql.DisclosureSelection{
				QueryId:        queryId,
				CredentialHash: cred.CredentialHash,
				ClaimPaths:     claimPaths,
			})
		}
	}
	return selections
}

// detectWrongCredentialIssued checks if any newly issued credential matches a required
// type but has wrong attribute values. Uses the client's full credential list.
func detectWrongCredentialIssued(s *session, plan *clientmodels.DisclosurePlan) {
	if plan.IssueDuringDisclosure == nil {
		return
	}

	allCreds, err := s.client.GetCredentials()
	if err != nil {
		return
	}

	s.snapshotPreExistingCredentials(allCreds)

	var previousWrongHash string
	if plan.IssueDuringDisclosure.WrongCredentialIssued != nil {
		previousWrongHash = plan.IssueDuringDisclosure.WrongCredentialIssued.Hash
	}

	for _, step := range plan.IssueDuringDisclosure.Steps {
		stepSatisfied := false
		var wrongForStep *clientmodels.Credential

		for _, bundle := range step.Options {
			for _, desc := range bundle.Credentials {
				for _, cred := range allCreds {
					if cred.CredentialId != desc.CredentialId {
						continue
					}
					_, preExisting := s.preExistingCredentialHashes[cred.Hash]
					if preExisting {
						continue
					}
					// This credential is new and matches the type. Check if values match.
					wrong := checkWrongCredential(cred, desc)
					if wrong != nil {
						if cred.Hash != previousWrongHash {
							wrongForStep = wrong
						}
					} else {
						stepSatisfied = true
					}
				}
			}
		}

		// Only report wrong credential if the step is not satisfied by a correct one
		if !stepSatisfied && wrongForStep != nil {
			plan.IssueDuringDisclosure.WrongCredentialIssued = wrongForStep
			return
		}
	}
}

// checkWrongCredential returns a Credential with only the mismatched attributes if
// the credential's values don't satisfy the requested values.
func checkWrongCredential(cred *clientmodels.Credential, option *clientmodels.CredentialDescriptor) *clientmodels.Credential {
	ok, _ := SatisfiesRequestedAttributes(cred.Attributes, option.Attributes)
	if ok {
		return nil
	}

	// Build a credential with only the mismatched attributes
	var mismatched []clientmodels.Attribute
	requestedByID := make(map[string]*clientmodels.Attribute)
	for i := range option.Attributes {
		requestedByID[clientmodels.ClaimPathKey(option.Attributes[i].ClaimPath)] = &option.Attributes[i]
	}

	for _, attr := range cred.Attributes {
		req, ok := requestedByID[clientmodels.ClaimPathKey(attr.ClaimPath)]
		if !ok || req.RequestedValue == nil || !req.RequestedValue.HasValue() {
			continue
		}
		satisfied, _ := SatisfiesRequestedAttributes([]clientmodels.Attribute{attr}, []clientmodels.Attribute{*req})
		if !satisfied {
			mismatched = append(mismatched, clientmodels.Attribute{
				ClaimPath:      attr.ClaimPath,
				DisplayName:    attr.DisplayName,
				Description:    attr.Description,
				Value:          attr.Value,
				RequestedValue: req.RequestedValue,
			})
		}
	}

	if len(mismatched) == 0 {
		return nil
	}

	return &clientmodels.Credential{
		CredentialId: cred.CredentialId,
		Hash:         cred.Hash,
		Attributes:   mismatched,
	}
}
