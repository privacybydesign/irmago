package wallet

import (
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// Policy decides, without user interaction, how the wallet responds to issuance
// offers and disclosure requests. Implementations must be safe for the wallet's
// sequential session use.
type Policy interface {
	// ApproveIssuance reports whether the offered credentials may be added to
	// the wallet. requestor may be nil when the issuer could not be identified.
	ApproveIssuance(offered []*clientmodels.Credential, requestor *clientmodels.TrustedParty) bool

	// TransactionCode supplies a pre-authorized-code tx_code when the issuer
	// requires one. Return ("", false) when none is available.
	TransactionCode() (string, bool)

	// ApproveDisclosure selects which credentials/claims to disclose for the
	// given plan. Returning ok=false denies the request. The returned
	// selections are passed verbatim to the OpenID4VP client.
	ApproveDisclosure(plan *clientmodels.DisclosurePlan, requestor *clientmodels.TrustedParty, hashToQueryID map[string]string) (selections []dcql.DisclosureSelection, ok bool)
}

// AutoApprovePolicy approves every issuance offer and satisfies every disclosure
// request by picking, for each required disjunction, the first fully-owned
// bundle and disclosing exactly the claims that bundle carries. It never
// supplies a transaction code (use a custom policy for pre-auth flows that need
// one). Intended for demos and tests.
type AutoApprovePolicy struct{}

func (AutoApprovePolicy) ApproveIssuance([]*clientmodels.Credential, *clientmodels.TrustedParty) bool {
	return true
}

func (AutoApprovePolicy) TransactionCode() (string, bool) { return "", false }

func (AutoApprovePolicy) ApproveDisclosure(plan *clientmodels.DisclosurePlan, _ *clientmodels.TrustedParty, hashToQueryID map[string]string) ([]dcql.DisclosureSelection, bool) {
	return selectMinimalOwned(plan, hashToQueryID)
}

// FuncPolicy adapts plain functions to the Policy interface, so callers (e.g. a
// CLI) can supply an interactive transaction code or an allow-list without
// defining a new type. Any nil field falls back to AutoApprovePolicy behavior.
type FuncPolicy struct {
	ApproveIssuanceFunc   func(offered []*clientmodels.Credential, requestor *clientmodels.TrustedParty) bool
	TransactionCodeFunc   func() (string, bool)
	ApproveDisclosureFunc func(plan *clientmodels.DisclosurePlan, requestor *clientmodels.TrustedParty, hashToQueryID map[string]string) ([]dcql.DisclosureSelection, bool)
}

func (p FuncPolicy) ApproveIssuance(offered []*clientmodels.Credential, requestor *clientmodels.TrustedParty) bool {
	if p.ApproveIssuanceFunc == nil {
		return true
	}
	return p.ApproveIssuanceFunc(offered, requestor)
}

func (p FuncPolicy) TransactionCode() (string, bool) {
	if p.TransactionCodeFunc == nil {
		return "", false
	}
	return p.TransactionCodeFunc()
}

func (p FuncPolicy) ApproveDisclosure(plan *clientmodels.DisclosurePlan, requestor *clientmodels.TrustedParty, hashToQueryID map[string]string) ([]dcql.DisclosureSelection, bool) {
	if p.ApproveDisclosureFunc == nil {
		return selectMinimalOwned(plan, hashToQueryID)
	}
	return p.ApproveDisclosureFunc(plan, requestor, hashToQueryID)
}

// selectMinimalOwned turns a DisclosurePlan into disclosure selections by
// choosing, for every disjunction, the first bundle the wallet already owns and
// disclosing exactly that bundle's claims. Optional disjunctions with no owned
// bundle are skipped. If a required disjunction cannot be satisfied from owned
// credentials (e.g. it needs issuance-during-disclosure), it returns ok=false —
// the POC does not attempt issuance-during-disclosure.
func selectMinimalOwned(plan *clientmodels.DisclosurePlan, hashToQueryID map[string]string) ([]dcql.DisclosureSelection, bool) {
	if plan == nil {
		return nil, false
	}
	// The POC cannot satisfy requests that require obtaining new credentials.
	if plan.IssueDuringDisclosure != nil && len(plan.IssueDuringDisclosure.Steps) > 0 {
		return nil, false
	}

	var selections []dcql.DisclosureSelection
	for _, pickOne := range plan.DisclosureChoicesOverview {
		if len(pickOne.OwnedOptions) == 0 {
			if pickOne.Optional {
				continue // nothing owned, but the verifier allows skipping
			}
			return nil, false // required disjunction we cannot satisfy
		}
		bundle := pickOne.OwnedOptions[0]
		for _, inst := range bundle.Credentials {
			claimPaths := make([][]any, 0, len(inst.Attributes))
			for _, attr := range inst.Attributes {
				if len(attr.ClaimPath) > 0 {
					claimPaths = append(claimPaths, attr.ClaimPath)
				}
			}
			selections = append(selections, dcql.DisclosureSelection{
				QueryId:        hashToQueryID[inst.Hash],
				CredentialHash: inst.Hash,
				ClaimPaths:     claimPaths,
			})
		}
	}
	return selections, true
}
