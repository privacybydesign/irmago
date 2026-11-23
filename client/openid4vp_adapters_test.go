package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/stretchr/testify/require"
)

// TestDisclosureChoicesSkipsAnOptionalPickOne pins how a skipped optional
// credential reaches the DCQL handlers: as nothing at all.
//
// A DCQL credential_set with `"required": false` becomes a DisclosurePickOne
// with Optional set, which the app may skip. It expresses that the way the IRMA
// path does — a choice selecting no credentials — and the conversion then
// produces no DisclosureSelection for that position, so no handler is asked to
// disclose anything and the credential is simply absent from the response.
//
// This matters because the alternative shape, a selected credential carrying no
// claim paths, is refused by mdoc_dcql.selectiveDiscloseByPaths and fails the
// whole disclosure. That refusal is correct — an mdoc has no always-disclosed
// payload, so disclosing zero elements would emit an empty `nameSpaces` map,
// which ISO/IEC 18013-5 does not permit — but it must never be what a legitimate
// skip produces. If someone later makes the conversion emit a selection for
// every pick-one regardless, this test fails rather than optional credentials
// becoming un-skippable.
func TestDisclosureChoicesSkipsAnOptionalPickOne(t *testing.T) {
	queryIds := []dcql.ChoiceQueryIds{
		{{Hash: "required-hash", QueryId: "required_pid", PathKeys: map[string]struct{}{}}},
		{{Hash: "optional-hash", QueryId: "optional_age", PathKeys: map[string]struct{}{}}},
	}
	required := clientmodels.DisclosureDisconSelection{
		Credentials: []clientmodels.SelectedCredential{{
			CredentialId:   "urn:eudi:pid:1",
			CredentialHash: "required-hash",
			AttributePaths: [][]any{{"given_name"}},
		}},
	}

	for name, choices := range map[string][]clientmodels.DisclosureDisconSelection{
		"optional choice selects nothing": {required, {Credentials: []clientmodels.SelectedCredential{}}},
		"optional choice is nil":          {required, {}},
		"optional choice omitted":         {required},
	} {
		t.Run(name, func(t *testing.T) {
			selections := disclosureChoicesToOpenID4VPSelections(choices, queryIds)

			require.Len(t, selections, 1,
				"a skipped optional pick-one must produce no selection, so no handler is asked to disclose nothing")
			require.Equal(t, "required_pid", selections[0].QueryId)
			require.Equal(t, "required-hash", selections[0].CredentialHash)
			require.NotEmpty(t, selections[0].ClaimPaths,
				"the required credential must still carry the paths it discloses")
		})
	}
}

// A bundle answering a multi-query credential set option comes back as one
// choice holding several credentials. Each must be presented under the query it
// answers, not all under the first.
func TestDisclosureChoicesSplitsABundleAcrossItsQueries(t *testing.T) {
	queryIds := []dcql.ChoiceQueryIds{{
		{Hash: "pid-hash", QueryId: "PID", PathKeys: map[string]struct{}{clientmodels.ClaimPathKey([]any{"family_name"}): {}}},
		{Hash: "eec-hash", QueryId: "EEC", PathKeys: map[string]struct{}{clientmodels.ClaimPathKey([]any{"credentialSubject", "code"}): {}}},
	}}
	choice := clientmodels.DisclosureDisconSelection{Credentials: []clientmodels.SelectedCredential{
		{CredentialId: "pid", CredentialHash: "pid-hash", AttributePaths: [][]any{{"family_name"}}},
		{CredentialId: "eec", CredentialHash: "eec-hash", AttributePaths: [][]any{{"credentialSubject", "code"}}},
	}}

	selections := disclosureChoicesToOpenID4VPSelections([]clientmodels.DisclosureDisconSelection{choice}, queryIds)

	require.Len(t, selections, 2)
	require.Equal(t, "PID", selections[0].QueryId)
	require.Equal(t, "pid-hash", selections[0].CredentialHash)
	require.Equal(t, "EEC", selections[1].QueryId)
	require.Equal(t, "eec-hash", selections[1].CredentialHash)
}

// An option naming two queries, `[["mobile", "email"]]`, where the wallet holds
// two mobiles and two emails, is offered as four pairs. Whichever pair the user
// picks, each of its credentials must go out under its own query, and only
// those two: one stored credential of a query must not be swapped for another.
func TestDisclosureChoicesMapEveryPairOfAMultiQueryOption(t *testing.T) {
	query := dcql.DcqlQuery{CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"mobile", "email"}}}}}
	result := &dcql.DcqlResult{QueryResults: map[string]*dcql.CredentialQueryResult{
		"mobile": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
			storedCredential("mobile", "mobile-1", "phone_number"),
			storedCredential("mobile", "mobile-2", "phone_number"),
		}},
		"email": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
			storedCredential("email", "email-1", "email"),
			storedCredential("email", "email-2", "email"),
		}},
	}}

	plan, queryIds, err := (&dcql.DcqlHandler{}).BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	pairs := plan.DisclosureChoicesOverview[0].OwnedOptions
	require.Len(t, pairs, 4, "two mobiles times two emails")

	for _, pair := range pairs {
		mobile, email := pair.Credentials[0].Hash, pair.Credentials[1].Hash
		t.Run(mobile+" with "+email, func(t *testing.T) {
			choice := clientmodels.DisclosureDisconSelection{}
			for _, cred := range pair.Credentials {
				choice.Credentials = append(choice.Credentials, clientmodels.SelectedCredential{
					CredentialId:   cred.CredentialId,
					CredentialHash: cred.Hash,
					AttributePaths: [][]any{cred.Attributes[0].ClaimPath},
				})
			}

			selections := disclosureChoicesToOpenID4VPSelections([]clientmodels.DisclosureDisconSelection{choice}, queryIds)

			require.Len(t, selections, 2)
			require.Equal(t, "mobile", selections[0].QueryId)
			require.Equal(t, mobile, selections[0].CredentialHash)
			require.Equal(t, "email", selections[1].QueryId)
			require.Equal(t, email, selections[1].CredentialHash)
		})
	}
}

// storedCredential is a stored credential offered as a candidate, disclosing one
// claim.
func storedCredential(credentialId, hash, claim string) *clientmodels.SelectableCredentialInstance {
	return &clientmodels.SelectableCredentialInstance{
		CredentialId: credentialId,
		Hash:         hash,
		Attributes: []clientmodels.Attribute{{
			ClaimPath: []any{claim},
			Value:     clientmodels.NewAttributeValue(hash),
		}},
	}
}
