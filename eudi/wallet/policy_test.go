package wallet

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

func attr(path ...any) clientmodels.Attribute {
	return clientmodels.Attribute{ClaimPath: path}
}

func TestSelectMinimalOwned_PicksFirstOwnedBundle(t *testing.T) {
	plan := &clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
			{
				OwnedOptions: []*clientmodels.DisclosureBundle{
					{Credentials: []*clientmodels.SelectableCredentialInstance{
						{Hash: "h1", Attributes: []clientmodels.Attribute{attr("given_name"), attr("family_name")}},
					}},
					// A second option that must be ignored.
					{Credentials: []*clientmodels.SelectableCredentialInstance{
						{Hash: "h2", Attributes: []clientmodels.Attribute{attr("given_name")}},
					}},
				},
			},
		},
	}
	sel, ok := selectMinimalOwned(plan, map[string]string{"h1": "q1", "h2": "q2"})
	require.True(t, ok)
	require.Len(t, sel, 1)
	require.Equal(t, "q1", sel[0].QueryId)
	require.Equal(t, "h1", sel[0].CredentialHash)
	require.Equal(t, [][]any{{"given_name"}, {"family_name"}}, sel[0].ClaimPaths)
}

func TestSelectMinimalOwned_MultiCredentialBundle(t *testing.T) {
	plan := &clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
			{OwnedOptions: []*clientmodels.DisclosureBundle{
				{Credentials: []*clientmodels.SelectableCredentialInstance{
					{Hash: "a", Attributes: []clientmodels.Attribute{attr("email")}},
					{Hash: "b", Attributes: []clientmodels.Attribute{attr("address", "street")}},
				}},
			}},
		},
	}
	sel, ok := selectMinimalOwned(plan, map[string]string{"a": "q1", "b": "q2"})
	require.True(t, ok)
	require.Len(t, sel, 2)
	require.Equal(t, "b", sel[1].CredentialHash)
	require.Equal(t, [][]any{{"address", "street"}}, sel[1].ClaimPaths)
}

func TestSelectMinimalOwned_OptionalUnownedIsSkipped(t *testing.T) {
	plan := &clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
			{Optional: true, OwnedOptions: nil, ObtainableOptions: []*clientmodels.CredentialDescriptor{{CredentialId: "x"}}},
			{OwnedOptions: []*clientmodels.DisclosureBundle{
				{Credentials: []*clientmodels.SelectableCredentialInstance{
					{Hash: "h1", Attributes: []clientmodels.Attribute{attr("given_name")}},
				}},
			}},
		},
	}
	sel, ok := selectMinimalOwned(plan, map[string]string{"h1": "q1"})
	require.True(t, ok)
	require.Len(t, sel, 1)
	require.Equal(t, "h1", sel[0].CredentialHash)
}

func TestSelectMinimalOwned_RequiredUnownedFails(t *testing.T) {
	plan := &clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
			{Optional: false, OwnedOptions: nil, ObtainableOptions: []*clientmodels.CredentialDescriptor{{CredentialId: "x"}}},
		},
	}
	_, ok := selectMinimalOwned(plan, nil)
	require.False(t, ok)
}

func TestSelectMinimalOwned_IssueDuringDisclosureFails(t *testing.T) {
	plan := &clientmodels.DisclosurePlan{
		IssueDuringDisclosure: &clientmodels.IssueDuringDisclosure{
			Steps: []clientmodels.IssuanceStep{{}},
		},
	}
	_, ok := selectMinimalOwned(plan, nil)
	require.False(t, ok)
}

func TestAutoApprovePolicy(t *testing.T) {
	p := AutoApprovePolicy{}
	require.True(t, p.ApproveIssuance(nil, nil))
	_, ok := p.TransactionCode()
	require.False(t, ok)
}

func TestFuncPolicy_Defaults(t *testing.T) {
	p := FuncPolicy{}
	require.True(t, p.ApproveIssuance(nil, nil))
	code, ok := p.TransactionCode()
	require.False(t, ok)
	require.Empty(t, code)
}
