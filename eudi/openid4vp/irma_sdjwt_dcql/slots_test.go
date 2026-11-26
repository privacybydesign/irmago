package irma_sdjwt_dcql_test

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The plan as choices, options and slots, for IRMA credentials over SD-JWT VC.

// A claim with three allowed values: a card holding the second is a candidate,
// one holding a fourth is not, and both the candidate and the obtainable
// descriptor carry all three values in request order.
func TestSlotsCarryEveryRequestedValue(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	second := storeTestCred(t, s, "test.test.email", map[string]string{"email": "b@b.nl"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "d@d.nl"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "path": ["email"], "values": ["a@a.nl", "b@b.nl", "c@c.nl"] }]
		}]
	}`)

	slot := onlySlot(t, plan)
	require.Len(t, slot.Candidates, 1, "only the card with an allowed value is a candidate")
	candidate := slot.Candidates[0]
	assert.Equal(t, second.Hash, candidate.Hash)
	require.Len(t, candidate.Attributes, 1)
	assert.Equal(t, []string{"a@a.nl", "b@b.nl", "c@c.nl"}, stringValues(candidate.Attributes[0].RequestedValues))

	assert.Empty(t, slot.Obtainable, "the type has no issue URL, so it is offered only while nothing usable is owned")
	h2, _ := createTestDcqlHandler(t)
	emptyPlan := buildPlan(t, h2, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "path": ["email"], "values": ["a@a.nl", "b@b.nl", "c@c.nl"] }]
		}]
	}`)
	emptySlot := onlySlot(t, emptyPlan)
	assert.Empty(t, emptySlot.Candidates)
	require.Len(t, emptySlot.Obtainable, 1)
	var requested *clientmodels.Attribute
	for i, attr := range emptySlot.Obtainable[0].Attributes {
		if attr.ClaimPath[0] == "email" {
			requested = &emptySlot.Obtainable[0].Attributes[i]
		}
	}
	require.NotNil(t, requested)
	assert.Equal(t, []string{"a@a.nl", "b@b.nl", "c@c.nl"}, stringValues(requested.RequestedValues))
	require.NotNil(t, requested.RequestedValue)
	assert.Equal(t, "a@a.nl", *requested.RequestedValue.String, "requested_value stays the first of them")
}

// A query without claims asks for the card and nothing in it: every card of the
// type is a candidate with no attributes.
func TestSlotsForAQueryWithoutClaims(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	info := storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@a.nl"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] }
		}]
	}`)

	slot := onlySlot(t, plan)
	require.Len(t, slot.Candidates, 1, "a query without claims must not drop the card")
	assert.Equal(t, info.Hash, slot.Candidates[0].Hash)
	assert.Empty(t, slot.Candidates[0].Attributes)
	assert.True(t, slot.Candidates[0].Usable)
}

// With claim_sets, each candidate carries the claims of the first set that card
// satisfies, so two cards of one slot can show different attributes.
func TestSlotCandidatesCarryTheirOwnClaimSet(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	withEmail := storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@a.nl", "domain": "a.nl"})
	domainOnly := storeTestCred(t, s, "test.test.email", map[string]string{"domain": "b.nl"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [
				{ "id": "em", "path": ["email"] },
				{ "id": "do", "path": ["domain"] }
			],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	slot := onlySlot(t, plan)
	require.Len(t, slot.Candidates, 2)
	byHash := map[string]*clientmodels.SelectableCredentialInstance{}
	for _, c := range slot.Candidates {
		byHash[c.Hash] = c
	}
	assert.Equal(t, [][]any{{"email"}}, claimPaths(byHash[withEmail.Hash]))
	assert.Equal(t, [][]any{{"domain"}}, claimPaths(byHash[domainOnly.Hash]))
}

// An expired card is a candidate that cannot be shared, sorted after the usable
// ones; while it is the only one, the slot offers the type again.
func TestSlotsMarkAnExpiredCardUnusable(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	expired := storeTestCredWith(t, s, "test.test.email", map[string]string{"email": "old@a.nl"}, func(info *irmaclient.SdJwtVcBatchMetadata) {
		past := irma.Timestamp(time.Now().Add(-time.Hour))
		info.Expires = &past
	})

	query := `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "path": ["email"] }]
		}]
	}`
	slot := onlySlot(t, buildPlan(t, h, query))
	require.Len(t, slot.Candidates, 1)
	assert.False(t, slot.Candidates[0].Usable)
	assert.Equal(t, clientmodels.UnusableReason_Expired, slot.Candidates[0].UnusableReason)
	assert.Len(t, slot.Obtainable, 1, "nothing usable, so the type is offered")

	valid := storeTestCred(t, s, "test.test.email", map[string]string{"email": "new@a.nl"})
	slot = onlySlot(t, buildPlan(t, h, query))
	require.Len(t, slot.Candidates, 2)
	assert.Equal(t, valid.Hash, slot.Candidates[0].Hash, "the usable card comes first")
	assert.Equal(t, expired.Hash, slot.Candidates[1].Hash)
	assert.Empty(t, slot.Obtainable, "a type without issue URL is not offered next to a usable card")
}

func onlySlot(t *testing.T, plan *clientmodels.DisclosurePlan) clientmodels.DisclosureSlot {
	t.Helper()
	require.Len(t, plan.Choices, 1)
	require.Len(t, plan.Choices[0].Options, 1)
	require.Len(t, plan.Choices[0].Options[0].Slots, 1)
	return plan.Choices[0].Options[0].Slots[0]
}

func stringValues(values []clientmodels.AttributeValue) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v.String != nil {
			out = append(out, *v.String)
		}
	}
	return out
}

func claimPaths(c *clientmodels.SelectableCredentialInstance) [][]any {
	paths := make([][]any, 0, len(c.Attributes))
	for _, attr := range c.Attributes {
		paths = append(paths, attr.ClaimPath)
	}
	return paths
}

func storeTestCredWith(
	t *testing.T,
	storage *irmaclient.InMemorySdJwtVcStorage,
	vct string,
	claims map[string]string,
	edit func(*irmaclient.SdJwtVcBatchMetadata),
) irmaclient.SdJwtVcBatchMetadata {
	t.Helper()
	keyBinder := sdjwt.NewDefaultKeyBinderWithInMemoryStorage()
	info, sdjwts := irmaclient.CreateMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, vct, "https://openid4vc.staging.yivi.app", claims, 1)
	edit(&info)
	require.NoError(t, storage.StoreCredential(info, sdjwts))
	return info
}
