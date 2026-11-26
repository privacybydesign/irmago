package sdjwt_dcql

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// What the SD-JWT VC handler gives the slots of a disclosure plan.

const emailVct = "https://example.com/EmailCredential"

// A claim with three allowed values: a card holding the second is a candidate
// carrying all three, in request order; a card holding a fourth is not.
func TestFindCandidates_SeveralAllowedValues(t *testing.T) {
	h, store := newTestHandler(t)
	require.NoError(t, store.StoreBatch(newTestBatch("hash-be", emailVct, map[string]any{"country": "BE"})))
	require.NoError(t, store.StoreBatch(newTestBatch("hash-de", emailVct, map[string]any{"country": "DE"})))

	result, err := h.FindCandidates(parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["`+emailVct+`"]},
		"claims": [{"path": ["country"], "values": ["NL", "BE", "LU"]}]
	}`))
	require.NoError(t, err)

	require.Len(t, result.OwnedCandidates, 1, "only the card with an allowed value is a candidate")
	candidate := result.OwnedCandidates[0]
	assert.Equal(t, "hash-be", candidate.Hash)
	attr := attributeAt(t, candidate.Attributes, "country")
	require.Len(t, attr.RequestedValues, 3)
	for i, want := range []string{"NL", "BE", "LU"} {
		require.NotNil(t, attr.RequestedValues[i].String)
		assert.Equal(t, want, *attr.RequestedValues[i].String)
	}
}

// Allowed values keep their JSON type: a boolean stays a boolean and a number a
// number, and matching compares typed values (a string "18" is not 18).
func TestFindCandidates_TypedRequestedValues(t *testing.T) {
	h, store := newTestHandler(t)
	require.NoError(t, store.StoreBatch(newTestBatch("hash-typed", emailVct, map[string]any{
		"age_over_18": true,
		"age":         float64(21),
	})))
	require.NoError(t, store.StoreBatch(newTestBatch("hash-strings", emailVct, map[string]any{
		"age_over_18": "true",
		"age":         "21",
	})))

	result, err := h.FindCandidates(parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["`+emailVct+`"]},
		"claims": [
			{"path": ["age_over_18"], "values": [true]},
			{"path": ["age"], "values": [21, 22]}
		]
	}`))
	require.NoError(t, err)

	require.Len(t, result.OwnedCandidates, 1, "string values do not match typed ones")
	assert.Equal(t, "hash-typed", result.OwnedCandidates[0].Hash)

	over18 := attributeAt(t, result.OwnedCandidates[0].Attributes, "age_over_18")
	require.Len(t, over18.RequestedValues, 1)
	assert.Equal(t, clientmodels.AttributeType_Bool, over18.RequestedValues[0].Type)
	require.NotNil(t, over18.RequestedValues[0].Bool)
	assert.True(t, *over18.RequestedValues[0].Bool)

	age := attributeAt(t, result.OwnedCandidates[0].Attributes, "age")
	require.Len(t, age.RequestedValues, 2)
	for i, want := range []int64{21, 22} {
		assert.Equal(t, clientmodels.AttributeType_Int, age.RequestedValues[i].Type)
		require.NotNil(t, age.RequestedValues[i].Int)
		assert.Equal(t, want, *age.RequestedValues[i].Int)
	}
}

// The descriptor for a type the wallet does not hold carries the allowed values
// too, so the user sees which card would do.
func TestUnobtainableDescriptor_CarriesRequestedValues(t *testing.T) {
	h, _ := newTestHandler(t)
	h.vctFetcher = &stubVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{
		emailVct: {Name: "Email"},
	}}

	result, err := h.FindCandidates(parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["`+emailVct+`"]},
		"claims": [{"path": ["country"], "values": ["NL", "BE", "LU"]}, {"path": ["email"]}]
	}`))
	require.NoError(t, err)
	require.Len(t, result.ObtainableDescriptors, 1)

	country := attributeAt(t, result.ObtainableDescriptors[0].Attributes, "country")
	require.Len(t, country.RequestedValues, 3)
	require.NotNil(t, country.RequestedValue)
	assert.Equal(t, "NL", *country.RequestedValue.String, "requested_value is the first of them")
	email := attributeAt(t, result.ObtainableDescriptors[0].Attributes, "email")
	assert.Nil(t, email.RequestedValue)
	assert.Empty(t, email.RequestedValues, "a claim without values asks for any value")
}

// A query without claims gives a candidate with no attributes: the card itself
// is what is shared.
func TestFindCandidates_NoClaims_CandidateWithoutAttributes(t *testing.T) {
	h, store := newTestHandler(t)
	require.NoError(t, store.StoreBatch(newTestBatch("hash-card", emailVct, map[string]any{"email": "a@a.nl"})))

	result, err := h.FindCandidates(parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["`+emailVct+`"]}
	}`))
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	assert.Empty(t, result.OwnedCandidates[0].Attributes)
	assert.True(t, result.OwnedCandidates[0].Usable)
}

// With claim_sets each card is matched on its own: the first set it satisfies
// decides which claims that candidate carries.
func TestFindCandidates_ClaimSetsPerCandidate(t *testing.T) {
	h, store := newTestHandler(t)
	require.NoError(t, store.StoreBatch(newTestBatch("hash-full", emailVct, map[string]any{"email": "a@a.nl", "domain": "a.nl"})))
	require.NoError(t, store.StoreBatch(newTestBatch("hash-domain", emailVct, map[string]any{"domain": "b.nl"})))

	result, err := h.FindCandidates(parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["`+emailVct+`"]},
		"claims": [{"id": "em", "path": ["email"]}, {"id": "do", "path": ["domain"]}],
		"claim_sets": [["em"], ["do"]]
	}`))
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 2)

	paths := map[string][]string{}
	for _, c := range result.OwnedCandidates {
		for _, attr := range c.Attributes {
			paths[c.Hash] = append(paths[c.Hash], attr.ClaimPath[0].(string))
		}
	}
	assert.Equal(t, []string{"email"}, paths["hash-full"])
	assert.Equal(t, []string{"domain"}, paths["hash-domain"])
}

// A batch whose instances are all used is a candidate that cannot be shared,
// with the reason used_up, and the type is described again for adding.
func TestFindCandidates_UsedUpBatchIsUnusable(t *testing.T) {
	h, store := newTestHandler(t)
	h.vctFetcher = &stubVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{emailVct: {Name: "Email"}}}
	batch := newTestBatch("hash-used", emailVct, map[string]any{"email": "a@a.nl"})
	batch.BatchSize = 2
	batch.RemainingCount = 0
	batch.Instances[0].Used = true
	require.NoError(t, store.StoreBatch(batch))

	result, err := h.FindCandidates(parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["`+emailVct+`"]},
		"claims": [{"path": ["email"]}]
	}`))
	require.NoError(t, err, "a used-up card no longer fails the request in the handler")
	require.Len(t, result.OwnedCandidates, 1)
	assert.False(t, result.OwnedCandidates[0].Usable)
	assert.Equal(t, clientmodels.UnusableReason_UsedUp, result.OwnedCandidates[0].UnusableReason)
	assert.Equal(t, "a@a.nl", *attributeAt(t, result.OwnedCandidates[0].Attributes, "email").Value.String,
		"its values come from the batch, as there is no instance left to read")
	assert.Len(t, result.ObtainableDescriptors, 1)
}

func attributeAt(t *testing.T, attrs []clientmodels.Attribute, name string) clientmodels.Attribute {
	t.Helper()
	for _, attr := range attrs {
		if len(attr.ClaimPath) == 1 && attr.ClaimPath[0] == name {
			return attr
		}
	}
	require.Failf(t, "attribute not found", "no attribute %q in %v", name, attrs)
	return clientmodels.Attribute{}
}

// One card may answer two slots (two queries): each gets its own presentation.
// For a batch, each presentation takes an instance of its own, so a card with
// one use left cannot answer two slots.
func TestPrepareDisclosure_SameCardForTwoQueries(t *testing.T) {
	twoQueries := []dcql.DisclosureSelection{
		{QueryId: "q1", CredentialHash: "hash-twice", ClaimPaths: [][]any{{"email"}}},
		{QueryId: "q2", CredentialHash: "hash-twice", ClaimPaths: [][]any{{"email"}}},
	}
	store := func(t *testing.T, size, remaining uint) (*Engine, db.SdJwtVcStore) {
		h, store := newTestHandler(t)
		batch := newTestBatch("hash-twice", emailVct, map[string]any{"email": "test@gmail.com"})
		batch.BatchSize = size
		batch.RemainingCount = remaining
		batch.Instances = nil
		for i := uint(0); i < size; i++ {
			batch.Instances = append(batch.Instances, models.SdJwtVcBatchInstance{RawCredential: []byte(validTestSdJwtVc), Used: i >= remaining})
		}
		require.NoError(t, store.StoreBatch(batch))
		return h, store
	}

	t.Run("a batch of two: two presentations, two instances used", func(t *testing.T) {
		h, store := store(t, 2, 2)
		prepared, err := h.PrepareDisclosure(twoQueries, "nonce", "aud")
		require.NoError(t, err)
		require.Len(t, prepared.QueryResponses, 2)
		assert.Equal(t, "q1", prepared.QueryResponses[0].QueryId)
		assert.Equal(t, "q2", prepared.QueryResponses[1].QueryId)
		reloaded, err := store.GetBatchByHash("hash-twice")
		require.NoError(t, err)
		assert.Equal(t, uint(0), reloaded.RemainingCount)
	})

	t.Run("a batch with one use left cannot answer both, and keeps its use", func(t *testing.T) {
		h, store := store(t, 2, 1)
		_, err := h.PrepareDisclosure(twoQueries, "nonce", "aud")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has 1 uses left")
		reloaded, err := store.GetBatchByHash("hash-twice")
		require.NoError(t, err)
		assert.Equal(t, uint(1), reloaded.RemainingCount, "nothing was spent on a response that is not sent")
	})

	t.Run("a reusable card answers both", func(t *testing.T) {
		h, _ := store(t, 1, 1)
		prepared, err := h.PrepareDisclosure(twoQueries, "nonce", "aud")
		require.NoError(t, err)
		assert.Len(t, prepared.QueryResponses, 2)
	})
}
