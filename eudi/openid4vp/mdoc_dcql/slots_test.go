package mdoc_dcql

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/stretchr/testify/require"
)

// What the mso_mdoc handler gives the slots of a disclosure plan.

// A claim with several allowed values carries all of them, typed and in request
// order, on the candidate; a card whose value is not among them is not one.
func TestFindCandidatesCarriesEveryRequestedValue(t *testing.T) {
	env := newTestEnv(t)

	query := func(values ...any) dcql.CredentialQuery {
		return dcql.CredentialQuery{
			Id:     "av",
			Format: string(clientmodels.Format_MsoMdoc),
			Meta:   &dcql.Meta{DocTypeValue: testDocType},
			Claims: []dcql.Claim{{Path: []any{testNamespace, "age_over_21"}, Values: values}},
		}
	}

	// The stored card has age_over_21 false: the second allowed value.
	result, err := env.handler.FindCandidates(query(true, false))
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	attr := mdocAttribute(t, result.OwnedCandidates[0].Attributes, "age_over_21")
	require.Len(t, attr.RequestedValues, 2)
	require.Equal(t, clientmodels.AttributeType_Bool, attr.RequestedValues[0].Type)
	require.True(t, *attr.RequestedValues[0].Bool)
	require.False(t, *attr.RequestedValues[1].Bool)

	result, err = env.handler.FindCandidates(query(true))
	require.NoError(t, err)
	require.Empty(t, result.OwnedCandidates, "a card whose value is not allowed is not a candidate")
	require.Len(t, result.ObtainableDescriptors, 1)
	descriptorAttr := mdocAttribute(t, result.ObtainableDescriptors[0].Attributes, "age_over_21")
	require.Len(t, descriptorAttr.RequestedValues, 1)
	require.NotNil(t, descriptorAttr.RequestedValue)
	require.True(t, *descriptorAttr.RequestedValue.Bool)
}

// intent_to_retain reaches the obtainable descriptor as it reaches candidates:
// set on every attribute, true or false, so what the verifier declared is shown
// before the card is added.
func TestUnobtainableDescriptorCarriesIntentToRetain(t *testing.T) {
	env := newTestEnv(t)

	result, err := env.handler.FindCandidates(dcql.CredentialQuery{
		Id:     "pid",
		Format: string(clientmodels.Format_MsoMdoc),
		Meta:   &dcql.Meta{DocTypeValue: "eu.europa.ec.eudi.pid.1"},
		Claims: []dcql.Claim{
			{Path: []any{"eu.europa.ec.eudi.pid.1", "family_name"}, IntentToRetain: true},
			{Path: []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.ObtainableDescriptors, 1)

	attrs := result.ObtainableDescriptors[0].Attributes
	require.Len(t, attrs, 2)
	require.NotNil(t, attrs[0].IntentToRetain)
	require.True(t, *attrs[0].IntentToRetain)
	require.NotNil(t, attrs[1].IntentToRetain, "a declared false is set too")
	require.False(t, *attrs[1].IntentToRetain)
}

func mdocAttribute(t *testing.T, attrs []clientmodels.Attribute, element string) clientmodels.Attribute {
	t.Helper()
	for _, attr := range attrs {
		if len(attr.ClaimPath) == 2 && attr.ClaimPath[1] == element {
			return attr
		}
	}
	require.Failf(t, "attribute not found", "no element %q in %v", element, attrs)
	return clientmodels.Attribute{}
}

// One card may answer two slots (two queries): each gets its own presentation,
// and for a batch each takes an instance of its own.
func TestPrepareDisclosureSameCardForTwoQueries(t *testing.T) {
	twoQueries := func(env *testEnv) []dcql.DisclosureSelection {
		sel := func(queryId string) dcql.DisclosureSelection {
			return dcql.DisclosureSelection{
				QueryId:              queryId,
				CredentialHash:       env.hash,
				ClaimPaths:           [][]any{{testNamespace, "age_over_18"}},
				RequireHolderBinding: true,
				ResponseUri:          testResponseU,
			}
		}
		return []dcql.DisclosureSelection{sel("q1"), sel("q2")}
	}

	t.Run("a batch of two: two presentations, both instances used", func(t *testing.T) {
		env := newTestEnvWithBatchSize(t, 2)
		prepared, err := env.handler.PrepareDisclosure(twoQueries(env), testNonce, testClientId)
		require.NoError(t, err)
		require.Len(t, prepared.QueryResponses, 2)
		batch, err := env.store.GetBatchByHash(env.hash)
		require.NoError(t, err)
		require.Equal(t, uint(0), batch.RemainingCount)
	})

	t.Run("a batch with one use left refuses both and spends nothing", func(t *testing.T) {
		env := newTestEnvWithBatchSize(t, 2)
		_, err := env.disclose(t)
		require.NoError(t, err)

		_, err = env.handler.PrepareDisclosure(twoQueries(env), testNonce, testClientId)
		require.Error(t, err)
		require.Contains(t, err.Error(), "has 1 uses left")
		batch, err := env.store.GetBatchByHash(env.hash)
		require.NoError(t, err)
		require.Equal(t, uint(1), batch.RemainingCount)
	})

	t.Run("a reusable card answers both", func(t *testing.T) {
		env := newTestEnv(t)
		prepared, err := env.handler.PrepareDisclosure(twoQueries(env), testNonce, testClientId)
		require.NoError(t, err)
		require.Len(t, prepared.QueryResponses, 2)
	})
}
