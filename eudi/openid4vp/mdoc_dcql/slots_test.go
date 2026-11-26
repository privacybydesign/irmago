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
