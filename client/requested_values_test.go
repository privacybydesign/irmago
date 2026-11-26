package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/assert"
)

// A card issued during a disclosure satisfies a claim with several allowed
// values when it holds any one of them, not only the first.
func TestSatisfiesRequestedAttributesAcceptsAnyRequestedValue(t *testing.T) {
	requested := []clientmodels.Attribute{{
		ClaimPath:       []any{"country"},
		RequestedValue:  clientmodels.NewAttributeValue("NL"),
		RequestedValues: []clientmodels.AttributeValue{*clientmodels.NewAttributeValue("NL"), *clientmodels.NewAttributeValue("BE"), *clientmodels.NewAttributeValue("LU")},
	}}
	holding := func(value string) []clientmodels.Attribute {
		return []clientmodels.Attribute{{ClaimPath: []any{"country"}, Value: clientmodels.NewAttributeValue(value)}}
	}

	for _, value := range []string{"NL", "BE", "LU"} {
		ok, issues := SatisfiesRequestedAttributes(holding(value), requested)
		assert.True(t, ok, "%s is allowed: %v", value, issues)
		ok, _ = clientmodels.SatisfiesRequestedAttributes(holding(value), requested)
		assert.True(t, ok, "%s is allowed (clientmodels)", value)
	}
	ok, issues := SatisfiesRequestedAttributes(holding("DE"), requested)
	assert.False(t, ok)
	assert.Len(t, issues, 1)
	ok, _ = clientmodels.SatisfiesRequestedAttributes(holding("DE"), requested)
	assert.False(t, ok)
}
