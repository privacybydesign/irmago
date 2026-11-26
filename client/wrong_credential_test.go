package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectWrongCredentialIssued(t *testing.T) {
	want := "NL"
	descriptor := &clientmodels.CredentialDescriptor{CredentialId: "address", Attributes: []clientmodels.Attribute{{
		ClaimPath:      []any{"country"},
		RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: &want},
	}}}
	planWith := func(optional bool, candidates ...*clientmodels.SelectableCredentialInstance) *clientmodels.DisclosurePlan {
		return &clientmodels.DisclosurePlan{Choices: []clientmodels.DisclosureChoice{{Optional: optional, Options: []clientmodels.DisclosureOption{{
			Slots: []clientmodels.DisclosureSlot{{Id: "address", Candidates: candidates, Obtainable: []*clientmodels.CredentialDescriptor{descriptor}}},
		}}}}}
	}
	card := func(id, hash, country string, issued int64) *clientmodels.Credential {
		return &clientmodels.Credential{
			CredentialId:          id,
			Hash:                  hash,
			CredentialInstanceIds: map[clientmodels.CredentialFormat]string{clientmodels.Format_SdJwtVc: hash},
			IssuanceDate:          &issued,
			Attributes:            []clientmodels.Attribute{{ClaimPath: []any{"country"}, Value: clientmodels.NewAttributeValue(country)}},
		}
	}
	preExisting := map[string]struct{}{"old-be": {}}

	t.Run("a new card of the asked kind with another value", func(t *testing.T) {
		wrong := detectWrongCredentialIssued(planWith(false), nil,
			[]*clientmodels.Credential{card("address", "old-be", "BE", 1), card("address", "new-de", "DE", 2)}, preExisting)
		require.NotNil(t, wrong)
		assert.Equal(t, "new-de", wrong.Hash)
		require.Len(t, wrong.Attributes, 1, "only what does not match")
		assert.Equal(t, "DE", *wrong.Attributes[0].Value.String)
		assert.Equal(t, "NL", *wrong.Attributes[0].RequestedValue.String)
	})

	t.Run("the last one issued of two", func(t *testing.T) {
		wrong := detectWrongCredentialIssued(planWith(false), nil,
			[]*clientmodels.Credential{card("address", "new-de", "DE", 2), card("address", "new-fr", "FR", 3)}, preExisting)
		require.NotNil(t, wrong)
		assert.Equal(t, "new-fr", wrong.Hash)
	})

	t.Run("a card that was there before is not reported", func(t *testing.T) {
		assert.Nil(t, detectWrongCredentialIssued(planWith(false), nil,
			[]*clientmodels.Credential{card("address", "old-be", "BE", 1)}, preExisting))
	})

	t.Run("a new card of another kind is not reported", func(t *testing.T) {
		assert.Nil(t, detectWrongCredentialIssued(planWith(false), nil,
			[]*clientmodels.Credential{card("email", "new-mail", "DE", 2)}, preExisting))
	})

	t.Run("nothing once the choice can be answered", func(t *testing.T) {
		usable := &clientmodels.SelectableCredentialInstance{Hash: "new-nl", Usable: true}
		assert.Nil(t, detectWrongCredentialIssued(planWith(false, usable), nil,
			[]*clientmodels.Credential{card("address", "new-de", "DE", 2), card("address", "new-nl", "NL", 3)}, preExisting))
	})

	t.Run("nothing for an optional choice", func(t *testing.T) {
		assert.Nil(t, detectWrongCredentialIssued(planWith(true), nil,
			[]*clientmodels.Credential{card("address", "new-de", "DE", 2)}, preExisting))
	})
}
