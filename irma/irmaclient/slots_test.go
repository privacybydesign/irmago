package irmaclient

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The seeded client holds one irma-demo.RU.studentCard (not a singleton, with
// an issue URL, issued without revocation support) and one test.test.mijnirma
// (a singleton).

func slotRequest(t *testing.T, client *IrmaClient, condiscon string) *irma.DisclosureRequest {
	t.Helper()
	cdc := irma.AttributeConDisCon{}
	require.NoError(t, json.Unmarshal([]byte(condiscon), &cdc))
	return &irma.DisclosureRequest{BaseRequest: irma.BaseRequest{ProtocolVersion: client.maxVersion}, Disclose: cdc}
}

func TestSlotCandidates(t *testing.T) {
	storage, client, _ := parseStorage(t)
	defer client.Close()
	defer storage.Close()

	studentCard := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	mijnirma := irma.NewCredentialTypeIdentifier("test.test.mijnirma")

	t.Run("one slot per credential type of a con, in order of first appearance", func(t *testing.T) {
		// The singleton before the non-singleton, and the non-singleton named
		// twice apart: still one slot each.
		request := slotRequest(t, client, `[[[
			"test.test.mijnirma.email",
			"irma-demo.RU.studentCard.level",
			"irma-demo.RU.studentCard.studentID"
		]]]`)
		discons := client.SlotCandidates(request)

		require.Len(t, discons, 1)
		assert.False(t, discons[0].Optional)
		require.Len(t, discons[0].Cons, 1)
		con := discons[0].Cons[0]
		require.Len(t, con, 2)
		assert.Equal(t, mijnirma, con[0].Type)
		assert.Equal(t, studentCard, con[1].Type)
		assert.Len(t, con[1].Requests, 2, "the type's requests stay together on its slot")
		for _, slot := range con {
			require.Len(t, slot.Candidates, 1)
			assert.True(t, slot.Candidates[0].Usable)
			assert.Equal(t, UnusableNone, slot.Candidates[0].Reason)
		}
		assert.False(t, con[0].Obtainable, "an owned, usable singleton is not offered again")
		assert.True(t, con[1].Obtainable, "a non-singleton with an issue URL can be added beside the owned one")
	})

	t.Run("an empty con makes the discon optional and is no option", func(t *testing.T) {
		discons := client.SlotCandidates(slotRequest(t, client, `[[[], ["irma-demo.RU.studentCard.level"]]]`))
		require.Len(t, discons, 1)
		assert.True(t, discons[0].Optional)
		require.Len(t, discons[0].Cons, 1)
	})

	t.Run("a required value that the card does not hold leaves the slot without candidates", func(t *testing.T) {
		discons := client.SlotCandidates(slotRequest(t, client, `[[[{"type": "irma-demo.RU.studentCard.studentID", "value": "not-held"}]]]`))
		slot := discons[0].Cons[0][0]
		assert.Empty(t, slot.Candidates)
		assert.True(t, slot.Obtainable)
	})

	t.Run("a request for the credential only", func(t *testing.T) {
		discons := client.SlotCandidates(slotRequest(t, client, `[[["irma-demo.RU.studentCard"]]]`))
		slot := discons[0].Cons[0][0]
		assert.Equal(t, studentCard, slot.Type)
		require.Len(t, slot.Requests, 1)
		assert.True(t, slot.Requests[0].Type.IsCredential())
		require.Len(t, slot.Candidates, 1)
	})

	t.Run("a revoked card is a candidate that cannot be used, and its type is offered again", func(t *testing.T) {
		attrs := client.attributes[mijnirma][0]
		attrs.Revoked = true
		defer func() { attrs.Revoked = false }()

		slot := client.SlotCandidates(slotRequest(t, client, `[[["test.test.mijnirma.email"]]]`))[0].Cons[0][0]
		require.Len(t, slot.Candidates, 1)
		assert.False(t, slot.Candidates[0].Usable)
		assert.Equal(t, UnusableRevoked, slot.Candidates[0].Reason)
		assert.True(t, slot.Obtainable, "a singleton without a usable card is offered to add again")
	})

	t.Run("a card without revocation support when a non-revocation proof is asked", func(t *testing.T) {
		request := slotRequest(t, client, `[[["irma-demo.RU.studentCard.level"]]]`)
		request.Revocation = irma.NonRevocationParameters{
			studentCard: {Updates: map[uint]*revocation.Update{2: {}}},
		}
		require.True(t, request.RequestsRevocation(studentCard))

		slot := client.SlotCandidates(request)[0].Cons[0][0]
		require.Len(t, slot.Candidates, 1)
		assert.False(t, slot.Candidates[0].Usable)
		assert.Equal(t, UnusableNotRevocable, slot.Candidates[0].Reason)

		request.Revocation = nil
		slot = client.SlotCandidates(request)[0].Cons[0][0]
		assert.True(t, slot.Candidates[0].Usable, "without a non-revocation request it is usable")
	})

	// IRMA's condiscon rule (AttributeConDisCon.Validate) allows at most one
	// non-singleton type per con, and a singleton is held at most once, so an
	// option has at most one slot with several candidates.
	t.Run("at most one slot of an option has several candidates", func(t *testing.T) {
		valid := slotRequest(t, client, `[[["test.test.mijnirma.email", "irma-demo.RU.studentCard.level"]]]`)
		require.NoError(t, valid.Disclose.Validate(client.Configuration))
		invalid := slotRequest(t, client, `[[["irma-demo.RU.studentCard.level", "irma-demo.MijnOverheid.fullName.familyname"]]]`)
		require.Error(t, invalid.Disclose.Validate(client.Configuration),
			"two non-singleton types in one con are refused before any slot is built")

		for _, con := range client.SlotCandidates(valid)[0].Cons {
			several := 0
			for _, slot := range con {
				if len(slot.Candidates) > 1 {
					several++
				}
			}
			assert.LessOrEqual(t, several, 1)
		}
	})

	t.Run("the same type in two discons is two slots", func(t *testing.T) {
		discons := client.SlotCandidates(slotRequest(t, client, `[
			[["irma-demo.RU.studentCard.level"]],
			[["irma-demo.RU.studentCard.studentID"]]
		]`))
		require.Len(t, discons, 2)
		assert.Equal(t, studentCard, discons[0].Cons[0][0].Type)
		assert.Equal(t, studentCard, discons[1].Cons[0][0].Type)
	})
}

// unusableReason applies satisfiesCon's usable rule: a request that accepts
// expired cards of a type (skipExpiryCheck) makes an expired card usable, and
// revocation only counts when a non-revocation proof is asked.
func TestUnusableReason(t *testing.T) {
	tests := []struct {
		name                              string
		revoked, validForRequest, revocOk bool
		want                              UnusableReason
	}{
		{"usable", false, true, true, UnusableNone},
		{"expired", false, false, true, UnusableExpired},
		{"revoked", true, true, true, UnusableRevoked},
		{"revoked and expired: revoked", true, false, true, UnusableRevoked},
		{"expired and not revocable: expired", false, false, false, UnusableExpired},
		{"not revocable", false, true, false, UnusableNotRevocable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, unusableReason(tt.revoked, tt.validForRequest, tt.revocOk))
		})
	}
}
