package clientmodels

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrackIssued(t *testing.T) {
	plan := func(candidates ...*SelectableCredentialInstance) *DisclosurePlan {
		return &DisclosurePlan{Choices: []DisclosureChoice{{Options: []DisclosureOption{{
			Slots: []DisclosureSlot{{Id: "s", Candidates: candidates}},
		}}}}}
	}
	old := &SelectableCredentialInstance{CredentialId: "email", Hash: "old", Usable: true}
	issued := &SelectableCredentialInstance{CredentialId: "phone", Hash: "new", Usable: true}
	issuedUnusable := &SelectableCredentialInstance{CredentialId: "pid", Hash: "new-expired"}
	preExisting := map[string]struct{}{"old": {}}

	first := plan(old)
	TrackIssued(first, nil, preExisting)
	assert.Empty(t, first.IssuedCredentialIds, "a card that was already there was not issued for the request")

	second := plan(old, issued, issuedUnusable)
	TrackIssued(second, first, preExisting)
	assert.Equal(t, map[string]struct{}{"phone": {}}, second.IssuedCredentialIds,
		"a new card counts once it is usable for the request")

	third := plan(old)
	TrackIssued(third, second, preExisting)
	assert.Equal(t, map[string]struct{}{"phone": {}}, third.IssuedCredentialIds, "what was issued stays recorded")
}
