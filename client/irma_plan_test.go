package client

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The IRMA plan as choices, options and slots, from what irmaclient reports per
// slot (irmaclient.SlotCandidates, tested there) and the wallet's credentials.

var (
	studentCard = irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	root        = irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root") // a singleton
	fullName    = irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName")
)

func TestIrmaChoices(t *testing.T) {
	conf := loadTestIrmaConfiguration(t)
	studentA := irmaCred(studentCard, "student-a", map[string]string{"level": "master", "studentID": "1", "university": "RU", "studentCardNumber": "11"})
	studentB := irmaCred(studentCard, "student-b", map[string]string{"level": "bachelor", "studentID": "2", "university": "RU", "studentCardNumber": "22"})
	bsn := irmaCred(root, "root", map[string]string{"BSN": "12345"})
	credentials := []*clientmodels.Credential{studentA, studentB, bsn}

	build := func(t *testing.T, discons ...irmaclient.DisconSlots) []clientmodels.DisclosureChoice {
		t.Helper()
		choices, err := createIrmaChoices(conf, credentials, discons, "en")
		require.NoError(t, err)
		return choices
	}

	t.Run("a single type: one choice, one option, one slot with only the asked attributes", func(t *testing.T) {
		choices := build(t, discon(con(slot(studentCard, reqs("level"), usableCands("student-a"), true))))

		require.Len(t, choices, 1)
		assert.False(t, choices[0].Optional)
		require.Len(t, choices[0].Options, 1)
		require.Len(t, choices[0].Options[0].Slots, 1)
		s := choices[0].Options[0].Slots[0]
		assert.Equal(t, "0:irma-demo.RU.studentCard", s.Id)
		assert.False(t, s.Multiple, "always false for IRMA")
		require.Len(t, s.Candidates, 1)
		assert.Equal(t, "student-a", s.Candidates[0].Hash)
		assert.Equal(t, []string{"level"}, attrNames(s.Candidates[0]))
		assert.True(t, s.Candidates[0].Usable)
		require.Len(t, s.Obtainable, 1)
		assert.Equal(t, studentCard.String(), s.Obtainable[0].CredentialId)
	})

	t.Run("singleton and non-singleton in one con: one option, two slots of one and two candidates", func(t *testing.T) {
		choices := build(t, discon(con(
			slot(studentCard, reqs("level"), usableCands("student-a", "student-b"), true),
			slot(root, reqs("BSN"), usableCands("root"), false),
		)))
		option := choices[0].Options[0]
		assert.Equal(t, []string{"0:irma-demo.RU.studentCard", "0:irma-demo.MijnOverheid.root"}, irmaSlotIds(option))
		assert.Len(t, option.Slots[0].Candidates, 2)
		assert.Len(t, option.Slots[1].Candidates, 1)
		assert.Empty(t, option.Slots[1].Obtainable)
	})

	// The case #804 names: with the singleton first, the pick-one bundles keyed
	// instances in a way that collided. Slots keep the con's order and each
	// type its own candidates.
	t.Run("the same with the singleton first", func(t *testing.T) {
		choices := build(t, discon(con(
			slot(root, reqs("BSN"), usableCands("root"), false),
			slot(studentCard, reqs("level"), usableCands("student-a", "student-b"), true),
		)))
		option := choices[0].Options[0]
		assert.Equal(t, []string{"0:irma-demo.MijnOverheid.root", "0:irma-demo.RU.studentCard"}, irmaSlotIds(option))
		assert.Equal(t, []string{"root"}, candidateHashes(option.Slots[0]))
		assert.ElementsMatch(t, []string{"student-a", "student-b"}, candidateHashes(option.Slots[1]))
	})

	t.Run("an optional discon", func(t *testing.T) {
		d := discon(con(slot(studentCard, reqs("level"), usableCands("student-a"), true)))
		d.Optional = true
		choices := build(t, d)
		assert.True(t, choices[0].Optional)
		assert.Len(t, choices[0].Options, 1, "the empty con is not an option")
	})

	t.Run("a required value is a list of one, on candidates and the descriptor", func(t *testing.T) {
		master := "master"
		requests := []irma.AttributeRequest{{Type: attrType(studentCard, "level"), Value: &master}}
		s := build(t, discon(con(slotWith(studentCard, requests, usableCands("student-a"), true))))[0].Options[0].Slots[0]

		level := s.Candidates[0].Attributes[0]
		require.NotNil(t, level.RequestedValue)
		assert.Equal(t, "master", *level.RequestedValue.String)
		require.Len(t, level.RequestedValues, 1)
		assert.Equal(t, "master", *level.RequestedValues[0].String)

		var described clientmodels.Attribute
		for _, attr := range s.Obtainable[0].Attributes {
			if attr.ClaimPath[0] == "level" {
				described = attr
			}
		}
		require.Len(t, described.RequestedValues, 1)
		assert.Equal(t, "master", *described.RequestedValues[0].String)
	})

	t.Run("nothing owned: the slot has no candidates and offers the type", func(t *testing.T) {
		s := build(t, discon(con(slot(fullName, reqs("familyname"), nil, true))))[0].Options[0].Slots[0]
		assert.Equal(t, "0:irma-demo.MijnOverheid.fullName", s.Id)
		assert.Empty(t, s.Candidates)
		require.Len(t, s.Obtainable, 1)
	})

	t.Run("a partly owned con: the owned slot has its card, the other only what can be added", func(t *testing.T) {
		option := build(t, discon(con(
			slot(root, reqs("BSN"), usableCands("root"), false),
			slot(fullName, reqs("familyname"), nil, true),
		)))[0].Options[0]
		assert.Equal(t, []string{"root"}, candidateHashes(option.Slots[0]))
		assert.Empty(t, option.Slots[0].Obtainable)
		assert.Empty(t, option.Slots[1].Candidates)
		assert.Len(t, option.Slots[1].Obtainable, 1)
	})

	t.Run("a request for the credential only gives candidates without attributes", func(t *testing.T) {
		requests := []irma.AttributeRequest{{Type: irma.NewAttributeTypeIdentifier(studentCard.String())}}
		s := build(t, discon(con(slotWith(studentCard, requests, usableCands("student-a"), false))))[0].Options[0].Slots[0]
		require.Len(t, s.Candidates, 1)
		assert.Empty(t, s.Candidates[0].Attributes)
	})

	t.Run("an unusable card keeps its reason and sorts after the usable one", func(t *testing.T) {
		candidates := []irmaclient.SlotCandidate{
			{Hash: "student-a", Usable: false, Reason: irmaclient.UnusableExpired},
			{Hash: "student-b", Usable: true},
		}
		s := build(t, discon(con(slot(studentCard, reqs("level"), candidates, true))))[0].Options[0].Slots[0]
		assert.Equal(t, []string{"student-b", "student-a"}, candidateHashes(s))
		assert.Equal(t, clientmodels.UnusableReason_Expired, s.Candidates[1].UnusableReason)
		assert.False(t, s.Candidates[1].Usable)
	})

	t.Run("the same type in two discons is two independent slots", func(t *testing.T) {
		choices := build(t,
			discon(con(slot(studentCard, reqs("level"), usableCands("student-a", "student-b"), true))),
			discon(con(slot(studentCard, reqs("studentID"), usableCands("student-a", "student-b"), true))),
		)
		first, second := choices[0].Options[0].Slots[0], choices[1].Options[0].Slots[0]
		assert.Equal(t, "0:irma-demo.RU.studentCard", first.Id)
		assert.Equal(t, "1:irma-demo.RU.studentCard", second.Id)
		assert.Equal(t, []string{"level"}, attrNames(first.Candidates[0]))
		assert.Equal(t, []string{"studentID"}, attrNames(second.Candidates[0]))
	})

	t.Run("attributes follow the schema order, not the request's", func(t *testing.T) {
		// studentCard's display order is level, studentID, studentCardNumber, university.
		s := build(t, discon(con(slot(studentCard, reqs("university", "studentID", "level"), usableCands("student-a"), false))))[0].Options[0].Slots[0]
		assert.Equal(t, []string{"level", "studentID", "university"}, attrNames(s.Candidates[0]))
	})

	t.Run("a candidate the wallet does not hold is an error", func(t *testing.T) {
		_, err := createIrmaChoices(conf, credentials, []irmaclient.DisconSlots{
			discon(con(slot(studentCard, reqs("level"), usableCands("gone"), false))),
		}, "en")
		require.Error(t, err)
	})
}

// createDisclosurePlan sends the slots next to the pick-ones, and the lists are
// never null on the wire.
func TestCreateDisclosurePlanFillsChoices(t *testing.T) {
	conf := loadTestIrmaConfiguration(t)
	plan, err := createDisclosurePlan(nil, conf, nil, []irmaclient.DisconSlots{
		discon(con(slot(fullName, reqs("familyname"), nil, false))),
	}, nil, "en")
	require.NoError(t, err)
	require.Len(t, plan.Choices, 1)
	assert.NotNil(t, plan.IssuedCredentialIds)

	raw, err := json.Marshal(plan.Choices)
	require.NoError(t, err)
	assert.JSONEq(t, `[{"optional": false, "options": [{"slots": [{
		"id": "0:irma-demo.MijnOverheid.fullName",
		"multiple": false,
		"candidates": [],
		"obtainable": []
	}]}]}]`, string(raw))
}

func discon(cons ...irmaclient.ConSlots) irmaclient.DisconSlots {
	return irmaclient.DisconSlots{Cons: cons}
}

func con(slots ...irmaclient.CredentialSlot) irmaclient.ConSlots {
	return slots
}

// slot is a credential type of a con asking the named attributes.
func slot(credType irma.CredentialTypeIdentifier, attrs []string, candidates []irmaclient.SlotCandidate, obtainable bool) irmaclient.CredentialSlot {
	requests := make([]irma.AttributeRequest, 0, len(attrs))
	for _, name := range attrs {
		requests = append(requests, irma.AttributeRequest{Type: attrType(credType, name)})
	}
	return slotWith(credType, requests, candidates, obtainable)
}

func slotWith(credType irma.CredentialTypeIdentifier, requests []irma.AttributeRequest, candidates []irmaclient.SlotCandidate, obtainable bool) irmaclient.CredentialSlot {
	return irmaclient.CredentialSlot{Type: credType, Requests: requests, Candidates: candidates, Obtainable: obtainable}
}

func reqs(attrs ...string) []string {
	return attrs
}

func usableCands(hashes ...string) []irmaclient.SlotCandidate {
	out := make([]irmaclient.SlotCandidate, 0, len(hashes))
	for _, h := range hashes {
		out = append(out, irmaclient.SlotCandidate{Hash: h, Usable: true})
	}
	return out
}

func attrType(credType irma.CredentialTypeIdentifier, name string) irma.AttributeTypeIdentifier {
	return irma.NewAttributeTypeIdentifier(credType.String() + "." + name)
}

// irmaCred is a stored IRMA credential as the client lists it.
func irmaCred(credType irma.CredentialTypeIdentifier, hash string, values map[string]string) *clientmodels.Credential {
	attrs := []clientmodels.Attribute{}
	for name, value := range values {
		attrs = append(attrs, clientmodels.Attribute{ClaimPath: []any{name}, Value: clientmodels.NewAttributeValue(value)})
	}
	issued := time.Now().Add(-time.Hour).Unix()
	return &clientmodels.Credential{
		CredentialId:          credType.String(),
		Hash:                  hash,
		CredentialInstanceIds: map[clientmodels.CredentialFormat]string{clientmodels.Format_Idemix: hash},
		Attributes:            attrs,
		IssuanceDate:          &issued,
	}
}

func irmaSlotIds(option clientmodels.DisclosureOption) []string {
	ids := []string{}
	for _, s := range option.Slots {
		ids = append(ids, s.Id)
	}
	return ids
}

func candidateHashes(s clientmodels.DisclosureSlot) []string {
	hashes := []string{}
	for _, c := range s.Candidates {
		hashes = append(hashes, c.Hash)
	}
	return hashes
}

func attrNames(c *clientmodels.SelectableCredentialInstance) []string {
	names := []string{}
	for _, attr := range c.Attributes {
		names = append(names, attr.ClaimPath[0].(string))
	}
	return names
}
