package dcql

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Without credential_sets every query is a required choice of one option of
// one slot, named after the query and carrying its `multiple`.
func TestChoicesFromCredentialQueries(t *testing.T) {
	query := DcqlQuery{Credentials: []CredentialQuery{
		{Id: "email", Format: "fake"},
		{Id: "phones", Format: "fake", Multiple: true},
	}}
	results := map[string]*CredentialQueryResult{
		"email":  {OwnedCandidates: cands(usable("email", "e-1", "email"))},
		"phones": {OwnedCandidates: cands(usable("phone", "p-1", "phone"), usable("phone", "p-2", "phone"))},
	}
	choices := mustBuild(t, query, results)

	require.Len(t, choices, 2)
	for i, want := range []struct {
		id       string
		multiple bool
		hashes   []string
	}{{"email", false, []string{"e-1"}}, {"phones", true, []string{"p-1", "p-2"}}} {
		assert.False(t, choices[i].Optional)
		require.Len(t, choices[i].Options, 1)
		require.Len(t, choices[i].Options[0].Slots, 1)
		slot := choices[i].Options[0].Slots[0]
		assert.Equal(t, want.id, slot.Id)
		assert.Equal(t, want.multiple, slot.Multiple)
		assert.Equal(t, [][]string{want.hashes}, slotHashes(choices[i].Options[0]))
	}
}

// A slot's candidates come best first (clientmodels.SortCandidates): an
// unusable card after the usable ones. A candidate without a hash cannot be
// selected and is left out.
func TestSlotCandidatesAreSorted(t *testing.T) {
	expired := usable("email", "a-expired", "email")
	expired.Usable = false
	expired.UnusableReason = clientmodels.UnusableReason_Expired
	query := DcqlQuery{Credentials: []CredentialQuery{{Id: "email", Format: "fake"}}}
	results := map[string]*CredentialQueryResult{
		"email": {OwnedCandidates: cands(expired, &clientmodels.SelectableCredentialInstance{Usable: true}, usable("email", "b-valid", "email"))},
	}
	choices := mustBuild(t, query, results)
	assert.Equal(t, [][]string{{"b-valid", "a-expired"}}, slotHashes(choices[0].Options[0]))
}

// What a slot offers to add: everything while no usable card is there, also a
// descriptor without an issue URL (it says what is asked); next to a usable
// card only a type that can be added beside it.
func TestSlotObtainable(t *testing.T) {
	url := "https://issuer.example/add"
	withURL := &clientmodels.CredentialDescriptor{CredentialId: "with-url", IssueURL: &url}
	singleton := &clientmodels.CredentialDescriptor{CredentialId: "singleton", IssueURL: &url, IsSingleton: true}
	noURL := &clientmodels.CredentialDescriptor{CredentialId: "no-url"}
	all := []*clientmodels.CredentialDescriptor{withURL, singleton, noURL}

	revoked := usable("x", "revoked", "a")
	revoked.Usable = false
	revoked.UnusableReason = clientmodels.UnusableReason_Revoked

	tests := []struct {
		name       string
		candidates []*clientmodels.SelectableCredentialInstance
		want       []string
	}{
		{"nothing owned", nil, []string{"with-url", "singleton", "no-url"}},
		{"only a revoked card", cands(revoked), []string{"with-url", "singleton", "no-url"}},
		{"a usable card", cands(usable("x", "ok", "a")), []string{"with-url"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, descriptorIdsOf(slotObtainable(tt.candidates, all)))
		})
	}
}

// A query that no credential set names is not part of the plan, as before.
func TestQueryNamedByNoSetIsLeftOut(t *testing.T) {
	query := setsQuery([][]string{{"email"}})
	query.Credentials = append(query.Credentials, CredentialQuery{Id: "unused", Format: "fake"})
	results := map[string]*CredentialQueryResult{
		"email":  {OwnedCandidates: cands(usable("email", "e-1", "email"))},
		"unused": {OwnedCandidates: cands(usable("x", "x-1", "x"))},
	}
	choices := mustBuild(t, query, results)
	require.Len(t, choices, 1)
	assert.Equal(t, []string{"email"}, slotIds(choices[0].Options[0]))
}

// The lists of the plan are never null on the wire, also when empty.
func TestChoicesMarshalWithoutNulls(t *testing.T) {
	query := DcqlQuery{Credentials: []CredentialQuery{{Id: "email", Format: "fake"}}}
	plan, err := NewDcqlHandler(nil).BuildDisclosurePlan(query, &DcqlResult{QueryResults: map[string]*CredentialQueryResult{
		"email": {},
	}}, nil, nil)
	require.NoError(t, err)

	raw, err := json.Marshal(plan)
	require.NoError(t, err)
	var wire struct {
		Choices []struct {
			Options []struct {
				Slots []map[string]json.RawMessage `json:"slots"`
			} `json:"options"`
		} `json:"choices"`
		IssuedCredentialIds json.RawMessage `json:"issued_credential_ids"`
	}
	require.NoError(t, json.Unmarshal(raw, &wire))
	require.Len(t, wire.Choices, 1)
	slot := wire.Choices[0].Options[0].Slots[0]
	assert.JSONEq(t, `[]`, string(slot["candidates"]))
	assert.JSONEq(t, `[]`, string(slot["obtainable"]))
	assert.JSONEq(t, `{}`, string(wire.IssuedCredentialIds))
}

// Unusable cards are candidates too, after the usable ones; a query whose
// only card is used up is a slot with that card, unusable, and what to add.
func TestBuildDisclosurePlanKeepsUnusableCards(t *testing.T) {
	query := DcqlQuery{Credentials: []CredentialQuery{{Id: "email", Format: "fake"}}}
	unusable := func(hash string, reason clientmodels.UnusableReason) *clientmodels.SelectableCredentialInstance {
		c := usable("email", hash, "email")
		c.Usable = false
		c.UnusableReason = reason
		return c
	}

	plan, err := NewDcqlHandler(nil).BuildDisclosurePlan(query, &DcqlResult{QueryResults: map[string]*CredentialQueryResult{
		"email": {OwnedCandidates: cands(unusable("e-expired", clientmodels.UnusableReason_Expired), usable("email", "e-valid", "email"))},
	}}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"e-valid", "e-expired"}}, slotHashes(plan.Choices[0].Options[0]))

	plan, err = NewDcqlHandler(nil).BuildDisclosurePlan(query, &DcqlResult{QueryResults: map[string]*CredentialQueryResult{
		"email": {
			OwnedCandidates:       cands(unusable("e-used", clientmodels.UnusableReason_UsedUp)),
			ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "email"}},
		},
	}}, nil, nil)
	require.NoError(t, err, "a used-up card no longer fails the request")
	slot := plan.Choices[0].Options[0].Slots[0]
	assert.Equal(t, clientmodels.UnusableReason_UsedUp, slot.Candidates[0].UnusableReason)
	assert.Equal(t, []string{"email"}, descriptorIdsOf(slot.Obtainable))
}

// A malformed credential_sets is refused before any plan is built, with an
// error that names what is wrong.
func TestMalformedCredentialSetsAreRefused(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{"unknown query id", `{"credentials": [{"id": "a", "format": "fake"}], "credential_sets": [{"options": [["a", "b"]]}]}`, `unknown credential query id "b"`},
		{"empty options", `{"credentials": [{"id": "a", "format": "fake"}], "credential_sets": [{"options": []}]}`, "empty options"},
		{"empty option", `{"credentials": [{"id": "a", "format": "fake"}], "credential_sets": [{"options": [[]]}]}`, "empty option"},
		{"duplicate query id", `{"credentials": [{"id": "a", "format": "fake"}, {"id": "a", "format": "fake"}]}`, `"a" is present more than once`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var query DcqlQuery
			require.NoError(t, json.Unmarshal([]byte(tt.query), &query))
			err := query.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}

	t.Run("an option naming one query twice", func(t *testing.T) {
		query := setsQuery([][]string{{"a", "a"}})
		require.NoError(t, query.Validate())
		_, err := buildChoices(query, map[string]*CredentialQueryResult{"a": {}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"a" more than once`)
	})
}

// trusted_authorities is parsed but not applied on this branch: a query that
// names one finds the same cards as without. Pinned so applying it later is a
// visible decision.
func TestTrustedAuthoritiesIsNotApplied(t *testing.T) {
	var query DcqlQuery
	require.NoError(t, json.Unmarshal([]byte(`{"credentials": [{
		"id": "a",
		"format": "fake",
		"trusted_authorities": [{"type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]}]
	}]}`), &query))
	require.NoError(t, query.Validate())
	require.Len(t, query.Credentials[0].TrustedAuthorities, 1, "parsed")

	seen := &recordingHandler{}
	result, err := NewDcqlHandler([]DcqlCredentialQueryHandler{seen}).FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.QueryResults["a"].OwnedCandidates, 1, "no card is filtered on the authorities")
}

// require_cryptographic_holder_binding is applied: the query's value reaches the
// format handler with each selection, true when absent. Pinned so that changing
// it is a visible decision.
func TestRequireCryptographicHolderBindingReachesTheHandler(t *testing.T) {
	no := false
	query := DcqlQuery{Credentials: []CredentialQuery{
		{Id: "bound", Format: "fake"},
		{Id: "unbound", Format: "fake", RequireHolderBinding: &no},
	}}
	seen := &recordingHandler{}
	_, err := NewDcqlHandler([]DcqlCredentialQueryHandler{seen}).PrepareDisclosure(query, []DisclosureSelection{
		{QueryId: "bound", CredentialHash: "h1"},
		{QueryId: "unbound", CredentialHash: "h2"},
	}, "nonce", "aud", ResponseBinding{})
	require.NoError(t, err)

	require.Len(t, seen.prepared, 2)
	assert.True(t, seen.prepared[0].RequireHolderBinding)
	assert.False(t, seen.prepared[1].RequireHolderBinding)
}

func TestSetUsable(t *testing.T) {
	zero, two := uint(0), uint(2)
	tests := []struct {
		name      string
		candidate clientmodels.SelectableCredentialInstance
		expired   bool
		want      clientmodels.UnusableReason
	}{
		{"fine", clientmodels.SelectableCredentialInstance{BatchInstanceCountRemaining: &two}, false, clientmodels.UnusableReason_None},
		{"unlimited", clientmodels.SelectableCredentialInstance{}, false, clientmodels.UnusableReason_None},
		{"expired", clientmodels.SelectableCredentialInstance{}, true, clientmodels.UnusableReason_Expired},
		{"used up", clientmodels.SelectableCredentialInstance{BatchInstanceCountRemaining: &zero}, false, clientmodels.UnusableReason_UsedUp},
		{"revoked wins", clientmodels.SelectableCredentialInstance{Revoked: true, BatchInstanceCountRemaining: &zero}, true, clientmodels.UnusableReason_Revoked},
		{"expired before used up", clientmodels.SelectableCredentialInstance{BatchInstanceCountRemaining: &zero}, true, clientmodels.UnusableReason_Expired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.candidate
			SetUsable(&c, tt.expired)
			assert.Equal(t, tt.want, c.UnusableReason)
			assert.Equal(t, tt.want == clientmodels.UnusableReason_None, c.Usable)
		})
	}
}

// recordingHandler answers every query of format "fake" with one usable card,
// and records the selections it is asked to present.
type recordingHandler struct {
	prepared []DisclosureSelection
}

func (*recordingHandler) CanHandleCredentialQuery(query CredentialQuery) bool {
	return query.Format == "fake"
}

func (*recordingHandler) FindCandidates(query CredentialQuery) (*CredentialQueryResult, error) {
	return &CredentialQueryResult{OwnedCandidates: cands(usable(query.Id, query.Id+"-hash", "x"))}, nil
}

func (h *recordingHandler) PrepareDisclosure(selections []DisclosureSelection, _, _ string) (*PreparedDisclosure, error) {
	h.prepared = append(h.prepared, selections...)
	prepared := &PreparedDisclosure{}
	for _, selection := range selections {
		prepared.QueryResponses = append(prepared.QueryResponses, QueryResponse{QueryId: selection.QueryId, Credentials: []string{selection.CredentialHash}})
	}
	return prepared, nil
}

// Without `multiple`, a query is answered by exactly one presentation
// (OpenID4VP 1.0 § 6.1). The wallet refuses to send two rather than a
// response the verifier rejects.
func TestPrepareDisclosureRefusesTwoPresentationsForOneQuery(t *testing.T) {
	query := DcqlQuery{Credentials: []CredentialQuery{
		{Id: "email1", Format: "fake"},
		{Id: "email2", Format: "fake"},
		{Id: "emails", Format: "fake", Multiple: true},
	}}
	handler := NewDcqlHandler([]DcqlCredentialQueryHandler{&recordingHandler{}})

	t.Run("two presentations for a single query are refused", func(t *testing.T) {
		_, err := handler.PrepareDisclosure(query, []DisclosureSelection{
			{QueryId: "email1", CredentialHash: "h1"},
			{QueryId: "email1", CredentialHash: "h2"},
		}, "nonce", "aud", ResponseBinding{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email1")
	})

	t.Run("one presentation per query is fine, also of the same card", func(t *testing.T) {
		prepared, err := handler.PrepareDisclosure(query, []DisclosureSelection{
			{QueryId: "email1", CredentialHash: "h1"},
			{QueryId: "email2", CredentialHash: "h1"},
		}, "nonce", "aud", ResponseBinding{})
		require.NoError(t, err)
		assert.Len(t, prepared.QueryResponses, 2)
	})

	t.Run("several presentations for a multiple query are fine", func(t *testing.T) {
		prepared, err := handler.PrepareDisclosure(query, []DisclosureSelection{
			{QueryId: "emails", CredentialHash: "h1"},
			{QueryId: "emails", CredentialHash: "h2"},
		}, "nonce", "aud", ResponseBinding{})
		require.NoError(t, err)
		assert.Len(t, prepared.QueryResponses, 2)
	})
}
