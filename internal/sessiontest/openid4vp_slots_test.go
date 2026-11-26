package sessiontest

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// OpenID4VP sessions answered per slot (the plan's Choices), against the
// Veramo verifier: each test ends in a response the verifier accepts, or in a
// refused answer that sends nothing.
func testSessionHandlerForOpenID4VPSlots(t *testing.T) {
	t.Run("credential set options", testOpenID4VPCredentialSetOptions)
	t.Run("one query in two sets with two different cards is refused", testOneQueryInTwoSetsWithDifferentCardsIsRefused)
	t.Run("multiple cards for one query", testMultipleCardsForOneQuery)
	t.Run("one of several requested values", testOneOfSeveralRequestedValues)
	t.Run("query without claims", testQueryWithoutClaimsAnsweredPerSlot)
}

// Credential set options, including ones that name several credential queries
// (`"options": [["test", "vcdm"]]`), whose credentials are shared together or
// not at all (OpenID4VP 1.0 § 6.2). The pair mixes formats on purpose, an
// SD-JWT VC and a VCDM credential, as eduwallet's exam check-in does.
//
// Each scenario says what the wallet holds, what the verifier asks for, what the
// user picks per credential set, and what the verifier receives.
var credentialSetScenarios = []credentialSetScenario{
	{
		name:     "a required pair, shared",
		holds:    []*credentialFixture{testVcdm, testSdJwt},
		request:  []credentialSetQuery{required(testSdJwt, testVcdm)},
		choose:   []setChoice{share},
		receives: []*credentialFixture{testSdJwt, testVcdm},
	},
	{
		name:     "a required pair shared, an optional email skipped",
		holds:    []*credentialFixture{testVcdm, testSdJwt, emailSdJwt},
		request:  []credentialSetQuery{required(testSdJwt, testVcdm), optional(emailSdJwt)},
		choose:   []setChoice{share, skip},
		receives: []*credentialFixture{testSdJwt, testVcdm},
	},
	{
		name:     "a required email and an optional pair, both shared",
		holds:    []*credentialFixture{testVcdm, testSdJwt, emailSdJwt},
		request:  []credentialSetQuery{required(emailSdJwt), optional(testSdJwt, testVcdm)},
		choose:   []setChoice{share, share},
		receives: []*credentialFixture{emailSdJwt, testSdJwt, testVcdm},
	},
	{
		name:     "a required email shared, an optional pair skipped",
		holds:    []*credentialFixture{testVcdm, testSdJwt, emailSdJwt},
		request:  []credentialSetQuery{required(emailSdJwt), optional(testSdJwt, testVcdm)},
		choose:   []setChoice{share, skip},
		receives: []*credentialFixture{emailSdJwt},
	},
	{
		// Half of the optional pair is missing: its slot has no card and
		// offers the type, the other slot has its card.
		name:     "an optional pair with one half missing",
		holds:    []*credentialFixture{testVcdm, emailSdJwt},
		request:  []credentialSetQuery{required(emailSdJwt), optional(testSdJwt, testVcdm)},
		choose:   []setChoice{share, skip},
		receives: []*credentialFixture{emailSdJwt},
	},
	{
		name:     "only an optional pair, skipped",
		holds:    []*credentialFixture{testVcdm, testSdJwt},
		request:  []credentialSetQuery{optional(testSdJwt, testVcdm)},
		choose:   []setChoice{skip},
		receives: nil,
	},
	{
		// Two copies of each credential: each slot lists its two cards, and the
		// user picks a card per slot that is not the first offered.
		name:     "a required pair with two copies of each, the second phone and first email shared",
		holds:    []*credentialFixture{phoneSdJwt, otherPhoneSdJwt, emailSdJwt, otherEmailSdJwt},
		request:  []credentialSetQuery{required(phoneSdJwt, emailSdJwt)},
		choose:   []setChoice{share},
		receives: []*credentialFixture{otherPhoneSdJwt, emailSdJwt},
	},
	{
		// One query in two sets has one presentation: the same card answers
		// its slot in both, and the verifier receives it once.
		name:     "one query in two sets, answered once",
		holds:    []*credentialFixture{emailSdJwt, phoneSdJwt, testSdJwt},
		request:  []credentialSetQuery{required(emailSdJwt, phoneSdJwt), required(emailSdJwt, testSdJwt)},
		choose:   []setChoice{share, share},
		receives: []*credentialFixture{emailSdJwt, phoneSdJwt, testSdJwt},
	},
}

func testOpenID4VPCredentialSetOptions(t *testing.T) {
	for _, scenario := range credentialSetScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			runCredentialSetScenario(t, scenario)
		})
	}
}

// credentialFixture is test data for one stored credential: how the issuer
// issues it, the DCQL credential query that asks for it, and the claims that
// query discloses. Two copies of one credential share the query but differ in
// their claims.
type credentialFixture struct {
	queryId string
	// credentialId is the id the wallet shows for the credential, owned or
	// obtainable.
	credentialId string
	configId     string
	issuedClaims string
	query        string
	// shownAs is a claim the wallet shows for this credential, with a value
	// that tells it apart from other copies.
	shownAs expectedClaim
	// disclosed is what the verifier receives for the query. It takes the
	// client because a VCDM credential discloses its holder DID, which is only
	// known after issuance.
	disclosed func(t *testing.T, c *client.Client) []expectedClaim
}

var testSdJwt = &credentialFixture{
	queryId:      "test",
	credentialId: "https://localhost:8443/vct/test",
	configId:     "TestCredentialSdJwt",
	issuedClaims: `{"given_name": "Test", "family_name": "User", "email": "test@example.com"}`,
	query: `{
		"id": "test",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://localhost:8443/vct/test"]},
		"claims": [{"path": ["email"]}]
	}`,
	shownAs: claim([]any{"email"}, "test@example.com"),
	disclosed: func(*testing.T, *client.Client) []expectedClaim {
		return []expectedClaim{claim([]any{"email"}, "test@example.com")}
	},
}

var (
	emailSdJwt      = emailSdJwtWith("email@example.com")
	otherEmailSdJwt = emailSdJwtWith("other@example.com")
	phoneSdJwt      = phoneSdJwtWith("+31600000001")
	otherPhoneSdJwt = phoneSdJwtWith("+31600000002")
)

func emailSdJwtWith(address string) *credentialFixture {
	return &credentialFixture{
		queryId:      "email",
		credentialId: "https://localhost:8443/vct/email",
		configId:     "EmailCredentialSdJwt",
		issuedClaims: `{"email": "` + address + `", "domain": "example.com"}`,
		query: `{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["https://localhost:8443/vct/email"]},
			"claims": [{"path": ["email"]}]
		}`,
		shownAs: claim([]any{"email"}, address),
		disclosed: func(*testing.T, *client.Client) []expectedClaim {
			return []expectedClaim{claim([]any{"email"}, address)}
		},
	}
}

func phoneSdJwtWith(number string) *credentialFixture {
	return &credentialFixture{
		queryId:      "phone",
		credentialId: "https://localhost:8443/vct/phone",
		configId:     "PhoneCredentialSdJwt",
		issuedClaims: `{"phone_number": "` + number + `"}`,
		query: `{
			"id": "phone",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["https://localhost:8443/vct/phone"]},
			"claims": [{"path": ["phone_number"]}]
		}`,
		shownAs: claim([]any{"phone_number"}, number),
		disclosed: func(*testing.T, *client.Client) []expectedClaim {
			return []expectedClaim{claim([]any{"phone_number"}, number)}
		},
	}
}

// testVcdm is the VCDM credential. Veramo issues every vc+sd-jwt claim in the
// clear, so the verifier receives all of credentialSubject, not just the claim
// the query asks for.
var testVcdm = &credentialFixture{
	queryId:      vcdmQueryId,
	credentialId: vcdmCredentialId,
	configId:     vcdmCredentialConfigId,
	issuedClaims: vcdmTestClaims,
	query: `{
		"id": "` + vcdmQueryId + `",
		"format": "vc+sd-jwt",
		"meta": {"type_values": [["` + vcdmVerifiableCredentialIri + `", "` + vcdmCredentialType + `"]]},
		"claims": [{"path": ["credentialSubject", "given_name"]}]
	}`,
	shownAs: claim([]any{"credentialSubject", "given_name"}, "Vera"),
	disclosed: func(t *testing.T, c *client.Client) []expectedClaim {
		return []expectedClaim{
			claim([]any{"given_name"}, "Vera"),
			claim([]any{"family_name"}, "Modell"),
			claim([]any{"email"}, "vera@example.com"),
			claim([]any{"id"}, vcdmHolderDid(t, requireSingleVcdmCredential(t, c).Attributes)),
		}
	},
}

// credentialSetQuery is one entry of DCQL credential_sets: a single option that
// names the given credentials. required and optional build one.
type credentialSetQuery struct {
	optional bool
	option   []*credentialFixture
}

func required(creds ...*credentialFixture) credentialSetQuery {
	return credentialSetQuery{option: creds}
}

func optional(creds ...*credentialFixture) credentialSetQuery {
	return credentialSetQuery{optional: true, option: creds}
}

// setChoice is what the user picks for one credential set: share the option,
// with the cards the scenario receives, or skip the set.
type setChoice bool

const (
	share setChoice = true
	skip  setChoice = false
)

type credentialSetScenario struct {
	name    string
	holds   []*credentialFixture
	request []credentialSetQuery
	choose  []setChoice // one per credential set, in request order
	// receives is what the verifier must receive. For a set the user shares,
	// it also says which copies to share, when the wallet holds several.
	receives []*credentialFixture
}

func runCredentialSetScenario(t *testing.T, s credentialSetScenario) {
	require.Len(t, s.choose, len(s.request), "a scenario picks once per credential set")

	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	sessionId := 0
	for _, cred := range s.holds {
		sessionId++
		issueCredentialViaOpenID4VCI(t, c, sessionId, sessionHandler, cred.configId, cred.issuedClaims)
	}

	verifier := createVeramoVerifierDcqlSessionWithQuery(t, credentialSetsDcqlQuery(t, s.requested(), s.request))
	sessionId++
	startOpenID4VPDisclosureSession(t, c, sessionId, verifier.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	s.requireOffered(t, session.DisclosurePlan)

	grantAnswer(t, c, session.Id, s.answer(t, session.DisclosurePlan, s.receives)...)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	s.requireReceived(t, c, checkVeramoVerifierOfferStatus(t, verifier.State))
}

// requireOffered checks the plan offers each credential set as one choice of
// one option, with a slot per query: the held copies as its candidates, and
// for a query without a held copy the type to obtain.
func (s credentialSetScenario) requireOffered(t *testing.T, plan *clientmodels.DisclosurePlan) {
	t.Helper()
	require.NotNil(t, plan)
	require.Len(t, plan.Choices, len(s.request), "each credential set is one choice")

	for i, set := range s.request {
		choice := plan.Choices[i]
		require.Equal(t, set.optional, choice.Optional, "credential set %d", i)
		require.Len(t, choice.Options, 1, "credential set %d has one option", i)
		slots := choice.Options[0].Slots
		require.Len(t, slots, len(set.option), "credential set %d: a slot per query", i)

		for j, cred := range set.option {
			slot := slots[j]
			require.Equal(t, cred.queryId, slot.Id)
			held := copiesFor(s.holds, cred)
			require.ElementsMatch(t, held, heldCopies(t, s.holds, slot.Candidates),
				"slot %q lists every held copy", slot.Id)
			if len(held) == 0 {
				var obtainable []string
				for _, descriptor := range slot.Obtainable {
					obtainable = append(obtainable, descriptor.CredentialId)
				}
				require.Equal(t, []string{cred.credentialId}, obtainable, "slot %q offers its type", slot.Id)
			} else {
				require.Empty(t, slot.Obtainable, "slot %q has a card, and its type cannot be added here", slot.Id)
			}
		}
	}
}

// answer picks, per credential set, the option with the copies in cards, or
// nothing for a skipped set.
func (s credentialSetScenario) answer(t *testing.T, plan *clientmodels.DisclosurePlan, cards []*credentialFixture) []clientmodels.ChoiceSelection {
	t.Helper()
	answer := make([]clientmodels.ChoiceSelection, 0, len(s.choose))
	for i, choice := range s.choose {
		if choice == skip {
			answer = append(answer, clientmodels.ChoiceSelection{Option: -1})
			continue
		}
		selection := clientmodels.ChoiceSelection{Option: 0}
		for j, cred := range s.request[i].option {
			wanted := copiesFor(cards, cred)
			require.Len(t, wanted, 1, "a shared set uses one copy for query %q", cred.queryId)
			slot := plan.Choices[i].Options[0].Slots[j]
			selection.Slots = append(selection.Slots, clientmodels.SlotSelection{
				SlotId:      slot.Id,
				Credentials: []clientmodels.SelectedCredential{selectWhole(candidateShowing(t, slot, wanted[0].shownAs))},
			})
		}
		answer = append(answer, selection)
	}
	return answer
}

// requireReceived checks the verifier received exactly the scenario's
// credentials, each under its own query id, once.
func (s credentialSetScenario) requireReceived(t *testing.T, c *client.Client, result veramoCheckResult) {
	t.Helper()
	require.Equal(t, "RESPONSE_RECEIVED", result.Status)
	require.NotNil(t, result.Result, "verifier result should not be nil")
	if len(s.receives) == 0 {
		require.Empty(t, result.Result.Credentials, "nothing may reach the verifier")
		return
	}

	// The verifier checks every query of the request, not just the ones in
	// vp_token. A query the wallet rightly leaves out (§ 8.1) shows up in its
	// result with no credentials and an "expects array of JWT tokens" error.
	var unanswered []string
	for _, cred := range s.requested() {
		if len(copiesFor(s.receives, cred)) == 0 {
			unanswered = append(unanswered, cred.queryId)
			require.Empty(t, result.Result.Credentials[cred.queryId], "query %q must not be answered", cred.queryId)
		}
	}
	requireNoVeramoVcdmErrors(t, result, unanswered...)

	for _, cred := range s.receives {
		// requireVerifierReceivedClaims reads only the first presentation of a
		// query, so a second copy sent alongside it would go unnoticed.
		require.Len(t, result.Result.Credentials[cred.queryId], 1, "query %q takes one presentation", cred.queryId)
		requireVerifierReceivedClaims(t, result, cred.queryId, cred.disclosed(t, c)...)
	}
}

// requested lists each credential query the request names once, in request
// order.
func (s credentialSetScenario) requested() []*credentialFixture {
	var creds []*credentialFixture
	for _, set := range s.request {
		for _, cred := range set.option {
			if len(copiesFor(creds, cred)) == 0 {
				creds = append(creds, cred)
			}
		}
	}
	return creds
}

// credentialSetsDcqlQuery builds the verifier's request: a credential query per
// requested credential, and the sets.
func credentialSetsDcqlQuery(t *testing.T, requested []*credentialFixture, sets []credentialSetQuery) string {
	t.Helper()
	type dcqlCredentialSet struct {
		Options  [][]string `json:"options"`
		Required bool       `json:"required"`
	}
	var queries []json.RawMessage
	for _, cred := range requested {
		queries = append(queries, json.RawMessage(cred.query))
	}
	var dcqlSets []dcqlCredentialSet
	for _, set := range sets {
		var option []string
		for _, cred := range set.option {
			option = append(option, cred.queryId)
		}
		dcqlSets = append(dcqlSets, dcqlCredentialSet{Options: [][]string{option}, Required: !set.optional})
	}
	query, err := json.Marshal(map[string]any{
		"dcql": map[string]any{"credentials": queries, "credential_sets": dcqlSets},
	})
	require.NoError(t, err)
	return string(query)
}

// One query in two sets is one slot with one presentation, so the answer must
// name the same card for it in both. Two different cards are refused before
// anything is sent.
func testOneQueryInTwoSetsWithDifferentCardsIsRefused(t *testing.T) {
	s := credentialSetScenario{
		holds:   []*credentialFixture{emailSdJwt, otherEmailSdJwt, phoneSdJwt, testSdJwt},
		request: []credentialSetQuery{required(emailSdJwt, phoneSdJwt), required(emailSdJwt, testSdJwt)},
		choose:  []setChoice{share, share},
	}
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()
	sessionId := 0
	for _, cred := range s.holds {
		sessionId++
		issueCredentialViaOpenID4VCI(t, c, sessionId, sessionHandler, cred.configId, cred.issuedClaims)
	}
	verifier := createVeramoVerifierDcqlSessionWithQuery(t, credentialSetsDcqlQuery(t, s.requested(), s.request))
	sessionId++
	startOpenID4VPDisclosureSession(t, c, sessionId, verifier.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	first := plan0Slot(t, session.DisclosurePlan, 0)
	second := plan0Slot(t, session.DisclosurePlan, 1)
	require.Equal(t, "email", first.Id)
	require.Equal(t, first, second, "one query is the same slot in both sets")

	answer := s.answer(t, session.DisclosurePlan, []*credentialFixture{emailSdJwt, phoneSdJwt, testSdJwt})
	answer[1].Slots[0].Credentials = []clientmodels.SelectedCredential{selectWhole(candidateShowing(t, second, otherEmailSdJwt.shownAs))}
	err := c.HandleUserInteraction(clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_Permission,
		Payload:   clientmodels.SessionPermissionInteractionPayload{Granted: true, Choices: answer},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "different cards in two choices")

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_Error)
	result := checkVeramoVerifierOfferStatus(t, verifier.State)
	require.NotContains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status, "nothing reached the verifier")
}

// A query with `multiple`: its slot takes one or more cards, and the vp_token
// holds a presentation per card under the query's id.
func testMultipleCardsForOneQuery(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()
	addresses := []string{"alice@example.com", "bob@example.com", "carol@example.com"}
	for i, address := range addresses {
		issueCredentialViaOpenID4VCI(t, c, i+1, sessionHandler, "EmailCredentialSdJwt", `{"email": "`+address+`", "domain": "example.com"}`)
	}
	dcqlQuery := `{"dcql": {"credentials": [{
		"id": "emails",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://localhost:8443/vct/email"]},
		"claims": [{"path": ["email"]}],
		"multiple": true
	}]}}`

	disclose := func(t *testing.T, sessionId int, pick ...string) (clientmodels.SessionState, error, veramoVerifierSession) {
		verifier := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
		startOpenID4VPDisclosureSession(t, c, sessionId, verifier.RequestUri)
		session := awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

		slot := plan0Slot(t, session.DisclosurePlan, 0)
		require.Equal(t, "emails", slot.Id)
		require.True(t, slot.Multiple)
		require.Len(t, slot.Candidates, 3)

		selection := clientmodels.SlotSelection{SlotId: slot.Id, Credentials: []clientmodels.SelectedCredential{}}
		for _, address := range pick {
			selection.Credentials = append(selection.Credentials, selectWhole(candidateShowing(t, slot, claim([]any{"email"}, address))))
		}
		err := c.HandleUserInteraction(clientmodels.SessionUserInteraction{
			SessionId: session.Id,
			Type:      clientmodels.UI_Permission,
			Payload: clientmodels.SessionPermissionInteractionPayload{Granted: true, Choices: []clientmodels.ChoiceSelection{
				{Option: 0, Slots: []clientmodels.SlotSelection{selection}},
			}},
		})
		return awaitSessionState(t, sessionHandler), err, verifier
	}

	t.Run("two of three", func(t *testing.T) {
		session, err, verifier := disclose(t, 4, addresses[0], addresses[2])
		require.NoError(t, err)
		requireSessionState(t, session, 4, clientmodels.Type_Disclosure, clientmodels.Status_Success)
		result := checkVeramoVerifierOfferStatus(t, verifier.State)
		require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
		require.Len(t, result.Result.Credentials["emails"], 2, "a presentation per card under the one query")
		var received []string
		for _, cred := range result.Result.Credentials["emails"] {
			received = append(received, cred.Claims["email"].(string))
		}
		require.ElementsMatch(t, []string{addresses[0], addresses[2]}, received)
	})

	t.Run("one", func(t *testing.T) {
		session, err, verifier := disclose(t, 5, addresses[1])
		require.NoError(t, err)
		requireSessionState(t, session, 5, clientmodels.Type_Disclosure, clientmodels.Status_Success)
		result := checkVeramoVerifierOfferStatus(t, verifier.State)
		require.Len(t, result.Result.Credentials["emails"], 1)
		requireVerifierReceivedClaims(t, result, "emails", claim([]any{"email"}, addresses[1]))
	})

	t.Run("none is refused", func(t *testing.T) {
		session, err, verifier := disclose(t, 6)
		require.Error(t, err)
		requireSessionState(t, session, 6, clientmodels.Type_Disclosure, clientmodels.Status_Error)
		result := checkVeramoVerifierOfferStatus(t, verifier.State)
		require.NotContains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	})
}

// A claim with several allowed values: a card holding one of them is the
// candidate, with every allowed value on it; a card holding another value is
// not; without a matching card, the obtainable type carries the values.
func testOneOfSeveralRequestedValues(t *testing.T) {
	dcqlQuery := `{"dcql": {"credentials": [{
		"id": "email",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://localhost:8443/vct/email"]},
		"claims": [{"path": ["domain"], "values": ["a.example", "b.example", "c.example"]}]
	}]}}`
	requireThreeValues := func(t *testing.T, attrs []clientmodels.Attribute) {
		t.Helper()
		i := slices.IndexFunc(attrs, func(a clientmodels.Attribute) bool {
			return clientmodels.ClaimPathKey(a.ClaimPath) == clientmodels.ClaimPathKey([]any{"domain"})
		})
		require.NotEqual(t, -1, i, "domain is shown")
		var values []string
		for _, v := range attrs[i].RequestedValues {
			require.NotNil(t, v.String)
			values = append(values, *v.String)
		}
		require.Equal(t, []string{"a.example", "b.example", "c.example"}, values)
	}

	t.Run("a card with the second value is shared", func(t *testing.T) {
		c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
		defer c.Close()
		issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "EmailCredentialSdJwt", `{"email": "b@b.example", "domain": "b.example"}`)
		issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "EmailCredentialSdJwt", `{"email": "z@z.example", "domain": "z.example"}`)

		verifier := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
		startOpenID4VPDisclosureSession(t, c, 3, verifier.RequestUri)
		session := awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

		slot := plan0Slot(t, session.DisclosurePlan, 0)
		require.Len(t, slot.Candidates, 1, "the card with another value is not a candidate")
		requireThreeValues(t, slot.Candidates[0].Attributes)

		grantAnswer(t, c, session.Id, firstOptionAnswer(t, session.DisclosurePlan)...)
		session = awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)
		result := checkVeramoVerifierOfferStatus(t, verifier.State)
		require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
		requireVerifierReceivedClaims(t, result, "email", claim([]any{"domain"}, "b.example"))
	})

	t.Run("without a matching card the type to add carries the values", func(t *testing.T) {
		c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
		defer c.Close()
		issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "EmailCredentialSdJwt", `{"email": "z@z.example", "domain": "z.example"}`)

		verifier := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
		startOpenID4VPDisclosureSession(t, c, 2, verifier.RequestUri)
		session := awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

		slot := plan0Slot(t, session.DisclosurePlan, 0)
		require.Empty(t, slot.Candidates)
		require.Len(t, slot.Obtainable, 1)
		requireThreeValues(t, slot.Obtainable[0].Attributes)
	})
}

// A query without claims, answered per slot. For an SD-JWT VC the verifier
// still receives the credential's always-disclosed claims, and the candidate
// shows them: here member_since, the only non-selectively-disclosable claim.
func testQueryWithoutClaimsAnsweredPerSlot(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()
	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "MembershipCredentialSdJwt", `{
		"member_name": "Alice",
		"member_since": "2020-01-01",
		"membership_type": "gold"
	}`)
	verifier := createVeramoVerifierDcqlSessionWithQuery(t, `{"dcql": {"credentials": [{
		"id": "membership-cred",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://localhost:8443/vct/membership"]}
	}]}}`)
	startOpenID4VPDisclosureSession(t, c, 2, verifier.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	slot := plan0Slot(t, session.DisclosurePlan, 0)
	require.Len(t, slot.Candidates, 1)
	var shown []string
	for _, attr := range slot.Candidates[0].Attributes {
		shown = append(shown, clientmodels.ClaimPathKey(attr.ClaimPath))
	}
	require.Equal(t, []string{clientmodels.ClaimPathKey([]any{"member_since"})}, shown)

	grantAnswer(t, c, session.Id, firstOptionAnswer(t, session.DisclosurePlan)...)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	result := checkVeramoVerifierOfferStatus(t, verifier.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "membership-cred", claim([]any{"member_since"}, "2020-01-01"))
}

// plan0Slot is the first slot of the first option of choice i.
func plan0Slot(t *testing.T, plan *clientmodels.DisclosurePlan, i int) clientmodels.DisclosureSlot {
	t.Helper()
	require.NotNil(t, plan)
	require.Greater(t, len(plan.Choices), i)
	require.NotEmpty(t, plan.Choices[i].Options)
	require.NotEmpty(t, plan.Choices[i].Options[0].Slots)
	return plan.Choices[i].Options[0].Slots[0]
}

// candidateShowing is the slot's candidate that shows the given claim value.
func candidateShowing(t *testing.T, slot clientmodels.DisclosureSlot, c expectedClaim) *clientmodels.SelectableCredentialInstance {
	t.Helper()
	i := slices.IndexFunc(slot.Candidates, func(candidate *clientmodels.SelectableCredentialInstance) bool {
		return shows(candidate, c)
	})
	require.NotEqual(t, -1, i, "slot %q has no card showing %v=%s", slot.Id, c.Path, c.Value)
	return slot.Candidates[i]
}

// selectWhole selects a candidate with every attribute it shows.
func selectWhole(candidate *clientmodels.SelectableCredentialInstance) clientmodels.SelectedCredential {
	var paths [][]any
	for _, attr := range candidate.Attributes {
		if attr.Value != nil {
			paths = append(paths, attr.ClaimPath)
		}
	}
	return clientmodels.SelectedCredential{CredentialId: candidate.CredentialId, CredentialHash: candidate.Hash, AttributePaths: paths}
}

// heldCopies says which held copy each candidate is.
func heldCopies(t *testing.T, holds []*credentialFixture, candidates []*clientmodels.SelectableCredentialInstance) []*credentialFixture {
	t.Helper()
	copies := []*credentialFixture{}
	for _, candidate := range candidates {
		i := slices.IndexFunc(holds, func(held *credentialFixture) bool {
			return held.credentialId == candidate.CredentialId && shows(candidate, held.shownAs)
		})
		require.NotEqual(t, -1, i, "candidate %s is none of the held copies", candidate.CredentialId)
		copies = append(copies, holds[i])
	}
	return copies
}

// shows reports whether the candidate shows the given claim value.
func shows(candidate *clientmodels.SelectableCredentialInstance, c expectedClaim) bool {
	return slices.ContainsFunc(candidate.Attributes, func(attr clientmodels.Attribute) bool {
		return clientmodels.ClaimPathKey(attr.ClaimPath) == clientmodels.ClaimPathKey(c.Path) &&
			attr.Value != nil && attr.Value.String != nil && *attr.Value.String == c.Value
	})
}

// copiesFor lists the credentials in creds that answer the same query as cred.
func copiesFor(creds []*credentialFixture, cred *credentialFixture) []*credentialFixture {
	var copies []*credentialFixture
	for _, c := range creds {
		if c.queryId == cred.queryId {
			copies = append(copies, c)
		}
	}
	return copies
}
