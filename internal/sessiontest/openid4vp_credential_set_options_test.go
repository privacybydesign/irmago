package sessiontest

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// Credential set options that name several credential queries, such as
// `"options": [["test", "vcdm"]]`. The credentials of such an option are shared
// together or not at all (OpenID4VP 1.0 § 6.2). The pair mixes formats on
// purpose, an SD-JWT VC and a VCDM credential, as eduwallet's exam check-in does.
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
		// Half of the optional pair is missing. Only that half is offered to
		// obtain, and because the set is optional, the session does not start
		// with an issuance step.
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
		// Two copies of each credential make four pairs. The user shares a pair
		// that is not the first one offered, and exactly that pair arrives.
		name:     "a required pair with two copies of each, the second phone and first email shared",
		holds:    []*credentialFixture{phoneSdJwt, otherPhoneSdJwt, emailSdJwt, otherEmailSdJwt},
		request:  []credentialSetQuery{required(phoneSdJwt, emailSdJwt)},
		choose:   []setChoice{share},
		receives: []*credentialFixture{otherPhoneSdJwt, emailSdJwt},
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

// setChoice is what the user picks for one credential set: share the bundle
// made of the credentials the scenario receives, or skip the set.
type setChoice bool

const (
	share setChoice = true
	skip  setChoice = false
)

type credentialSetScenario struct {
	name     string
	holds    []*credentialFixture
	request  []credentialSetQuery
	choose   []setChoice // one per credential set, in request order
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

	verifier := createVeramoVerifierDcqlSessionWithQuery(t, s.dcqlQuery(t))
	sessionId++
	startOpenID4VPDisclosureSession(t, c, sessionId, verifier.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	s.requireOffered(t, session.DisclosurePlan)

	choices := make([]clientmodels.DisclosureDisconSelection, len(s.choose))
	for i, choice := range s.choose {
		if choice == share {
			choices[i] = makeDisclosureChoice(s.bundleToShare(t, i, session.DisclosurePlan.DisclosureChoicesOverview[i]))
		}
	}
	grantPermission(t, c, session.Id, choices...)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	s.requireReceived(t, c, checkVeramoVerifierOfferStatus(t, verifier.State))
}

// requireOffered checks the plan offers each credential set as one choice. A
// complete set offers one bundle per combination of the held copies, each in
// the option's order. An incomplete set offers no bundle, and only its missing
// credentials to obtain.
func (s credentialSetScenario) requireOffered(t *testing.T, plan *clientmodels.DisclosurePlan) {
	t.Helper()
	require.NotNil(t, plan)
	require.Nil(t, plan.IssueDuringDisclosure, "no scenario has a required set the wallet cannot answer")
	require.Len(t, plan.DisclosureChoicesOverview, len(s.request), "each credential set is one choice")

	for i, set := range s.request {
		offered := plan.DisclosureChoicesOverview[i]
		require.Equal(t, set.optional, offered.Optional, "credential set %d", i)

		missing := s.missingFrom(set)
		if len(missing) == 0 {
			var offeredBundles [][]*credentialFixture
			for _, bundle := range offered.OwnedOptions {
				offeredBundles = append(offeredBundles, s.heldCopies(t, bundle))
			}
			require.ElementsMatch(t, s.combinationsOf(set), offeredBundles,
				"credential set %d offers a bundle per combination of held copies", i)
			continue
		}

		require.Empty(t, offered.OwnedOptions, "credential set %d is incomplete, so it has no bundle", i)
		var obtainableIds []string
		for _, descriptor := range offered.ObtainableOptions {
			obtainableIds = append(obtainableIds, descriptor.CredentialId)
		}
		require.Equal(t, credentialIds(missing), obtainableIds,
			"credential set %d offers only its missing credentials to obtain", i)
	}
}

// requireReceived checks the verifier received exactly the scenario's
// credentials, each under its own query id.
func (s credentialSetScenario) requireReceived(t *testing.T, c *client.Client, result veramoCheckResult) {
	t.Helper()
	if len(s.receives) == 0 {
		require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
		if result.Result != nil {
			require.Empty(t, result.Result.Credentials)
		}
		return
	}

	require.Equal(t, "RESPONSE_RECEIVED", result.Status)

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
		requireVerifierReceivedClaims(t, result, cred.queryId, cred.disclosed(t, c)...)
	}
}

// dcqlQuery builds the verifier's request: a credential query per credential the
// sets name, and the sets themselves.
func (s credentialSetScenario) dcqlQuery(t *testing.T) string {
	t.Helper()
	type dcqlCredentialSet struct {
		Options  [][]string `json:"options"`
		Required bool       `json:"required"`
	}
	var queries []json.RawMessage
	for _, cred := range s.requested() {
		queries = append(queries, json.RawMessage(cred.query))
	}
	var sets []dcqlCredentialSet
	for _, set := range s.request {
		var option []string
		for _, cred := range set.option {
			option = append(option, cred.queryId)
		}
		sets = append(sets, dcqlCredentialSet{Options: [][]string{option}, Required: !set.optional})
	}

	query, err := json.Marshal(map[string]any{
		"dcql": map[string]any{"credentials": queries, "credential_sets": sets},
	})
	require.NoError(t, err)
	return string(query)
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

func (s credentialSetScenario) missingFrom(set credentialSetQuery) []*credentialFixture {
	var missing []*credentialFixture
	for _, cred := range set.option {
		if len(copiesFor(s.holds, cred)) == 0 {
			missing = append(missing, cred)
		}
	}
	return missing
}

// combinationsOf lists every bundle of held copies that answers the set's
// option: one copy per query, in the option's order.
func (s credentialSetScenario) combinationsOf(set credentialSetQuery) [][]*credentialFixture {
	combinations := [][]*credentialFixture{{}}
	for _, cred := range set.option {
		var next [][]*credentialFixture
		for _, prefix := range combinations {
			for _, held := range copiesFor(s.holds, cred) {
				next = append(next, append(slices.Clone(prefix), held))
			}
		}
		combinations = next
	}
	return combinations
}

// bundleToShare is the offered bundle made of the copies the scenario receives
// for set i.
func (s credentialSetScenario) bundleToShare(t *testing.T, i int, offered clientmodels.DisclosurePickOne) *clientmodels.DisclosureBundle {
	t.Helper()
	var wanted []*credentialFixture
	for _, cred := range s.request[i].option {
		received := copiesFor(s.receives, cred)
		require.Len(t, received, 1, "a shared set receives one copy of query %q", cred.queryId)
		wanted = append(wanted, received[0])
	}
	for _, bundle := range offered.OwnedOptions {
		if slices.Equal(s.heldCopies(t, bundle), wanted) {
			return bundle
		}
	}
	require.FailNow(t, "no offered bundle holds the credentials to share", "credential set %d", i)
	return nil
}

// heldCopies says which held copy each credential of an offered bundle is.
func (s credentialSetScenario) heldCopies(t *testing.T, bundle *clientmodels.DisclosureBundle) []*credentialFixture {
	t.Helper()
	copies := make([]*credentialFixture, 0, len(bundle.Credentials))
	for _, offered := range bundle.Credentials {
		i := slices.IndexFunc(s.holds, func(held *credentialFixture) bool {
			return held.credentialId == offered.CredentialId && shows(offered, held.shownAs)
		})
		require.NotEqual(t, -1, i, "offered credential %s is none of the held copies", offered.CredentialId)
		copies = append(copies, s.holds[i])
	}
	return copies
}

// shows reports whether the offered credential shows the given claim value.
func shows(offered *clientmodels.SelectableCredentialInstance, c expectedClaim) bool {
	return slices.ContainsFunc(offered.Attributes, func(attr clientmodels.Attribute) bool {
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

func credentialIds(creds []*credentialFixture) []string {
	ids := make([]string, 0, len(creds))
	for _, cred := range creds {
		ids = append(ids, cred.credentialId)
	}
	return ids
}
