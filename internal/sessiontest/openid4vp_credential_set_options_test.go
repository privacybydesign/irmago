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
}

func testOpenID4VPCredentialSetOptions(t *testing.T) {
	for _, scenario := range credentialSetScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			runCredentialSetScenario(t, scenario)
		})
	}
}

// credentialFixture is test data for one credential: how the issuer issues it,
// the DCQL credential query that asks for it, and the claims that query
// discloses.
type credentialFixture struct {
	queryId string
	// credentialId is the id the wallet shows for the credential, owned or
	// obtainable.
	credentialId string
	configId     string
	issuedClaims string
	query        string
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
	disclosed: func(*testing.T, *client.Client) []expectedClaim {
		return []expectedClaim{claim([]any{"email"}, "test@example.com")}
	},
}

var emailSdJwt = &credentialFixture{
	queryId:      "email",
	credentialId: "https://localhost:8443/vct/email",
	configId:     "EmailCredentialSdJwt",
	issuedClaims: `{"email": "email@example.com", "domain": "example.com"}`,
	query: `{
		"id": "email",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://localhost:8443/vct/email"]},
		"claims": [{"path": ["email"]}]
	}`,
	disclosed: func(*testing.T, *client.Client) []expectedClaim {
		return []expectedClaim{claim([]any{"email"}, "email@example.com")}
	},
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

// setChoice is what the user picks for one credential set: share the one
// bundle the wallet offers, or skip the set.
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
			choices[i] = makeDisclosureChoice(session.DisclosurePlan.DisclosureChoicesOverview[i].OwnedOptions[0])
		}
	}
	grantPermission(t, c, session.Id, choices...)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	s.requireReceived(t, c, checkVeramoVerifierOfferStatus(t, verifier.State))
}

// requireOffered checks the plan offers each credential set as one choice: a
// complete set as one bundle of its credentials in the option's order, and an
// incomplete set with no bundle and only its missing credentials to obtain.
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
			require.Len(t, offered.OwnedOptions, 1, "credential set %d is offered as one bundle", i)
			var bundleIds []string
			for _, cred := range offered.OwnedOptions[0].Credentials {
				bundleIds = append(bundleIds, cred.CredentialId)
			}
			require.Equal(t, credentialIds(set.option), bundleIds, "credential set %d", i)
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
		if !slices.Contains(s.receives, cred) {
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

// requested lists each credential the request names once, in request order.
func (s credentialSetScenario) requested() []*credentialFixture {
	var creds []*credentialFixture
	for _, set := range s.request {
		for _, cred := range set.option {
			if !slices.Contains(creds, cred) {
				creds = append(creds, cred)
			}
		}
	}
	return creds
}

func (s credentialSetScenario) missingFrom(set credentialSetQuery) []*credentialFixture {
	var missing []*credentialFixture
	for _, cred := range set.option {
		if !slices.Contains(s.holds, cred) {
			missing = append(missing, cred)
		}
	}
	return missing
}

func credentialIds(creds []*credentialFixture) []string {
	ids := make([]string, 0, len(creds))
	for _, cred := range creds {
		ids = append(ids, cred.credentialId)
	}
	return ids
}
