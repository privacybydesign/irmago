package sessiontest

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
)

// ============================================================================
// PID and mDL as mdoc
//
// Every other mdoc in this suite is the age credential: one namespace, boolean
// elements, nothing else. The reference issuer also mints a PID and an mDL as
// mso_mdoc, and those carry what the age credential cannot: tagged dates, an
// integer, a nested object, arrays, a portrait. The subtests here issue both
// into one wallet and then ask for them in the combinations a relying party
// would, so that each value type crosses the permission screen, the wire and the
// activity log at least once.
//
// The issuer fills in its own elements on top of what the offer supplies:
// issuance and expiry dates ninety days apart, the issuing authority and
// country. Those are read back from the credential list rather than predicted,
// so a run across midnight does not fail on a date.
// ============================================================================

const (
	pidMdocConfigId    = "eu.europa.ec.eudi.pid_mdoc"
	pidMdocDocType     = "eu.europa.ec.eudi.pid.1"
	pidMdocNamespace   = "eu.europa.ec.eudi.pid.1"
	pidMdocDisplayName = "PID (MSO Mdoc)"

	mdlConfigId    = "eu.europa.ec.eudi.mdl_mdoc"
	mdlDocType     = "org.iso.18013.5.1.mDL"
	mdlNamespace   = "org.iso.18013.5.1"
	mdlDisplayName = "mDL (MSO Mdoc)"

	pidMdocQueryId = "pid"
	mdlQueryId     = "mdl"

	mdlLicenceNumber = "X1234"
	// A one-pixel PNG, base64 as the offer endpoint takes it.
	mdlPortrait = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)

// mdlPortraitBytes is the portrait as the issuer signs it into the mDL.
func mdlPortraitBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(mdlPortrait)
	require.NoError(t, err)
	return raw
}

func testSessionHandlerForOpenID4VPWithPidAndMdlMdocs(t *testing.T) {
	t.Run(
		"issuance/a pid and an mdl are issued as mdoc and both are logged",
		testPidAndMdlMdocIssuance,
	)

	t.Run(
		"disclosure/pid names",
		testOpenID4VP_PidMdoc_Names,
	)
	t.Run(
		"disclosure/pid integer with a value constraint",
		testOpenID4VP_PidMdoc_IntegerValueConstraint,
	)
	t.Run(
		"disclosure/dates from both credentials",
		testOpenID4VP_PidMdlMdoc_Dates,
	)
	t.Run(
		"disclosure/structured values from both credentials",
		testOpenID4VP_PidMdlMdoc_StructuredValues,
	)
	t.Run(
		"disclosure/mdl licence number and portrait",
		testOpenID4VP_Mdl_LicenceNumberAndPortrait,
	)
	t.Run(
		"disclosure/two doctypes in one request",
		testOpenID4VP_PidMdlMdoc_TwoDocTypes,
	)
	t.Run(
		"disclosure/a credential_sets choice across doctypes",
		testOpenID4VP_PidMdlMdoc_CredentialSetChoice,
	)
}

// testPidAndMdlMdocIssuance issues both credentials and checks what the wallet
// made of them: the credential list entries, and one issuance log entry per
// credential carrying the same attributes and dates the list shows.
func testPidAndMdlMdocIssuance(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidAndMdlMdocs(t, c, sessionHandler)

	pid := credentialListEntry(t, c, pidMdocDocType)
	require.Equal(t, pidMdocDisplayName, pid.Name)
	require.Equal(t, avIssuerDisplayName, pid.Issuer.Name)
	require.Contains(t, pid.CredentialInstanceIds, clientmodels.Format_MsoMdoc)
	require.Greater(t, *pid.BatchInstanceCountsRemaining[clientmodels.Format_MsoMdoc], uint(1))

	mdl := credentialListEntry(t, c, mdlDocType)
	require.Equal(t, mdlDisplayName, mdl.Name)
	require.Equal(t, avIssuerDisplayName, mdl.Issuer.Name)
	require.Contains(t, mdl.CredentialInstanceIds, clientmodels.Format_MsoMdoc)
	require.Greater(t, *mdl.BatchInstanceCountsRemaining[clientmodels.Format_MsoMdoc], uint(1))

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 2, "one issuance entry per credential and nothing else")

	for _, cred := range []*clientmodels.Credential{pid, mdl} {
		entry := findIssuanceLog(t, logs, cred.CredentialId)
		require.Equal(t, clientmodels.Protocol_OpenID4VCI, entry.Protocol)
		require.NotNil(t, entry.Issuer)
		require.Equal(t, avIssuerDisplayName, entry.Issuer.Name)
		require.Len(t, entry.Credentials, 1)

		requireLogCredential(
			t,
			entry.Credentials[0],
			expectedLogCredential{
				CredentialId: cred.CredentialId,
				Formats:      []clientmodels.CredentialFormat{clientmodels.Format_MsoMdoc},
				Name:         new(cred.Name),
				IssuerName:   new(avIssuerDisplayName),
				Attributes:   expectedAttrsOf(cred.Attributes),
				IssuanceDate: cred.IssuanceDate,
				ExpiryDate:   cred.ExpiryDate,
			},
			cred.CredentialId+" issuance entry",
		)
	}
}

// testOpenID4VP_PidMdoc_Names asks the PID for its two name strings.
func testOpenID4VP_PidMdoc_Names(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidAndMdlMdocs(t, c, sessionHandler)

	dcql := `{
		"credentials": [
			{
				"id": "pid",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
				"claims": [
					{ "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
					{ "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
				]
			}
		]
	}`
	testSession, requestJwt := startMdocDcqlSession(t, c, 3, sessionHandler, dcql)

	session := testSession.ClientSession
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{pidMdocPlanCredential(pidMdocNameAttrs()...)}},
			},
		},
	)

	approvedRequestor := session.Requestor
	grantFirstOwnedOptions(t, c, 3, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	presented := requireSingleDeviceResponse(t, walletResponse, pidMdocQueryId)
	elements := requireMdocPresentationVerifies(
		t,
		presented,
		pidMdocNamespace,
		pidMdocDocType,
		avSessionTranscript(t, requestJwt),
	)
	require.Equal(
		t,
		map[string]any{
			"family_name": samplePidUserData().FamilyName,
			"given_name":  samplePidUserData().GivenName,
		},
		elements,
	)

	requireDisclosureLogWith(
		t,
		c,
		approvedRequestor,
		pidMdocLogCredential(t, c, pidMdocNameAttrs()...),
	)
}

// testOpenID4VP_PidMdoc_IntegerValueConstraint asks for the PID's sex element
// under a DCQL values constraint, once satisfied and once not.
//
// The value travels as a CBOR unsigned integer, is cached as a JSON number and
// is compared against the integer in the query. The AV suite covers the same
// path for a boolean; this is the first integer through it.
func testOpenID4VP_PidMdoc_IntegerValueConstraint(t *testing.T) {
	t.Run(
		"a matching value is offered and disclosed",
		func(t *testing.T) {
			c, sessionHandler := createPidIssuerTestClient(t)
			defer c.Close()

			issuePidAndMdlMdocs(t, c, sessionHandler)

			dcql := `{
				"credentials": [
					{
						"id": "pid",
						"format": "mso_mdoc",
						"meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
						"claims": [
							{ "path": ["eu.europa.ec.eudi.pid.1", "sex"], "values": [2] }
						]
					}
				]
			}`
			testSession, requestJwt := startMdocDcqlSession(t, c, 3, sessionHandler, dcql)

			session := testSession.ClientSession
			requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

			sexAttr := pidMdocAttr("sex", "Sex", intVal(pidSex))
			sexAttr.RequestedValue = intVal(pidSex)
			requireDisclosurePlan(
				t,
				session.DisclosurePlan,
				expectedDisclosurePlan{
					Choices: []expectedPickOneChoice{
						{Owned: []expectedPlanCredential{pidMdocPlanCredential(sexAttr)}},
					},
				},
			)

			approvedRequestor := session.Requestor
			grantFirstOwnedOptions(t, c, 3, session)

			session = awaitSessionState(t, sessionHandler)
			requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

			walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
			presented := requireSingleDeviceResponse(t, walletResponse, pidMdocQueryId)
			elements := requireMdocPresentationVerifies(
				t,
				presented,
				pidMdocNamespace,
				pidMdocDocType,
				avSessionTranscript(t, requestJwt),
			)
			require.Equal(t, map[string]any{"sex": pidSex}, elements)

			requireDisclosureLogWith(
				t,
				c,
				approvedRequestor,
				pidMdocLogCredential(t, c, pidMdocAttr("sex", "Sex", intVal(pidSex))),
			)
		},
	)

	t.Run(
		"an unsatisfied value offers nothing and logs nothing",
		func(t *testing.T) {
			c, sessionHandler := createPidIssuerTestClient(t)
			defer c.Close()

			issuePidAndMdlMdocs(t, c, sessionHandler)

			dcql := `{
				"credentials": [
					{
						"id": "pid",
						"format": "mso_mdoc",
						"meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
						"claims": [
							{ "path": ["eu.europa.ec.eudi.pid.1", "sex"], "values": [3] }
						]
					}
				]
			}`
			testSession, _ := startMdocDcqlSession(t, c, 3, sessionHandler, dcql)

			session := testSession.ClientSession
			if session.Status != clientmodels.Status_Error {
				requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
				for _, choice := range session.DisclosurePlan.DisclosureChoicesOverview {
					require.Empty(
						t,
						choice.OwnedOptions,
						"the wallet offered a credential whose sex does not match the constrained value",
					)
				}
			}

			requireNoDisclosureLog(t, c)
		},
	)
}

// testOpenID4VP_PidMdlMdoc_Dates asks for a tagged date from each credential:
// the PID's birth date and the mDL's expiry date.
//
// Both travel as CBOR tag 1004 full-dates. The verifier decodes them correctly,
// which is checked first. The permission screen and the log have to show the
// date itself under its label, and today they show the decoded tag as a Go map,
// so the wire is verified before the screen so that a red screen still reports
// what left the wallet.
func testOpenID4VP_PidMdlMdoc_Dates(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidAndMdlMdocs(t, c, sessionHandler)

	dcql := `{
		"credentials": [
			{
				"id": "pid",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
				"claims": [
					{ "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
				]
			},
			{
				"id": "mdl",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
				"claims": [
					{ "path": ["org.iso.18013.5.1", "expiry_date"] }
				]
			}
		]
	}`
	testSession, requestJwt := startMdocDcqlSession(t, c, 3, sessionHandler, dcql)

	session := testSession.ClientSession
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 2)

	approvedRequestor := session.Requestor
	plan := session.DisclosurePlan
	grantFirstOwnedOptions(t, c, 3, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	mdlExpiry := mdocDateFromCredentialList(t, c, mdlDocType, mdlNamespace, "expiry_date")
	transcript := avSessionTranscript(t, requestJwt)
	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)

	pidPresented := requireSingleDeviceResponse(t, walletResponse, pidMdocQueryId)
	pidElements := requireMdocPresentationVerifies(t, pidPresented, pidMdocNamespace, pidMdocDocType, transcript)
	require.Equal(t, map[string]any{"birth_date": samplePidUserData().Birthdate}, pidElements)

	mdlPresented := requireSingleDeviceResponse(t, walletResponse, mdlQueryId)
	mdlElements := requireMdocPresentationVerifies(t, mdlPresented, mdlNamespace, mdlDocType, transcript)
	require.Equal(t, map[string]any{"expiry_date": mdlExpiry}, mdlElements)

	birthDateAttr := pidMdocAttr("birth_date", "Birth Date", strVal(samplePidUserData().Birthdate))
	expiryAttr := mdlAttr("expiry_date", "Expiry Date", strVal(mdlExpiry))

	requireDisclosurePlan(
		t,
		plan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{pidMdocPlanCredential(birthDateAttr)}},
				{Owned: []expectedPlanCredential{mdlPlanCredential(expiryAttr)}},
			},
		},
	)

	requireDisclosureLogWith(
		t,
		c,
		approvedRequestor,
		pidMdocLogCredential(t, c, birthDateAttr),
		mdlLogCredential(t, c, expiryAttr),
	)
}

// testOpenID4VP_PidMdlMdoc_StructuredValues asks for the PID's place of birth
// (a map) and nationality (an array) and the mDL's driving privileges (an array
// of maps).
//
// The verifier receives the structures intact, checked first. On the permission
// screen and in the log the wallet already has one rendering for these values:
// the flattened rows the credential list shows for the same credential, so that
// is what both are held to. Today they show Go map and slice text instead.
func testOpenID4VP_PidMdlMdoc_StructuredValues(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidAndMdlMdocs(t, c, sessionHandler)

	dcql := `{
		"credentials": [
			{
				"id": "pid",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
				"claims": [
					{ "path": ["eu.europa.ec.eudi.pid.1", "place_of_birth"] },
					{ "path": ["eu.europa.ec.eudi.pid.1", "nationality"] }
				]
			},
			{
				"id": "mdl",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
				"claims": [
					{ "path": ["org.iso.18013.5.1", "driving_privileges"] }
				]
			}
		]
	}`
	testSession, requestJwt := startMdocDcqlSession(t, c, 3, sessionHandler, dcql)

	session := testSession.ClientSession
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 2)

	approvedRequestor := session.Requestor
	plan := session.DisclosurePlan
	grantFirstOwnedOptions(t, c, 3, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	transcript := avSessionTranscript(t, requestJwt)
	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)

	pidPresented := requireSingleDeviceResponse(t, walletResponse, pidMdocQueryId)
	pidElements := requireMdocPresentationVerifies(t, pidPresented, pidMdocNamespace, pidMdocDocType, transcript)
	require.Equal(
		t,
		map[string]any{
			"place_of_birth": map[string]any{"country": pidBirthCountry, "locality": pidBirthLocality},
			"nationality":    []any{pidNationality},
		},
		pidElements,
	)

	mdlPresented := requireSingleDeviceResponse(t, walletResponse, mdlQueryId)
	mdlElements := requireMdocPresentationVerifies(t, mdlPresented, mdlNamespace, mdlDocType, transcript)
	require.Equal(
		t,
		map[string]any{
			"driving_privileges": []any{map[string]any{"vehicle_category_code": mdlVehicleCategory}},
		},
		mdlElements,
	)

	pidRows := credentialListRowsUnder(t, c, pidMdocDocType, pidMdocNamespace, "place_of_birth")
	pidRows = append(pidRows, credentialListRowsUnder(t, c, pidMdocDocType, pidMdocNamespace, "nationality")...)
	mdlRows := credentialListRowsUnder(t, c, mdlDocType, mdlNamespace, "driving_privileges")

	requireDisclosurePlan(
		t,
		plan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{pidMdocPlanCredential(pidRows...)}},
				{Owned: []expectedPlanCredential{mdlPlanCredential(mdlRows...)}},
			},
		},
	)

	requireDisclosureLogWith(
		t,
		c,
		approvedRequestor,
		pidMdocLogCredential(t, c, pidRows...),
		mdlLogCredential(t, c, mdlRows...),
	)
}

// testOpenID4VP_Mdl_LicenceNumberAndPortrait asks the mDL for its licence number
// and portrait.
//
// The portrait travels as a CBOR byte string, the issuer having decoded the
// base64 the offer supplied. The wallet shows those bytes base64-encoded again,
// so the screen and the log carry the text the offer started from, while the
// verifier receives the image bytes themselves.
func testOpenID4VP_Mdl_LicenceNumberAndPortrait(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidAndMdlMdocs(t, c, sessionHandler)

	dcql := `{
		"credentials": [
			{
				"id": "mdl",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
				"claims": [
					{ "path": ["org.iso.18013.5.1", "document_number"] },
					{ "path": ["org.iso.18013.5.1", "portrait"] }
				]
			}
		]
	}`
	testSession, requestJwt := startMdocDcqlSession(t, c, 3, sessionHandler, dcql)

	attrs := []expectedAttr{
		mdlAttr("document_number", "Licence number", strVal(mdlLicenceNumber)),
		mdlAttr("portrait", "Portrait", strVal(mdlPortrait)),
	}

	session := testSession.ClientSession
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{mdlPlanCredential(attrs...)}},
			},
		},
	)

	approvedRequestor := session.Requestor
	grantFirstOwnedOptions(t, c, 3, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	presented := requireSingleDeviceResponse(t, walletResponse, mdlQueryId)
	elements := requireMdocPresentationVerifies(
		t,
		presented,
		mdlNamespace,
		mdlDocType,
		avSessionTranscript(t, requestJwt),
	)
	require.Equal(
		t,
		map[string]any{
			"document_number": mdlLicenceNumber,
			"portrait":        mdlPortraitBytes(t),
		},
		elements,
	)

	requireDisclosureLogWith(t, c, approvedRequestor, mdlLogCredential(t, c, attrs...))
}

// testOpenID4VP_PidMdlMdoc_TwoDocTypes asks for one element of each credential
// in one request.
//
// Two different credentials answer two queries, so each presentation lands under
// its own query id and the log lists two credentials of two docTypes. This is
// the shape the age two-query test cannot reach, where one credential answers
// both and the plan's hash-to-query map keeps only the last.
func testOpenID4VP_PidMdlMdoc_TwoDocTypes(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidAndMdlMdocs(t, c, sessionHandler)

	dcql := `{
		"credentials": [
			{
				"id": "pid",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
				"claims": [
					{ "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
				]
			},
			{
				"id": "mdl",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
				"claims": [
					{ "path": ["org.iso.18013.5.1", "document_number"] }
				]
			}
		]
	}`
	testSession, requestJwt := startMdocDcqlSession(t, c, 3, sessionHandler, dcql)

	givenNameAttr := pidMdocAttr("given_name", "Given Name(s)", strVal(samplePidUserData().GivenName))
	licenceAttr := mdlAttr("document_number", "Licence number", strVal(mdlLicenceNumber))

	session := testSession.ClientSession
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{pidMdocPlanCredential(givenNameAttr)}},
				{Owned: []expectedPlanCredential{mdlPlanCredential(licenceAttr)}},
			},
		},
	)

	approvedRequestor := session.Requestor
	grantFirstOwnedOptions(t, c, 3, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	transcript := avSessionTranscript(t, requestJwt)
	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)

	pidPresented := requireSingleDeviceResponse(t, walletResponse, pidMdocQueryId)
	pidElements := requireMdocPresentationVerifies(t, pidPresented, pidMdocNamespace, pidMdocDocType, transcript)
	require.Equal(t, map[string]any{"given_name": samplePidUserData().GivenName}, pidElements)

	mdlPresented := requireSingleDeviceResponse(t, walletResponse, mdlQueryId)
	mdlElements := requireMdocPresentationVerifies(t, mdlPresented, mdlNamespace, mdlDocType, transcript)
	require.Equal(t, map[string]any{"document_number": mdlLicenceNumber}, mdlElements)

	requireDisclosureLogWith(
		t,
		c,
		approvedRequestor,
		pidMdocLogCredential(t, c, givenNameAttr),
		mdlLogCredential(t, c, licenceAttr),
	)
}

// testOpenID4VP_PidMdlMdoc_CredentialSetChoice offers the PID and the mDL as
// alternatives. The user picks the mDL, and the PID's query id is absent from
// what the verifier receives and from the log.
func testOpenID4VP_PidMdlMdoc_CredentialSetChoice(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidAndMdlMdocs(t, c, sessionHandler)

	dcql := `{
		"credentials": [
			{
				"id": "pid",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
				"claims": [
					{ "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
				]
			},
			{
				"id": "mdl",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
				"claims": [
					{ "path": ["org.iso.18013.5.1", "document_number"] }
				]
			}
		],
		"credential_sets": [
			{ "options": [["pid"], ["mdl"]] }
		]
	}`
	testSession, requestJwt := startMdocDcqlSession(t, c, 3, sessionHandler, dcql)

	givenNameAttr := pidMdocAttr("given_name", "Given Name(s)", strVal(samplePidUserData().GivenName))
	licenceAttr := mdlAttr("document_number", "Licence number", strVal(mdlLicenceNumber))

	session := testSession.ClientSession
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{
					pidMdocPlanCredential(givenNameAttr),
					mdlPlanCredential(licenceAttr),
				}},
			},
		},
	)

	approvedRequestor := session.Requestor
	chosen := ownedOptionWithCredentialId(t, session.DisclosurePlan.DisclosureChoicesOverview[0], mdlDocType)
	grantPermission(t, c, 3, makeDisclosureChoice(chosen))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	requireQueryAbsent(t, walletResponse, pidMdocQueryId)

	presented := requireSingleDeviceResponse(t, walletResponse, mdlQueryId)
	elements := requireMdocPresentationVerifies(
		t,
		presented,
		mdlNamespace,
		mdlDocType,
		avSessionTranscript(t, requestJwt),
	)
	require.Equal(t, map[string]any{"document_number": mdlLicenceNumber}, elements)

	requireDisclosureLogWith(t, c, approvedRequestor, mdlLogCredential(t, c, licenceAttr))
}

// ----------------------------------------------------------------------------
// Issuance
// ----------------------------------------------------------------------------

const (
	pidBirthCountry    = "NL"
	pidBirthLocality   = "Amsterdam"
	pidNationality     = "NL"
	pidResidentCity    = "Utrecht"
	mdlVehicleCategory = "B"
)

// pidSex is the ISO/IEC 5218 code the PID is issued with, as the int64 the
// normalised verifier output and the wallet's attribute values both use.
const pidSex int64 = 2

// issuePidAndMdlMdocs issues the reference issuer's PID and mDL as mso_mdoc into
// the wallet, as sessions 1 and 2, for the same person the SD-JWT PID tests use.
func issuePidAndMdlMdocs(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler) {
	t.Helper()
	issueMdocViaPythonIssuer(t, c, 1, sessionHandler, pidMdocConfigId, pidMdocIssuanceData())
	issueMdocViaPythonIssuer(t, c, 2, sessionHandler, mdlConfigId, mdlIssuanceData())
}

// pidMdocIssuanceData is what the offer asks the issuer to put in the PID. The
// issuer adds issuance and expiry dates, issuing authority and country itself.
func pidMdocIssuanceData() map[string]any {
	person := samplePidUserData()
	return map[string]any{
		"family_name":    person.FamilyName,
		"given_name":     person.GivenName,
		"birth_date":     person.Birthdate,
		"place_of_birth": map[string]any{"country": pidBirthCountry, "locality": pidBirthLocality},
		"nationality":    []string{pidNationality},
		"sex":            pidSex,
		"resident_city":  pidResidentCity,
	}
}

// mdlIssuanceData is what the offer asks the issuer to put in the mDL. Every
// element the mDL metadata marks mandatory and does not fill itself has to be
// here, or the wallet refuses the credential at issuance.
func mdlIssuanceData() map[string]any {
	person := samplePidUserData()
	return map[string]any{
		"family_name":        person.FamilyName,
		"given_name":         person.GivenName,
		"birth_date":         person.Birthdate,
		"document_number":    mdlLicenceNumber,
		"portrait":           mdlPortrait,
		"driving_privileges": []any{map[string]any{"vehicle_category_code": mdlVehicleCategory}},
	}
}

// issueMdocViaPythonIssuer drives the pre-authorized flow for any mdoc
// configuration the reference issuer publishes, with the given offer data.
func issueMdocViaPythonIssuer(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
	credentialConfigId string,
	data map[string]any,
) {
	t.Helper()

	status, body := postAvMdocOfferRequest(
		t,
		map[string]any{
			"credentials": []map[string]any{
				{"credential_configuration_id": credentialConfigId, "data": data},
			},
		},
	)
	require.Equal(
		t,
		http.StatusOK,
		status,
		"the issuer should mint an offer for %s: %s",
		credentialConfigId,
		body,
	)

	var offerJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &offerJSON))
	txCode := extractTxCodeValue(t, offerJSON)
	require.NotEmpty(t, txCode, "the offer must embed a tx_code")

	startOpenID4VCISession(t, c, sessionId, offerUriFromJson(t, offerJSON))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(
		t,
		session,
		sessionId,
		clientmodels.Type_Issuance,
		clientmodels.Status_RequestPreAuthorizedCode,
	)

	userInteraction(
		t,
		c,
		clientmodels.SessionUserInteraction{
			SessionId: session.Id,
			Type:      clientmodels.UI_PreAuthorizedCode,
			Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
				Proceed:         true,
				TransactionCode: &txCode,
			},
		},
	)

	session = awaitSessionState(t, sessionHandler)
	if session.Status == clientmodels.Status_Error && session.Error != nil {
		t.Fatalf("issuance of %s errored: %+v", credentialConfigId, session.Error)
	}
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	if session.Status == clientmodels.Status_Error && session.Error != nil {
		t.Fatalf("issuance of %s errored after permission: %+v", credentialConfigId, session.Error)
	}
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

// ----------------------------------------------------------------------------
// Expectations
// ----------------------------------------------------------------------------

func pidMdocAttr(element, label string, value *clientmodels.AttributeValue) expectedAttr {
	return expectedAttr{
		Path:        []any{pidMdocNamespace, element},
		DisplayName: new(label),
		Value:       value,
	}
}

func mdlAttr(element, label string, value *clientmodels.AttributeValue) expectedAttr {
	return expectedAttr{
		Path:        []any{mdlNamespace, element},
		DisplayName: new(label),
		Value:       value,
	}
}

func pidMdocNameAttrs() []expectedAttr {
	person := samplePidUserData()
	return []expectedAttr{
		pidMdocAttr("family_name", "Family Name(s)", strVal(person.FamilyName)),
		pidMdocAttr("given_name", "Given Name(s)", strVal(person.GivenName)),
	}
}

// pidMdocPlanCredential is the PID as the permission screen shows it. The
// issuer's logo URL points at a host these tests cannot reach, so no image is
// asserted; everything else matches what the age credential pins.
func pidMdocPlanCredential(attrs ...expectedAttr) expectedPlanCredential {
	return mdocPlanCredential(pidMdocDocType, pidMdocDisplayName, attrs)
}

func mdlPlanCredential(attrs ...expectedAttr) expectedPlanCredential {
	return mdocPlanCredential(mdlDocType, mdlDisplayName, attrs)
}

func mdocPlanCredential(docType, name string, attrs []expectedAttr) expectedPlanCredential {
	return expectedPlanCredential{
		CredentialId:        docType,
		Name:                name,
		IssuerName:          avIssuerDisplayName,
		Attributes:          attrs,
		IssuerVerified:      new(true),
		Format:              new(clientmodels.Format_MsoMdoc),
		HasIssuanceDate:     new(true),
		HasExpiryDate:       new(true),
		Revoked:             new(false),
		RevocationSupported: new(false),
	}
}

// pidMdocLogCredential is the PID as the activity log records it, with the dates
// the credential list reports for it.
func pidMdocLogCredential(t *testing.T, c *client.Client, attrs ...expectedAttr) expectedLogCredential {
	t.Helper()
	return mdocLogCredential(t, c, pidMdocDocType, pidMdocDisplayName, attrs)
}

func mdlLogCredential(t *testing.T, c *client.Client, attrs ...expectedAttr) expectedLogCredential {
	t.Helper()
	return mdocLogCredential(t, c, mdlDocType, mdlDisplayName, attrs)
}

func mdocLogCredential(
	t *testing.T,
	c *client.Client,
	docType string,
	name string,
	attrs []expectedAttr,
) expectedLogCredential {
	t.Helper()

	stored := credentialListEntry(t, c, docType)
	return expectedLogCredential{
		CredentialId:        docType,
		Formats:             []clientmodels.CredentialFormat{clientmodels.Format_MsoMdoc},
		Name:                new(name),
		IssuerName:          new(avIssuerDisplayName),
		IssuerVerified:      new(true),
		Attributes:          attrs,
		IssuanceDate:        stored.IssuanceDate,
		ExpiryDate:          stored.ExpiryDate,
		Revoked:             new(false),
		RevocationSupported: new(false),
	}
}

// requireDisclosureLogWith asserts exactly one disclosure entry, filed under the
// verifier the permission screen showed, listing exactly the given credentials.
func requireDisclosureLogWith(
	t *testing.T,
	c *client.Client,
	approvedRequestor clientmodels.TrustedParty,
	expected ...expectedLogCredential,
) {
	t.Helper()

	disclosureLog := requireSingleDisclosureLog(t, c)
	requireLogVerifier(t, disclosureLog, approvedRequestor)
	require.Len(t, disclosureLog.Credentials, len(expected), "one log credential per presented credential")

	for _, exp := range expected {
		logged := findLogCredential(t, disclosureLog.Credentials, exp.CredentialId)
		requireLogCredential(t, logged, exp, exp.CredentialId+" entry")
	}
}

func findIssuanceLog(
	t *testing.T,
	logs []clientmodels.LogInfo,
	credentialId string,
) *clientmodels.IssuanceLog {
	t.Helper()

	for i := range logs {
		entry := logs[i].IssuanceLog
		if logs[i].Type != clientmodels.LogType_Issuance || entry == nil {
			continue
		}
		for _, cred := range entry.Credentials {
			if cred.CredentialId == credentialId {
				return entry
			}
		}
	}

	t.Fatalf("no issuance log entry for %q", credentialId)
	return nil
}

// expectedAttrsOf turns attributes the wallet already shows, in the credential
// list, into the expectation another surface has to match exactly.
func expectedAttrsOf(attrs []clientmodels.Attribute) []expectedAttr {
	expected := make([]expectedAttr, 0, len(attrs))
	for _, attr := range attrs {
		expected = append(
			expected,
			expectedAttr{
				Path:        attr.ClaimPath,
				DisplayName: attr.DisplayName,
				Value:       attr.Value,
			},
		)
	}
	return expected
}

// credentialListRowsUnder returns the credential list's rows for one element of
// an mdoc: the element itself and, for a structured value, the rows flattened
// under it.
func credentialListRowsUnder(
	t *testing.T,
	c *client.Client,
	credentialId string,
	namespace string,
	element string,
) []expectedAttr {
	t.Helper()

	var rows []clientmodels.Attribute
	for _, attr := range credentialListEntry(t, c, credentialId).Attributes {
		if len(attr.ClaimPath) >= 2 && attr.ClaimPath[0] == namespace && attr.ClaimPath[1] == element {
			rows = append(rows, attr)
		}
	}
	require.NotEmpty(t, rows, "the credential list shows nothing for %s/%s", namespace, element)

	return expectedAttrsOf(rows)
}

// mdocDateFromCredentialList reads a date element back from the credential list
// as the string the issuer minted, accepting both the row shape a correctly
// decoded date has and the Content row a raw CBOR tag is flattened into today.
func mdocDateFromCredentialList(
	t *testing.T,
	c *client.Client,
	credentialId string,
	namespace string,
	element string,
) string {
	t.Helper()

	attrs := credentialListEntry(t, c, credentialId).Attributes
	for _, path := range [][]any{
		{namespace, element},
		{namespace, element, "Content"},
	} {
		attr := findAttr(attrs, path...)
		if attr != nil && attr.Value != nil && attr.Value.String != nil {
			return *attr.Value.String
		}
	}

	t.Fatalf("the credential list carries no date for %s/%s", namespace, element)
	return ""
}

// ----------------------------------------------------------------------------
// Reading what the verifier received
// ----------------------------------------------------------------------------

// requireMdocPresentationVerifies verifies one presented document the way a
// verifier that checks device binding would, and returns the disclosed elements
// in comparable Go shapes: dates as their string, maps keyed by string, integers
// as int64.
func requireMdocPresentationVerifies(
	t *testing.T,
	response stdmdoc.DeviceResponse,
	namespace string,
	docType string,
	transcript stdmdoc.SessionTranscript,
) map[string]any {
	t.Helper()

	verifier := stdmdoc.NewVerifier([]*x509.Certificate{eudiPidIssuerPyCACert(t)})
	results, err := verifier.VerifyDeviceResponse(response, namespace, docType, transcript)
	require.NoError(t, err)
	require.Len(t, results, 1)

	result := results[0]
	require.True(t, result.Valid, "presented %s did not verify: %s", docType, result.Error)
	require.True(
		t,
		result.DeviceAuthValid,
		"deviceAuth did not verify against the rebuilt session transcript: %s",
		result.Error,
	)

	elements, ok := normaliseCbor(result.Attributes).(map[string]any)
	require.True(t, ok, "verified attributes should normalise to a map, got %T", result.Attributes)
	return elements
}

// normaliseCbor rewrites what the CBOR decoder produces into the shapes a test
// can state literally: tag 1004 becomes its date string, maps get string keys,
// unsigned integers become int64, recursively.
func normaliseCbor(value any) any {
	switch v := value.(type) {
	case cbor.Tag:
		if v.Number == 1004 {
			if date, ok := v.Content.(string); ok {
				return date
			}
		}
		return normaliseCbor(v.Content)
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[fmt.Sprint(key)] = normaliseCbor(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = normaliseCbor(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = normaliseCbor(item)
		}
		return out
	case uint64:
		return int64(v)
	case uint:
		return int64(v)
	case int:
		return int64(v)
	default:
		return value
	}
}
