package sessiontest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// EUDI Python issuer mdoc tests
//
// These tests exercise the OID4VCI issuance and OID4VP disclosure path for an
// mso_mdoc credential issued by a real issuer service — the EUDI reference
// Python issuer (pinned to v0.9.4 in docker-compose.yml) with its Age
// Verification configuration enabled in
// testdata/eudi-pid-issuer-py/conf/config_issuer_backend.yaml.
//
// This is the counterpart of the seeded-credential mdoc test in
// openid4vp_mdoc_av_disclosure_test.go: that one stores a locally signed
// credential directly (covering presentation and the unauthorized-docType
// refusal), while these cover the full end-to-end flow — the issuer's PKI is
// the committed testdata CA rather than a per-run one, and issuance populates
// the display metadata the seeded test must do without.
//
// Disclosure runs against the eudi_openid4vp container (port 8089, plain
// direct_post) — deliberately not the direct_post.jwt container the seeded
// test uses, so the response-mode-independence of the wallet's mdoc session
// transcript is proven against a real verifier.
//
// Plan: docs/plans/eudi-pid-python-mdoc-av-tests.md
// ============================================================================

const (
	// The credential configuration enabled in the issuer's backend config.
	// Its docType is avDocType (eu.europa.ec.av.1), shared with the seeded
	// mdoc test.
	eudiPidIssuerPyAvMdocConfigID = "eu.europa.ec.eudi.age_verification_mdoc"

	// English display name from the issuer's credential metadata.
	eudiPidIssuerPyAvMdocDisplayNameEN = "Proof of Age"

	// English display name from the issuer's issuer-level metadata.
	eudiPidIssuerPyIssuerDisplayNameEN = "Digital Credentials Issuer"

	// Validity (days) the issuer's AV configuration adds to the MSO's signed
	// timestamp to produce validUntil (issuer_config.validity upstream).
	avMdocValidityDays = 90
)

// testSessionHandlerForEudiPidPythonIssuerMdoc is the test entrypoint
// registered in session_handler_test.go. It groups all subtests that depend
// on the Python issuer's Age Verification mdoc configuration.
func testSessionHandlerForEudiPidPythonIssuerMdoc(t *testing.T) {
	t.Run("issues AV mdoc batch with unique device keys", testEudiPidPythonIssuerIssuesAvMdoc)
	t.Run("discloses AV mdoc to EUDI verifier over direct_post", testEudiPidPythonIssuerDisclosesAvMdocOverDirectPost)
}

// ----------------------------------------------------------------------------
// Subtests
// ----------------------------------------------------------------------------

func testEudiPidPythonIssuerIssuesAvMdoc(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, eudiPidIssuerPyAvMdocDisplayNameEN)
	require.NotNil(t, cred, "issued AV mdoc should appear in GetCredentials")

	// The stored credential's id must be the mdoc docType from the signed
	// MSO — the mdoc analogue of the SD-JWT test's non-URL vct assertion.
	require.Equal(t, avDocType, cred.CredentialId,
		"stored credential id must be the mdoc docType")

	// The issuer advertises batch_credential_issuance.batch_size 100, the
	// wallet requests that many proofs verbatim, and the parser refuses a
	// batch where two instances share a device key — so 100 remaining
	// instances prove a full batch of uniquely-keyed mdocs was issued.
	remaining := cred.BatchInstanceCountsRemaining[clientmodels.Format_MsoMdoc]
	require.NotNil(t, remaining, "an mdoc batch must carry a finite remaining count")
	require.Equal(t, uint(100), *remaining)

	// Validity comes from the MSO validityInfo, not from claims (the AV
	// profile has no date claims). Compare the two stored values against
	// each other rather than the test wallclock — same reasoning as
	// extractAndCheckPidDateClaims, but at whole-timestamp precision.
	require.NotNil(t, cred.IssuanceDate)
	require.NotNil(t, cred.ExpiryDate)
	issuedAt := time.Unix(*cred.IssuanceDate, 0)
	expiresAt := time.Unix(*cred.ExpiryDate, 0)
	require.WithinDuration(t, time.Now().UTC(), issuedAt, 24*time.Hour,
		"MSO signed timestamp should be near the test wallclock")
	require.Equal(t, avMdocValidityDays*24*time.Hour, expiresAt.Sub(issuedAt),
		"MSO validUntil must be signed + %d days (issuer config validity)", avMdocValidityDays)

	// The claim paths are the two-component [namespace, elementIdentifier]
	// form mdoc matching requires; labels come from the issuer's credential
	// metadata. Order matches the metadata claim ordering (age_over_18 is
	// declared before age_over_21). Only the two claims sent in the offer's
	// data payload exist — the payload-driven build drops the other
	// age_over_NN flags the metadata declares.
	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{Path: []any{avDocType, "age_over_18"}, DisplayName: new("Age Over 18"), Value: boolVal(true)},
		expectedAttr{Path: []any{avDocType, "age_over_21"}, DisplayName: new("Age Over 21"), Value: boolVal(false)},
	)
}

func testEudiPidPythonIssuerDisclosesAvMdocOverDirectPost(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	verifierSession, err := irmaclient.StartTestSessionAtEudiVerifier(
		eudiPidIssuerPyOpenID4VPVerifierHost, createAvMdocAuthRequestRequest(t))
	require.NoError(t, err)

	startOpenID4VPDisclosureSession(t, c, 2, verifierSession.SessionLink)

	disclosureSession := awaitSessionState(t, sessionHandler)
	if disclosureSession.Status == clientmodels.Status_Error && disclosureSession.Error != nil {
		t.Fatalf("disclosure errored: %+v", disclosureSession.Error)
	}
	requireSessionState(t, disclosureSession, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, disclosureSession.Protocol)

	// Display metadata was stored at issuance, so the plan shows the
	// issuer's names — unlike the seeded test, where the credential name
	// falls back to the raw docType and the claim has no label.
	requireDisclosurePlan(t, disclosureSession.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{{
					CredentialId: avDocType,
					Name:         eudiPidIssuerPyAvMdocDisplayNameEN,
					IssuerName:   eudiPidIssuerPyIssuerDisplayNameEN,
					Attributes: []expectedAttr{
						{
							Path:        []any{avDocType, "age_over_18"},
							DisplayName: new("Age Over 18"),
							Value:       boolVal(true),
						},
					},
				}},
			},
		},
	})

	chosen := disclosureSession.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, disclosureSession.Id, makeDisclosureChoice(chosen))

	disclosureSession = awaitSessionState(t, sessionHandler)
	requireSessionState(t, disclosureSession, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// The credential also carries age_over_21; exactly one element coming
	// back is what makes this a selective-disclosure proof rather than a
	// disclose-everything one. requireMdocVerifierResult asserts a
	// DeviceSigned is present and exactly the requested element is disclosed.
	requireMdocVerifierResult(t, verifierSession, "age", avDocType, "age_over_18", true)

	// Disclosure consumes one instance of the batch of 100.
	expectedRemaining := uint(99)
	requireBatchRemaining(t, c, eudiPidIssuerPyAvMdocDisplayNameEN, &expectedRemaining)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// issueAvMdocViaPythonIssuer drives the full pre-authorized OID4VCI flow for
// the Age Verification mdoc configuration. The data payload deliberately
// carries one true and one false flag: both boolean values get pinned at
// issuance, and the disclosure test can prove the wallet filtered rather
// than disclosed everything there was.
func issueAvMdocViaPythonIssuer(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
) {
	t.Helper()
	issueViaPythonIssuer(t, c, sessionId, sessionHandler,
		eudiPidIssuerPyAvMdocConfigID,
		map[string]any{
			"age_over_18": true,
			"age_over_21": false,
		},
		eudiPidIssuerPyAvMdocDisplayNameEN,
	)
}

// createAvMdocAuthRequestRequest builds the verifier's session-creation
// request for the age query.
//
// Like createMdocAvAuthRequestRequest (the seeded test's variant) this
// passes the mdoc issuer's trust anchor as issuer_chain, but here that is
// the committed testdata CA the Python issuer's signing certificate chains
// to, not a per-run IACA. The DCQL requests only age_over_18: that is the
// single claim the verifier certificate's scheme extension authorizes for
// eu.europa.ec.av.1, and leaving age_over_21 out is what the selective
// disclosure assertion feeds on. The body is marshalled rather than
// formatted into a template because a PEM block carries newlines, which
// have to be escaped to survive as a JSON string value.
func createAvMdocAuthRequestRequest(t *testing.T) string {
	t.Helper()

	request := map[string]any{
		"type": "vp_token",
		"dcql_query": map[string]any{
			"credentials": []map[string]any{
				{
					"id":     "age",
					"format": string(clientmodels.Format_MsoMdoc),
					"meta":   map[string]any{"doctype_value": avDocType},
					"claims": []map[string]any{
						{"path": []string{avDocType, "age_over_18"}},
					},
				},
			},
		},
		"nonce":              "nonce",
		"jar_mode":           "by_reference",
		"request_uri_method": "post",
		"issuer_chain":       string(readEudiPidIssuerPyCA(t)),
	}

	body, err := json.Marshal(request)
	require.NoError(t, err)
	return string(body)
}
