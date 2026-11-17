package sessiontest

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	rootpkg "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server/keyshare/keyshareserver"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// TestGenerateClientStorageForRegressionTests regenerates the storage regression
// fixture for the current version (testdata/storage_regression/v<Version>/), used
// by TestClientStorageRegression. Run with GENERATE_STORAGE set:
//
//	GENERATE_STORAGE=1 go test -run TestGenerateClientStorageForRegressionTests -count=1 ./internal/sessiontest/
//
// Sessions performed:
//   - IRMA issuance: irma-demo.MijnOverheid.fullName (idemix), test.test.email
//     (idemix + 10 SD-JWTs), irma-demo.MijnOverheid.singleton, irma-demo.RU.studentCard.
//   - OpenID4VCI issuance: 3x TestCredentialSdJwt (vct https://localhost:8443/vct/test) and
//     1x OrganizationCredentialSdJwt (vct https://localhost:8443/vct/organization, deeply nested).
//   - IRMA disclosures: test.test.email; irma-demo.MijnOverheid.fullName (x2); and one spanning
//     irma-demo.MijnOverheid.fullName + irma-demo.MijnOverheid.singleton + irma-demo.RU.studentCard.
//   - IRMA signature.
//   - OpenID4VP disclosures: test.test.email (x2, served from bbolt) plus
//     https://localhost:8443/vct/test and https://localhost:8443/vct/organization
//     (served from the EUDI DB, via the veramo verifier).
//   - Status list: 1x StatusListCredentialSdJwt (vct https://localhost:8443/vct/statuslist),
//     revoked at the issuer and then refreshed, so it is stored as revoked.
//   - mdoc: 1x age-verification mdoc (docType eu.europa.ec.av.1) issued over OpenID4VCI by
//     the Python PID issuer, then disclosed once over OpenID4VP to the EUDI reference verifier.
//   - VCDM (vc+sd-jwt, from veramo): TestCredentialVcdm (Vera), disclosed once to the veramo
//     verifier; StatusListCredentialVcdm, revoked through its Bitstring Status List and then
//     refreshed; an Open Badges credential with claim images, disclosed once; and a spare
//     TestCredentialVcdm, removed.
//   - Removals, as the final actions: irma-demo.RU.studentCard, 2 spare https://localhost:8443/vct/test
//     and the spare VCDM credential.
//
// Resulting database state:
//   - bbolt (bbolt_client_db): irma-demo.MijnOverheid.fullName, irma-demo.MijnOverheid.singleton
//     and test.test.email; the test.test.email SD-JWT retains 8 of 10 instances (2 consumed by
//     OpenID4VP disclosure); irma-demo.RU.studentCard removed.
//   - EUDI sqlcipher (eudi_client_db): one https://localhost:8443/vct/test, one
//     https://localhost:8443/vct/organization and one https://localhost:8443/vct/statuslist
//     batch remaining; the status-list batch carries a status.status_list reference with a
//     LastKnownStatus of INVALID, alongside a cached Status List Token; plus one
//     eu.europa.ec.av.1 mdoc batch with one instance spent by the disclosure; plus three VCDM
//     batches: Vera's (disclosed once), the revoked status-list one, and the Open Badge,
//     whose claim images are stored next to the logos.
//   - Activity logs (merged from both stores): all four types — issuance, disclosure, signature,
//     removal — returned newest-first, ending with the four removals.
func TestGenerateClientStorageForRegressionTests(t *testing.T) {
	if os.Getenv("GENERATE_STORAGE") == "" {
		t.Skip("GENERATE_STORAGE not set, skipping storage generation")
	}
	// Start infrastructure
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServerWithDB(t, logger, irma.NewSchemeManagerIdentifier("test"), 0,
		func(conf *keyshareserver.Configuration) {
			conf.KeyshareAttributeValidity = int(time.Until(time.Now().AddDate(20, 0, 0)).Hours() / 24)
		})
	defer keyshareServer.Stop()

	storagePath := newSnapshotWallet(t)
	c, clientHandler, sessionHandler := openSnapshotWallet(t, storagePath)
	c.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, clientHandler.AwaitEnrollmentResult())

	// 1. Issue idemix-only credential (MijnOverheid.fullName)
	issue(t, irmaServer, c, sessionHandler, 1, withSnapshotValidity(createMijnOverheidIssuanceRequest()))
	awaitSessionState(t, sessionHandler)

	// 2. Issue combined idemix + sd-jwt credential (test.test.email)
	issue(t, irmaServer, c, sessionHandler, 2, withSnapshotValidity(createIrmaIssuanceRequestWithSdJwts("test.test.email", "email")))
	awaitSessionState(t, sessionHandler)

	// 3. Issue singleton credential
	issue(t, irmaServer, c, sessionHandler, 3, withSnapshotValidity(&irma.IssuanceRequest{
		LDContext: irma.LDContextIssuanceRequest,
		Credentials: []*irma.CredentialRequest{
			{
				CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.singleton"),
				Attributes: map[string]string{
					"BSN": "12345",
				},
			},
		},
	}))
	awaitSessionState(t, sessionHandler)

	// 3b. Issue an OpenID4VCI SD-JWT credential so the EUDI (sqlcipher) DB is
	// populated. IRMA-issued SD-JWTs go to bbolt; only OpenID4VCI issuance
	// writes the EUDI credential store.
	issueCredentialViaOpenID4VCI(t, c, 8, sessionHandler, "TestCredentialSdJwt",
		`{"given_name": "Test", "family_name": "User", "email": "test@example.com"}`)

	// 3c. Issue an idemix-only student card (another credential type).
	issue(t, irmaServer, c, sessionHandler, 9, withSnapshotValidity(createStudentCardIssuanceRequest()))
	awaitSessionState(t, sessionHandler)

	// 3d. Issue two more OpenID4VCI credentials (more EUDI data, and spare
	// credentials to remove later for the removal-ordering assertion).
	issueCredentialViaOpenID4VCI(t, c, 10, sessionHandler, "TestCredentialSdJwt",
		`{"given_name": "Alice", "family_name": "Example", "email": "alice@example.com"}`)
	issueCredentialViaOpenID4VCI(t, c, 12, sessionHandler, "TestCredentialSdJwt",
		`{"given_name": "Bob", "family_name": "Example", "email": "bob@example.com"}`)

	// 3e. Issue an OpenID4VCI credential with deeply nested attributes
	// (organizational credential: university -> faculties -> departments -> courses).
	issueCredentialViaOpenID4VCI(t, c, 16, sessionHandler, "OrganizationCredentialSdJwt", organizationClaimsJSON)

	// 3f. Issue a status-list credential and then revoke it, so the snapshot
	// carries Token Status List state at rest: instances with a
	// status.status_list{uri,idx} reference, a LastKnownStatus of INVALID, and a
	// cached Status List Token. Revoking is what makes this worth storing — a
	// non-revoked instance's LastKnownStatus is the zero value, so a snapshot of
	// one would still read correctly if status storage broke entirely.
	//
	// RefreshStatuses is what writes the new status to storage; without it the
	// wallet would still hold the VALID reading taken at issuance.
	issueStatusListCredential(t, c, sessionHandler, 18)
	revokeStatusListCredentialViaVeramo(t, statusListCredentialEmail)
	require.NoError(t, c.RefreshStatuses(context.Background()))

	// 3g. Issue an age-verification mdoc from the Python PID issuer, so the
	// snapshot holds an mso_mdoc batch: per-instance device keys, the issuer
	// signed MSO, and the issuer's display metadata.
	issueAvMdocViaPythonIssuer(t, c, 19, sessionHandler)

	// 3h. Issue an SD-JWT-secured VCDM credential, so the snapshot holds a
	// vcdm_batches row, its instance, and its holder binding key in the table
	// VCDM shares with SD-JWT VC. It is a single instance: veramo gives every
	// copy in a batch its own credentialSubject.id, and v1.5.0 refuses such a
	// batch.
	issueCredentialViaOpenID4VCI(t, c, 21, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)

	// 3i. Issue a VCDM credential with a Bitstring Status List entry and revoke
	// it, so the snapshot carries bitstring_status_entries and a revoked
	// LastKnownStatus on a VCDM instance.
	issueVcdmStatusListCredential(t, c, sessionHandler, 22)
	revokeCredentialsViaVeramo(t, vcdmStatusListRecordType, vcdmStatusListEmail)
	require.NoError(t, c.RefreshStatuses(context.Background()))

	// 3j. Issue an Open Badges credential with claim images, so the snapshot
	// holds stored claim images next to the logos.
	startClaimImagesServer(t)
	issueOpenBadgeForSnapshot(t, c, 23, sessionHandler)

	// 3k. Issue a spare VCDM credential, removed at the end.
	issueCredentialViaOpenID4VCI(t, c, 24, sessionHandler, vcdmCredentialConfigId, vcdmSpareClaims)

	// Verify credentials are present
	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	t.Logf("Credentials after issuance: %d", len(creds))
	for _, cred := range creds {
		t.Logf("  - %s", cred.CredentialId)
	}

	// 4. Perform IRMA disclosure session
	performIrmaDisclosureSession(t, c, 4, sessionHandler, irmaServer)

	// 5. Perform IRMA signature session
	performIrmaSignatureSession(t, c, 5, sessionHandler, irmaServer)

	// 6. Perform OpenID4VP disclosure sessions (direct_post and direct_post.jwt)
	discloseOverOpenID4VP(t, c, 6, sessionHandler, testdata.OpenID4VP_DirectPost_Host)
	discloseOverOpenID4VP(t, c, 7, sessionHandler, testdata.OpenID4VP_DirectPostJwt_Host)

	// 7b-7c. A few more IRMA disclosures (idemix, non-keyshare) so the log has
	// several disclosure entries to assert ordering against.
	performDisclosureSessionForAttribute(t, c, 11, sessionHandler, irmaServer, "irma-demo.MijnOverheid.fullName.familyname")
	performDisclosureSessionForAttribute(t, c, 13, sessionHandler, irmaServer, "irma-demo.MijnOverheid.fullName.firstnames")

	// 7d. A single disclosure session spanning multiple credential types
	// (fullName + singleton + studentCard) so the fixture exercises a
	// multi-credential disclosure. Each credential is its own conjunction
	// (IRMA disallows multiple non-singletons in one inner conjunction).
	multiReq := irma.NewDisclosureRequest()
	multiReq.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{irma.AttributeCon{irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname")}},
		irma.AttributeDisCon{irma.AttributeCon{irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN")}},
		irma.AttributeDisCon{irma.AttributeCon{irma.NewAttributeRequest("irma-demo.RU.studentCard.university")}},
	}
	c.NewSession(14, startSameDeviceIrmaSessionAtServer(t, irmaServer, multiReq))
	multiSession := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, multiSession.Status)
	var multiChoices []clientmodels.DisclosureDisconSelection
	for _, slot := range multiSession.DisclosurePlan.DisclosureChoicesOverview {
		multiChoices = append(multiChoices, makeDisclosureChoice(slot.OwnedOptions[0]))
	}
	grantPermission(t, c, multiSession.Id, multiChoices...)
	multiSession = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, multiSession.Status)

	// 7e. Disclose the OpenID4VCI-issued credential over OpenID4VP (via the
	// veramo verifier). This is an OpenID4VP disclosure of an EUDI credential
	// stored in the sqlcipher DB, distinct from the email SD-JWT disclosures
	// above (which are served from bbolt).
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, `{
		"dcql": {
			"credentials": [
				{
					"id": "test-cred",
					"format": "dc+sd-jwt",
					"meta": { "vct_values": ["https://localhost:8443/vct/test"] },
					"claims": [ { "path": ["given_name"] }, { "path": ["email"] } ]
				}
			]
		}
	}`)
	startOpenID4VPDisclosureSession(t, c, 15, veramoSession.RequestUri)
	eudiVpSession := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, eudiVpSession.Status)
	grantPermission(t, c, eudiVpSession.Id, makeDisclosureChoice(eudiVpSession.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]))
	eudiVpSession = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, eudiVpSession.Status)

	// 7f. Disclose the deeply nested organization credential over OpenID4VP,
	// selecting only a few specific nested claims rather than the whole tree.
	orgVeramoSession := createVeramoVerifierDcqlSessionWithQuery(t, `{
		"dcql": {
			"credentials": [
				{
					"id": "org-cred",
					"format": "dc+sd-jwt",
					"meta": { "vct_values": ["https://localhost:8443/vct/organization"] },
					"claims": [
						{ "path": ["university", "name"] },
						{ "path": ["university", "founded"] }
					]
				}
			]
		}
	}`)
	startOpenID4VPDisclosureSession(t, c, 17, orgVeramoSession.RequestUri)
	orgVpSession := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, orgVpSession.Status)
	grantPermission(t, c, orgVpSession.Id, makeDisclosureChoice(orgVpSession.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]))
	orgVpSession = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, orgVpSession.Status)

	// 7g. Disclose the mdoc to the EUDI reference verifier, which spends one
	// batch instance and writes an mdoc disclosure log.
	discloseAvMdocOnce(t, c, sessionHandler, 20)

	// 7h. Disclose the VCDM credential to the veramo verifier as a vp+jwt,
	// which spends one instance and writes a VCDM disclosure log. The query
	// also matches the status-list and spare VCDM credentials; pick Vera's.
	discloseVcdmToVeramo(t, c, sessionHandler, 25, vcdmDcqlQuery(
		`"meta": {"type_values": [["`+vcdmVerifiableCredentialIri+`", "`+vcdmCredentialType+`"]]}`,
		[]any{"credentialSubject", "given_name"},
		[]any{"credentialSubject", "email"},
	), func(cred *clientmodels.SelectableCredentialInstance) bool {
		return vcdmSubjectValue(cred.Attributes, "email") == "vera@example.com"
	})

	// 7i. Disclose the Open Badges credential, so a disclosure log holds claim
	// images. A log entry's images cannot be fetched again, so this is what
	// shows whether stored claim images still load.
	discloseVcdmToVeramo(t, c, sessionHandler, 26, vcdmDcqlQuery("",
		[]any{"credentialSubject", "photo"},
		[]any{"credentialSubject", "achievement"},
		[]any{"credentialSubject", "logo"},
		[]any{"credentialSubject", "broken"},
	), func(cred *clientmodels.SelectableCredentialInstance) bool {
		return cred.Name == openBadgeCredentialName
	})

	// 8. Remove several credentials as the final actions, so the newest activity
	// logs are an ordered run of removals. Keep the credentials the regression
	// test asserts on: fullName, singleton, email, and one OpenID4VCI credential.
	keep := map[string]bool{
		"irma-demo.MijnOverheid.fullName":         true,
		"irma-demo.MijnOverheid.singleton":        true,
		"test.test.email":                         true,
		"https://localhost:8443/vct/organization": true, // keep the deeply nested credential
		"https://localhost:8443/vct/statuslist":   true, // keep the revoked status-list credential
		eudiPidIssuerPyAvDocType:                  true, // keep the mdoc
	}
	creds, _, err = c.GetCredentials()
	require.NoError(t, err)
	removals := 0
	for _, cred := range creds {
		if keep[cred.CredentialId] {
			continue
		}
		// Keep the canonical OpenID4VCI test credential (given_name "Test") so
		// the fixture is deterministic; remove the Alice/Bob spares and the
		// student card (3 removals in total).
		if cred.CredentialId == "https://localhost:8443/vct/test" && credentialAttrValue(cred, "given_name") == "Test" {
			continue
		}
		// Keep Vera's VCDM credential, the revoked status-list one and the Open
		// Badge; remove only the spare VCDM credential.
		if cred.Name == openBadgeCredentialName {
			continue
		}
		if cred.CredentialId == vcdmCredentialId && vcdmSubjectValue(cred.Attributes, "email") != vcdmSpareEmail {
			continue
		}
		require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))
		removals++
	}
	require.Equal(t, 4, removals, "expected exactly 4 credential removals")

	// Log final state
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	t.Logf("Total log entries: %d", len(logs))
	for _, log := range logs {
		t.Logf("  - type=%s", log.Type)
	}

	creds, _, err = c.GetCredentials()
	require.NoError(t, err)
	t.Logf("Final credentials: %d", len(creds))
	for _, cred := range creds {
		t.Logf("  - %s", cred.CredentialId)
	}

	// Close client to flush database
	require.NoError(t, c.Close())

	dir := snapshotDir(t, "v"+rootpkg.Version)
	saveSnapshot(t, storagePath, dir, keyshareServer.DB)
	fmt.Printf("Storage written to %s\n", dir)
}

// withSnapshotValidity makes every credential in req valid for 20 years. With
// IRMA's default of 6 months, a snapshot's IRMA credentials would expire long
// before the snapshot stops mattering. The IRMA server's expiry check can be
// skipped, but an IRMA-issued SD-JWT carries the same expiry as exp, and an
// external OpenID4VP verifier rejects it once that has passed. Snapshots up to
// v1.4.0 predate this and fall back to fresh credentials (see
// replaceExpiredEmailSdJwts).
func withSnapshotValidity(req *irma.IssuanceRequest) *irma.IssuanceRequest {
	validity := irma.Timestamp(time.Now().AddDate(20, 0, 0))
	for _, cred := range req.Credentials {
		cred.Validity = &validity
	}
	return req
}

// credentialAttrValue returns the string value of a top-level attribute, or ""
// if absent. Used to pick a specific credential among same-typed ones.
func credentialAttrValue(cred *clientmodels.Credential, key string) string {
	for _, a := range cred.Attributes {
		if len(a.ClaimPath) == 1 && a.ClaimPath[0] == key && a.Value != nil && a.Value.String != nil {
			return *a.Value.String
		}
	}
	return ""
}

// The spare VCDM credential, issued only to be removed: its removal log is the
// snapshot's VCDM removal entry.
const vcdmSpareEmail = "spare-vcdm@example.com"

var vcdmSpareClaims = `{
	"given_name": "Spare",
	"family_name": "Modell",
	"email": "` + vcdmSpareEmail + `"
}`

// vcdmSubjectValue returns the string value of credentialSubject.<key>, or ""
// if absent.
func vcdmSubjectValue(attrs []clientmodels.Attribute, key string) string {
	for _, a := range attrs {
		if len(a.ClaimPath) == 2 && a.ClaimPath[0] == "credentialSubject" && a.ClaimPath[1] == key &&
			a.Value != nil && a.Value.String != nil {
			return *a.Value.String
		}
	}
	return ""
}

// issueOpenBadgeForSnapshot issues the Open Badges test credential, with the
// same claims and images as testOpenBadgesClaimImages, so the regression test
// can check them with requireOpenBadgeImages. startClaimImagesServer must be
// running: the wallet downloads the images and the context at issuance.
func issueOpenBadgeForSnapshot(t *testing.T, c *client.Client, sessionId int, sessionHandler *MockSessionHandler) {
	t.Helper()
	offer := postOffer(t, preAuthIssuerURL, preAuthAdminToken, fmt.Sprintf(`{
		"credentials": [%q],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate"
			}
		},
		"credentialDataSupplierInput": {},
		"credential": {
			"@context": [%q, %q],
			"image": {"id": %q, "type": "Image"},
			"issuer": {"image": %q},
			"credentialSubject": {
				"photo": %q,
				"achievement": {
					"name": "Schildertechnieken",
					"image": {"id": %q, "type": "Image"}
				},
				"logo": {"id": %q, "type": "Image"},
				"broken": {"id": %q, "type": "Image"}
			}
		}
	}`, openBadgeCredentialConfigId, vcdm.ContextV2, openBadgeContextURL,
		logoImageURL, logoImageURL,
		photoDataURI, badgeImageURL, logoImageURL, missingImageURL))
	startOpenID4VCISession(t, c, sessionId, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	grantPermission(t, c, session.Id)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

// discloseVcdmToVeramo runs one vc+sd-jwt disclosure to the veramo verifier,
// disclosing the owned option whose credential pick accepts, and checks that
// the verifier accepted the presentation.
func discloseVcdmToVeramo(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionId int,
	dcql string, pick func(*clientmodels.SelectableCredentialInstance) bool) {
	t.Helper()
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcql)
	startOpenID4VPDisclosureSession(t, c, sessionId, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 1)
	var chosen *clientmodels.DisclosureBundle
	for _, option := range session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions {
		if pick(option.Credentials[0]) {
			require.Nil(t, chosen, "more than one owned option matches")
			chosen = option
		}
	}
	require.NotNil(t, chosen, "no owned option matches")
	grantPermission(t, c, session.Id, makeDisclosureChoice(chosen))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Equal(t, "RESPONSE_RECEIVED", result.Status)
	requireNoVeramoVcdmErrors(t, result)
}
