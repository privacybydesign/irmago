package sessiontest

import (
	"fmt"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// ========================================================================
// Pre-authorized code flow
// ========================================================================

func testSessionHandlerForOpenID4VCIPreAuth(t *testing.T) {
	t.Run("reaches permission request", testOpenID4VCIPreAuthFlowReachesPermission)
	t.Run("grants permission and exchanges token", testOpenID4VCIPreAuthFlowGrantsPermissionAndExchangesToken)
	t.Run("denies permission after grant", testOpenID4VCIPreAuthFlowDeniesPermission)
	t.Run("with tx_code grants permission and exchanges token", testOpenID4VCIPreAuthFlowWithTxCode)
	t.Run("wrong tx_code can be retried", testOpenID4VCIPreAuthFlowWrongTxCodeRetry)
	t.Run("tx_code retries are exhausted after max attempts", testOpenID4VCIPreAuthFlowTxCodeRetriesExhausted)
	t.Run("user can cancel mid-tx_code-retry", testOpenID4VCIPreAuthFlowCancelMidTxCodeRetry)
	t.Run("can be dismissed", testOpenID4VCIPreAuthFlowCanBeDismissed)
	t.Run("prefers VCT type metadata over issuer credential_metadata", testOpenID4VCIPreAuthFlowPrefersVctMetadataOverCredentialMetadata)
	t.Run("resolves VCT type metadata from issued JWT when issuer metadata vct is unknown", testOpenID4VCIPreAuthFlowResolvesVctFromIssuedJwt)
	t.Run("issues credential with nested claims", testOpenID4VCIPreAuthFlowNestedClaims)
	t.Run("issues multiple credential types", testOpenID4VCIPreAuthFlowMultipleCredentialTypes)
	t.Run("issues credential with array claims", testOpenID4VCIPreAuthFlowArrayClaims)
	t.Run("issues credential with mixed sd and non-sd claims", testOpenID4VCIPreAuthFlowMixedSdNonSd)
	t.Run("issues eduid credential with boolean claims", testOpenID4VCIPreAuthFlowEduIdCredential)
	t.Run("issues deeply nested credential", testOpenID4VCIPreAuthFlowDeeplyNestedCredential)
	t.Run("issued credential can be deleted", testOpenID4VCIPreAuthFlowCredentialDeletion)
	t.Run("batch size 1 has nil remaining count", testOpenID4VCIPreAuthFlowBatchSize1)
	t.Run("batch size 2 has remaining count", testOpenID4VCIPreAuthFlowBatchSize2)
}

func testOpenID4VCIPreAuthFlowReachesPermission(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_OpenID4VCI, session.Protocol)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
}

func testOpenID4VCIPreAuthFlowGrantsPermissionAndExchangesToken(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	// Await the permission request and verify offered credentials.
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	offered := session.OfferedCredentials[0]
	require.Equal(t, "Test Credential (SD-JWT)", offered.Name["en"])
	requireAttrsInOrder(t, offered.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       strVal("User"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("test@example.com"),
		},
	)

	// The offered credential must have a valid issuance date (the test issuer
	// does not set exp, so expiry may be 0).
	now := time.Now().Unix()
	require.InDelta(t, now, offered.IssuanceDate, 60,
		"issuance date should be approximately now")

	grantPermission(t, c, session.Id)

	// The test issuer uses did:web, so full credential verification should work.
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	status := checkOfferStatus(t, preAuthIssuerURL, preAuthAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status,
		"server should have issued the credential via pre-authorized code flow")

	// Verify the credential appears in GetCredentials with correct attribute metadata.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
	require.NotNil(t, cred, "issued credential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       strVal("User"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("test@example.com"),
		},
	)
}

func testOpenID4VCIPreAuthFlowDeniesPermission(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.NotEmpty(t, session.OfferedCredentials)

	denyPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)
}

func testOpenID4VCIPreAuthFlowWithTxCode(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOfferWithTxCode(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	require.NotNil(t, session.TransactionCodeParameters)
	require.Equal(t, "numeric", session.TransactionCodeParameters.InputMode)
	require.NotNil(t, session.TransactionCodeParameters.Length)
	require.Equal(t, 6, *session.TransactionCodeParameters.Length)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
			Proceed:         true,
			TransactionCode: &offer.TxCode,
		},
	})

	// Await the permission request and verify offered credentials.
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)
	require.Equal(t, "Test Credential (SD-JWT)", session.OfferedCredentials[0].Name["en"])

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	status := checkOfferStatus(t, preAuthIssuerURL, preAuthAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status)

	// Verify the credential appears in GetCredentials with correct attribute metadata.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
	require.NotNil(t, cred, "issued credential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       strVal("TxCode"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("txcode@example.com"),
		},
	)
}

func testOpenID4VCIPreAuthFlowWrongTxCodeRetry(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOfferWithTxCode(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	require.Nil(t, session.RemainingTxCodeAttempts, "no retry indicator on initial prompt")

	wrongCode := "000000"
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
			Proceed:         true,
			TransactionCode: &wrongCode,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	require.NotNil(t, session.RemainingTxCodeAttempts, "retry indicator present after wrong code")
	require.Equal(t, 2, *session.RemainingTxCodeAttempts)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
			Proceed:         true,
			TransactionCode: &offer.TxCode,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

func testOpenID4VCIPreAuthFlowTxCodeRetriesExhausted(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOfferWithTxCode(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	require.Nil(t, session.RemainingTxCodeAttempts)

	wrongCode := "000000"
	expectedRemaining := []int{2, 1}
	for i := 0; i < 2; i++ {
		userInteraction(t, c, clientmodels.SessionUserInteraction{
			SessionId: session.Id,
			Type:      clientmodels.UI_PreAuthorizedCode,
			Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
				Proceed:         true,
				TransactionCode: &wrongCode,
			},
		})
		session = awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
		require.NotNil(t, session.RemainingTxCodeAttempts)
		require.Equal(t, expectedRemaining[i], *session.RemainingTxCodeAttempts)
	}

	// Third (final) wrong attempt: session should now go to error.
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
			Proceed:         true,
			TransactionCode: &wrongCode,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Error)
}

func testOpenID4VCIPreAuthFlowCancelMidTxCodeRetry(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOfferWithTxCode(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	wrongCode := "000000"
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
			Proceed:         true,
			TransactionCode: &wrongCode,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	require.NotNil(t, session.RemainingTxCodeAttempts)

	// User cancels at the retry prompt.
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: false},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)
}

func testOpenID4VCIPreAuthFlowCanBeDismissed(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_DismissSession,
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)
}

// testOpenID4VCIPreAuthFlowPrefersVctMetadataOverCredentialMetadata pins that
// when the issuer advertises a SD-JWT VC type-metadata URL via the credential's
// `vct` field, the wallet fetches that document and uses its credential and
// claim display values in preference to the OID4VCI `credential_metadata`
// block in the issuer's well-known document.
//
// The fixture uses sentinel suffixes — "(from credential_metadata)" vs
// "(from VCT)" — on every display string so a test failure tells you exactly
// which path won. The VCT document also uses the current SD-JWT VC draft's
// "label" field for claim displays (the spec field name; OID4VCI metadata
// uses "name"), exercising the spec-conformant path.
func testOpenID4VCIPreAuthFlowPrefersVctMetadataOverCredentialMetadata(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createVctMetadataPreAuthOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	if session.Status == clientmodels.Status_Error {
		t.Fatalf("session ended in error: %+v", session.Error)
	}
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	offered := session.OfferedCredentials[0]
	require.Equal(t, "VCT Metadata Test (from VCT)", offered.Name["en"],
		"VCT type metadata's credential display name must win over the issuer's credential_metadata")
	require.Equal(t, "VCT Metadata Test (uit VCT)", offered.Name["nl"],
		"non-English VCT locale must also reach the wallet")

	requireAttrsInOrder(t, offered.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name (from VCT)", "nl": "Voornaam (uit VCT)"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name (from VCT)", "nl": "Achternaam (uit VCT)"},
			Value:       strVal("User"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email (from VCT)", "nl": "E-mailadres (uit VCT)"},
			Value:       strVal("test@example.com"),
		},
	)
}

// testOpenID4VCIPreAuthFlowResolvesVctFromIssuedJwt locks in the wallet's
// post-issuance VCT resolution behavior: when the issuer's well-known document
// advertises `vct: "unknown"` (or any other non-URL placeholder) but the
// issued SD-JWT still carries a fetchable vct URL, the wallet must fetch the
// type metadata after issuance and surface its values in OfferedCredentials.
//
// The fixture stages this with `extends: "TestCredential"` (which doesn't
// match any VCT file's `credentials` list, so veramo's metadata-serving path
// returns `vct: "unknown"`) plus a VCT file whose `credentials` array names
// `PostIssuanceVctTestCredentialSdJwt` (the actual credential id, which
// veramo's issuance path uses — so the JWT does get a real vct URL).
//
// Every VCT display string is suffixed `(from VCT post-issuance)` so a
// failure tells you the wallet fell back to credential_metadata.
func testOpenID4VCIPreAuthFlowResolvesVctFromIssuedJwt(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPostIssuanceVctPreAuthOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	if session.Status == clientmodels.Status_Error {
		t.Fatalf("session ended in error: %+v", session.Error)
	}
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	offered := session.OfferedCredentials[0]
	require.Equal(t, "Post-Issuance VCT Test (from VCT)", offered.Name["en"],
		"VCT credential name (resolved from issued JWT's vct claim) must reach the wallet even when issuer metadata vct=unknown")
	require.Equal(t, "Post-Issuance VCT Test (uit VCT)", offered.Name["nl"])

	requireAttrsInOrder(t, offered.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name (from VCT post-issuance)", "nl": "Voornaam (uit VCT post-issuance)"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name (from VCT post-issuance)", "nl": "Achternaam (uit VCT post-issuance)"},
			Value:       strVal("User"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email (from VCT post-issuance)", "nl": "E-mailadres (uit VCT post-issuance)"},
			Value:       strVal("test@example.com"),
		},
	)
}

func testOpenID4VCIPreAuthFlowNestedClaims(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a HouseCredential with nested address claims.
	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "HouseCredentialSdJwt", `{
		"owner_name": "Alice",
		"address": {
			"street": "123 Main St",
			"city": "Amsterdam",
			"country": "NL"
		}
	}`)

	// Verify the credential appears in GetCredentials with correct attributes.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "House Possession Credential (SD-JWT)")
	require.NotNil(t, cred, "issued HouseCredential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"owner_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
			Value:       strVal("Alice"),
		},
		header(
			[]any{"address"},
			clientmodels.TranslatedString{"en": "Address", "nl": "Adres"},
		),
		expectedAttr{
			Path:        []any{"address", "street"},
			DisplayName: &clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
			Value:       strVal("123 Main St"),
		},
		expectedAttr{
			Path:        []any{"address", "city"},
			DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
			Value:       strVal("Amsterdam"),
		},
		expectedAttr{
			Path:        []any{"address", "country"},
			DisplayName: &clientmodels.TranslatedString{"en": "Country", "nl": "Land"},
			Value:       strVal("NL"),
		},
	)
}

func testOpenID4VCIPreAuthFlowMultipleCredentialTypes(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue an EmailCredential.
	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "nested-test@example.com",
		"domain": "example.com"
	}`)

	// Issue a StudentCardCredential.
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "StudentCardCredentialSdJwt", `{
		"university": "TU Delft",
		"level": "MSc",
		"student_id": "S12345"
	}`)

	// Issue a HouseCredential with nested claims.
	issueCredentialViaOpenID4VCI(t, c, 3, sessionHandler, "HouseCredentialSdJwt", `{
		"owner_name": "Bob",
		"address": {
			"street": "456 Oak Ave",
			"city": "Rotterdam",
			"country": "NL"
		}
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	// Verify EmailCredential attributes.
	emailCred := findCredentialByName(t, creds, "en", "Email Credential (SD-JWT)")
	require.NotNil(t, emailCred, "EmailCredential should appear in GetCredentials")
	requireAttrsInOrder(t, emailCred.Attributes,
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("nested-test@example.com"),
		},
		expectedAttr{
			Path:        []any{"domain"},
			DisplayName: &clientmodels.TranslatedString{"en": "Domain", "nl": "Domein"},
			Value:       strVal("example.com"),
		},
	)

	// Verify StudentCardCredential attributes. The metadata declares `courses` but
	// the issuer didn't populate it; the payload-driven build drops absent claims.
	studentCred := findCredentialByName(t, creds, "en", "Student Card Credential (SD-JWT)")
	require.NotNil(t, studentCred, "StudentCardCredential should appear in GetCredentials")
	requireAttrsInOrder(t, studentCred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("TU Delft"),
		},
		expectedAttr{
			Path:        []any{"level"},
			DisplayName: &clientmodels.TranslatedString{"en": "Level", "nl": "Niveau"},
			Value:       strVal("MSc"),
		},
		expectedAttr{
			Path:        []any{"student_id"},
			DisplayName: &clientmodels.TranslatedString{"en": "Student ID", "nl": "Studentnummer"},
			Value:       strVal("S12345"),
		},
	)

	// Verify HouseCredential attributes.
	houseCred := findCredentialByName(t, creds, "en", "House Possession Credential (SD-JWT)")
	require.NotNil(t, houseCred, "HouseCredential should appear in GetCredentials")
	requireAttrsInOrder(t, houseCred.Attributes,
		expectedAttr{
			Path:        []any{"owner_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
			Value:       strVal("Bob"),
		},
		header(
			[]any{"address"},
			clientmodels.TranslatedString{"en": "Address", "nl": "Adres"},
		),
		expectedAttr{
			Path:        []any{"address", "street"},
			DisplayName: &clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
			Value:       strVal("456 Oak Ave"),
		},
		expectedAttr{
			Path:        []any{"address", "city"},
			DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
			Value:       strVal("Rotterdam"),
		},
		expectedAttr{
			Path:        []any{"address", "country"},
			DisplayName: &clientmodels.TranslatedString{"en": "Country", "nl": "Land"},
			Value:       strVal("NL"),
		},
	)
}

func testOpenID4VCIPreAuthFlowArrayClaims(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "StudentCardCredentialSdJwt", `{
		"university": "TU Delft",
		"level": "MSc",
		"student_id": "S99999",
		"courses": ["Algorithms", "Databases", "Security"]
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Student Card Credential (SD-JWT)")
	require.NotNil(t, cred, "issued StudentCardCredential should appear in GetCredentials")

	// Array claims are flattened into indexed paths with a section header.
	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("TU Delft"),
		},
		expectedAttr{
			Path:        []any{"level"},
			DisplayName: &clientmodels.TranslatedString{"en": "Level", "nl": "Niveau"},
			Value:       strVal("MSc"),
		},
		expectedAttr{
			Path:        []any{"student_id"},
			DisplayName: &clientmodels.TranslatedString{"en": "Student ID", "nl": "Studentnummer"},
			Value:       strVal("S99999"),
		},
		header(
			[]any{"courses"},
			clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"},
		),
		expectedAttr{
			Path:  []any{"courses", 0},
			Value: strVal("Algorithms"),
		},
		expectedAttr{
			Path:  []any{"courses", 1},
			Value: strVal("Databases"),
		},
		expectedAttr{
			Path:  []any{"courses", 2},
			Value: strVal("Security"),
		},
	)
}

func testOpenID4VCIPreAuthFlowMixedSdNonSd(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "MembershipCredentialSdJwt", `{
		"member_name": "Alice",
		"member_since": "2020-01-15",
		"membership_type": "gold"
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Membership Credential (SD-JWT)")
	require.NotNil(t, cred, "issued MembershipCredential should appear in GetCredentials")

	// member_name and membership_type are SD, member_since is non-SD.
	// All should appear in GetCredentials regardless.
	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"member_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Member Name", "nl": "Naam lid"},
			Value:       strVal("Alice"),
		},
		expectedAttr{
			Path:        []any{"member_since"},
			DisplayName: &clientmodels.TranslatedString{"en": "Member Since", "nl": "Lid sinds"},
			Value:       strVal("2020-01-15"),
		},
		expectedAttr{
			Path:        []any{"membership_type"},
			DisplayName: &clientmodels.TranslatedString{"en": "Membership Type", "nl": "Type lidmaatschap"},
			Value:       strVal("gold"),
		},
	)
}

func testOpenID4VCIPreAuthFlowEduIdCredential(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "EduIdCredentialSdJwt", `{
		"schac_home_organization": "university.nl",
		"name": "Jan de Vries",
		"given_name": "Jan",
		"family_name": "de Vries",
		"email": "jan@university.nl",
		"eduperson_scoped_affiliation": "student@university.nl",
		"eduperson_assurance": "https://eduid.nl/assurance/low",
		"is_student": true,
		"is_faculty": false,
		"is_member": true,
		"is_staff": false,
		"is_alum": false,
		"is_affiliate": false,
		"is_employee": false,
		"is_library-walk-in": false
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "eduID")
	require.NotNil(t, cred, "issued EduIdCredential should appear in GetCredentials")

	// All 15 claims should be present. eduperson_assurance is non-SD.
	// Boolean values are stored as string "true"/"false" via NewAttributeValue.
	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"schac_home_organization"},
			DisplayName: &clientmodels.TranslatedString{"en": "Organization", "nl": "Instelling"},
			Value:       strVal("university.nl"),
		},
		expectedAttr{
			Path:        []any{"name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Name", "nl": "Naam"},
			Value:       strVal("Jan de Vries"),
		},
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given name", "nl": "Voornaam"},
			Value:       strVal("Jan"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
			Value:       strVal("de Vries"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "E-mail", "nl": "E-mail"},
			Value:       strVal("jan@university.nl"),
		},
		expectedAttr{
			Path:        []any{"eduperson_scoped_affiliation"},
			DisplayName: &clientmodels.TranslatedString{"en": "Affiliation (scoped)", "nl": "Betrekking (in relatie)"},
			Value:       strVal("student@university.nl"),
		},
		expectedAttr{
			Path:        []any{"eduperson_assurance"},
			DisplayName: &clientmodels.TranslatedString{"en": "Assurance", "nl": "Bevestiging"},
			Value:       strVal("https://eduid.nl/assurance/low"),
		},
		expectedAttr{
			Path:        []any{"is_student"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsStudent", "nl": "IsStudent"},
			Value:       boolVal(true),
		},
		expectedAttr{
			Path:        []any{"is_faculty"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsFaculty", "nl": "IsFaculteitslid"},
			Value:       boolVal(false),
		},
		expectedAttr{
			Path:        []any{"is_member"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsMember", "nl": "IsLid"},
			Value:       boolVal(true),
		},
		expectedAttr{
			Path:        []any{"is_staff"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsStaff", "nl": "IsStaf"},
			Value:       boolVal(false),
		},
		expectedAttr{
			Path:        []any{"is_alum"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsAlumnus", "nl": "IsAlumnus"},
			Value:       boolVal(false),
		},
		expectedAttr{
			Path:        []any{"is_affiliate"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsAffiliate", "nl": "IsVerbonden"},
			Value:       boolVal(false),
		},
		expectedAttr{
			Path:        []any{"is_employee"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsEmployee", "nl": "IsMedewerker"},
			Value:       boolVal(false),
		},
		expectedAttr{
			Path:        []any{"is_library-walk-in"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsLibraryWalkIn", "nl": "IsBibliotheekBezoeker"},
			Value:       boolVal(false),
		},
	)
}

// testOpenID4VCIPreAuthFlowDeeplyNestedCredential issues a credential with
// deeply nested structure: an object containing an array of objects, each
// containing an array of objects, each containing an array. This mirrors the
// structure in buildDeeplyNestedSdJwt from the SD-JWT presentation tests.
//
// Structure:
//
//	university (object):
//	  name: "TU Delft"
//	  faculties (array of objects):
//	    [0]:
//	      faculty_name: "EEMCS"
//	      departments (array of objects):
//	        [0]:
//	          dept_name: "Software Technology"
//	          courses: ["Compiler Construction", "Distributed Systems", "Intro to CS"]
//	        [1]:
//	          dept_name: "Data Science"
//	          courses: ["Machine Learning"]
//	    [1]:
//	      faculty_name: "Architecture"
//	      departments (array of objects):
//	        [0]:
//	          dept_name: "Urbanism"
//	          courses: ["City Planning"]
//	  founded: 1842
func testOpenID4VCIPreAuthFlowDeeplyNestedCredential(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := postOffer(t, preAuthIssuerURL, preAuthAdminToken, fmt.Sprintf(`{
		"credentials": ["OrganizationCredentialSdJwt"],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate"
			}
		},
		"credentialDataSupplierInput": %s
	}`, `{
		"university": {
			"name": "TU Delft",
			"faculties": [
				{
					"faculty_name": "EEMCS",
					"departments": [
						{
							"dept_name": "Software Technology",
							"courses": ["Compiler Construction", "Distributed Systems", "Intro to CS"]
						},
						{
							"dept_name": "Data Science",
							"courses": ["Machine Learning"]
						}
					]
				},
				{
					"faculty_name": "Architecture",
					"departments": [
						{
							"dept_name": "Urbanism",
							"courses": ["City Planning"]
						}
					]
				}
			],
			"founded": 1842
		}
	}`))

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	deptName := &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"}
	facName := &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"}
	departments := clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}
	courses := clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}

	// Verify offered credentials contain the deeply nested attribute values.
	offered := session.OfferedCredentials[0]
	require.Equal(t, "Organization Credential (SD-JWT)", offered.Name["en"])
	requireAttrsInOrder(t, offered.Attributes,
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		expectedAttr{
			Path:        []any{"university", "name"},
			DisplayName: &clientmodels.TranslatedString{"en": "University Name", "nl": "Naam universiteit"},
			Value:       strVal("TU Delft"),
		},
		header([]any{"university", "faculties"}, clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}),
		expectedAttr{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, departments),
		expectedAttr{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, courses),
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 1},
			Value: strVal("Distributed Systems"),
		},
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 2},
			Value: strVal("Intro to CS"),
		},
		expectedAttr{
			Path:        []any{"university", "faculties", 0, "departments", 1, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Data Science"),
		},
		header([]any{"university", "faculties", 0, "departments", 1, "courses"}, courses),
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 1, "courses", 0},
			Value: strVal("Machine Learning"),
		},
		expectedAttr{
			Path:        []any{"university", "faculties", 1, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("Architecture"),
		},
		header([]any{"university", "faculties", 1, "departments"}, departments),
		expectedAttr{
			Path:        []any{"university", "faculties", 1, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Urbanism"),
		},
		header([]any{"university", "faculties", 1, "departments", 0, "courses"}, courses),
		expectedAttr{
			Path:  []any{"university", "faculties", 1, "departments", 0, "courses", 0},
			Value: strVal("City Planning"),
		},
		expectedAttr{
			Path:        []any{"university", "founded"},
			DisplayName: &clientmodels.TranslatedString{"en": "Founded", "nl": "Opgericht"},
			Value:       intVal(1842),
		},
	)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Verify the credential appears in GetCredentials.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Organization Credential (SD-JWT)")
	require.NotNil(t, cred, "issued OrganizationCredential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		expectedAttr{
			Path:        []any{"university", "name"},
			DisplayName: &clientmodels.TranslatedString{"en": "University Name", "nl": "Naam universiteit"},
			Value:       strVal("TU Delft"),
		},
		header([]any{"university", "faculties"}, clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}),
		// Faculty 0 (EEMCS) — keys ordered by metadata: faculty_name, departments.
		expectedAttr{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, departments),
		// Department 0 (Software Technology) — keys ordered by metadata: dept_name, courses.
		expectedAttr{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, courses),
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 1},
			Value: strVal("Distributed Systems"),
		},
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 2},
			Value: strVal("Intro to CS"),
		},
		// Department 1 (Data Science).
		expectedAttr{
			Path:        []any{"university", "faculties", 0, "departments", 1, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Data Science"),
		},
		header([]any{"university", "faculties", 0, "departments", 1, "courses"}, courses),
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 1, "courses", 0},
			Value: strVal("Machine Learning"),
		},
		// Faculty 1 (Architecture).
		expectedAttr{
			Path:        []any{"university", "faculties", 1, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("Architecture"),
		},
		header([]any{"university", "faculties", 1, "departments"}, departments),
		expectedAttr{
			Path:        []any{"university", "faculties", 1, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Urbanism"),
		},
		header([]any{"university", "faculties", 1, "departments", 0, "courses"}, courses),
		expectedAttr{
			Path:  []any{"university", "faculties", 1, "departments", 0, "courses", 0},
			Value: strVal("City Planning"),
		},
		expectedAttr{
			Path:        []any{"university", "founded"},
			DisplayName: &clientmodels.TranslatedString{"en": "Founded", "nl": "Opgericht"},
			Value:       intVal(1842),
		},
	)

	// Verify the credential can be disclosed over OpenID4VP.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "org-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/organization"]
					},
					"claims": [
						{ "path": ["university"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	disclosureSession := awaitSessionState(t, sessionHandler)
	requireSessionState(t, disclosureSession, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	cred2 := disclosureSession.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, disclosureSession.Id, makeDisclosureChoice(cred2))

	disclosureSession = awaitSessionState(t, sessionHandler)
	requireSessionState(t, disclosureSession, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Verify the verifier received the university claim as a nested object.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)

	// Check the deeply nested structure was preserved.
	requireVerifierReceivedClaims(t, result, "org-cred",
		claim([]any{"university", "name"}, "TU Delft"),
		claim([]any{"university", "faculties", 0, "faculty_name"}, "EEMCS"),
		claim([]any{"university", "faculties", 0, "departments", 0, "dept_name"}, "Software Technology"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 0}, "Compiler Construction"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 1}, "Distributed Systems"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 2}, "Intro to CS"),
		claim([]any{"university", "faculties", 0, "departments", 1, "dept_name"}, "Data Science"),
		claim([]any{"university", "faculties", 0, "departments", 1, "courses", 0}, "Machine Learning"),
		claim([]any{"university", "faculties", 1, "faculty_name"}, "Architecture"),
		claim([]any{"university", "faculties", 1, "departments", 0, "dept_name"}, "Urbanism"),
		claim([]any{"university", "faculties", 1, "departments", 0, "courses", 0}, "City Planning"),
		claim([]any{"university", "founded"}, "1842"),
	)
}

// testOpenID4VCIPreAuthFlowCredentialDeletion verifies that an EUDI SD-JWT credential
// issued via OID4VCI can be deleted. The credential only exists in the EUDI GORM storage
// (not in the IRMA BBolt storage), so its hash won't be found in getIrmaCredentialInfoList().
// This specifically guards against an index-out-of-range panic when the hash lookup returns -1.
func testOpenID4VCIPreAuthFlowCredentialDeletion(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.NotEmpty(t, session.OfferedCredentials)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Verify the credential was issued.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
	require.NotNil(t, cred, "issued credential should appear in GetCredentials")
	deletedHash := cred.Hash

	// Delete the EUDI credential using its own instance IDs.
	// This must not panic even though the hash is absent from the IRMA credential list.
	require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))

	// Verify the specific credential is gone by checking no credential has the deleted hash.
	creds, err = c.GetCredentials()
	require.NoError(t, err)
	for _, c := range creds {
		require.NotEqual(t, deletedHash, c.Hash, "deleted credential (hash %s) should no longer appear in GetCredentials", deletedHash)
	}
}

func testOpenID4VCIPreAuthFlowBatchSize1(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	// Default issuer has no batch_credential_issuance, so the map should exist
	// but the count for sd-jwt should be nil.
	offered := session.OfferedCredentials[0]
	require.NotNil(t, offered.BatchInstanceCountsRemaining)
	require.Len(t, offered.BatchInstanceCountsRemaining, 1)
	require.Nil(t, offered.BatchInstanceCountsRemaining[clientmodels.Format_SdJwtVc],
		"batch remaining count should be nil for single-instance issuance")

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

func testOpenID4VCIPreAuthFlowBatchSize2(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := postOffer(t, batch2IssuerURL, batch2AdminToken, `{
		"credentials": ["EmailCredentialSdJwt"],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate"
			}
		},
		"credentialDataSupplierInput": {
			"email": "batch@example.com",
			"domain": "example.com"
		}
	}`)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	// batch2-issuer has batch_credential_issuance.batch_size = 2.
	offered := session.OfferedCredentials[0]
	require.NotNil(t, offered.BatchInstanceCountsRemaining,
		"batch remaining should be set for batch issuance")
	require.Len(t, offered.BatchInstanceCountsRemaining, 1)
	remaining := offered.BatchInstanceCountsRemaining[clientmodels.Format_SdJwtVc]
	require.NotNil(t, remaining)
	require.Equal(t, uint(2), *remaining,
		"batch remaining should equal the issuer's batch_size")

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

// ========================================================================
// Authorization code flow
// ========================================================================

func testSessionHandlerForOpenID4VCIAuthCode(t *testing.T) {
	t.Run("reaches auth request", testOpenID4VCIAuthCodeFlowReachesAuthRequest)
	t.Run("grants permission and exchanges token", testOpenID4VCIAuthCodeFlowGrantsPermissionAndExchangesToken)
	t.Run("denies permission after grant", testOpenID4VCIAuthCodeFlowDeniesPermission)
	t.Run("can be dismissed", testOpenID4VCIAuthCodeFlowCanBeDismissed)
	t.Run("issues credential with nested claims", testOpenID4VCIAuthCodeFlowNestedClaims)
}

func testOpenID4VCIAuthCodeFlowReachesAuthRequest(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createAuthCodeOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_OpenID4VCI, session.Protocol)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestAuthorizationCode)
	require.NotEmpty(t, session.AuthorizationRequestUrl)
}

func testOpenID4VCIAuthCodeFlowGrantsPermissionAndExchangesToken(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createAuthCodeOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestAuthorizationCode)

	code := getAuthorizationCode(t, session.AuthorizationRequestUrl)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_AuthorizationCode,
		Payload: clientmodels.SessionAuthCodeInteractionPayload{
			Code:    &code,
			Proceed: true,
		},
	})

	// Await the permission request and verify offered credentials.
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	offered := session.OfferedCredentials[0]
	require.Equal(t, "Test Credential (SD-JWT)", offered.Name["en"])
	requireAttrsInOrder(t, offered.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       strVal("AuthCode"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("authcode@example.com"),
		},
	)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	status := checkOfferStatus(t, authcodeIssuerURL, authcodeAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status,
		"server should have issued the credential via authorization code flow")

	// Verify the credential appears in GetCredentials with correct attribute metadata.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
	require.NotNil(t, cred, "issued credential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       strVal("AuthCode"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("authcode@example.com"),
		},
	)
}

func testOpenID4VCIAuthCodeFlowDeniesPermission(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createAuthCodeOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestAuthorizationCode)

	code := getAuthorizationCode(t, session.AuthorizationRequestUrl)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_AuthorizationCode,
		Payload: clientmodels.SessionAuthCodeInteractionPayload{
			Code:    &code,
			Proceed: true,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.NotEmpty(t, session.OfferedCredentials)

	denyPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)
}

func testOpenID4VCIAuthCodeFlowCanBeDismissed(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createAuthCodeOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestAuthorizationCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_DismissSession,
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)
}

func testOpenID4VCIAuthCodeFlowNestedClaims(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a HouseCredential with nested address claims via authorization code flow.
	issueCredentialViaOpenID4VCIAuthCode(t, c, 1, sessionHandler, "HouseCredentialSdJwt", `{
		"owner_name": "Charlie",
		"address": {
			"street": "789 Elm St",
			"city": "Utrecht",
			"country": "NL"
		}
	}`)

	// Verify the credential appears in GetCredentials with correct attributes.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "House Possession Credential (SD-JWT)")
	require.NotNil(t, cred, "issued HouseCredential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"owner_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
			Value:       strVal("Charlie"),
		},
		header(
			[]any{"address"},
			clientmodels.TranslatedString{"en": "Address", "nl": "Adres"},
		),
		expectedAttr{
			Path:        []any{"address", "street"},
			DisplayName: &clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
			Value:       strVal("789 Elm St"),
		},
		expectedAttr{
			Path:        []any{"address", "city"},
			DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
			Value:       strVal("Utrecht"),
		},
		expectedAttr{
			Path:        []any{"address", "country"},
			DisplayName: &clientmodels.TranslatedString{"en": "Country", "nl": "Land"},
			Value:       strVal("NL"),
		},
	)
}

// issueCredentialViaOpenID4VCIAuthCode issues a single credential through the
// veramo-agent OID4VCI authorization code flow.
func issueCredentialViaOpenID4VCIAuthCode(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
	credentialType string,
	claimsJSON string,
) {
	t.Helper()

	offerBody := fmt.Sprintf(`{
		"credentials": [%q],
		"grants": {
			"authorization_code": {
				"issuer_state": "generate"
			}
		},
		"credentialDataSupplierInput": %s
	}`, credentialType, claimsJSON)

	offer := postOffer(t, authcodeIssuerURL, authcodeAdminToken, offerBody)
	startOpenID4VCISession(t, c, sessionId, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_RequestAuthorizationCode)

	code := getAuthorizationCode(t, session.AuthorizationRequestUrl)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_AuthorizationCode,
		Payload: clientmodels.SessionAuthCodeInteractionPayload{
			Code:    &code,
			Proceed: true,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.NotEmpty(t, session.OfferedCredentials)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_Success)

	status := checkOfferStatus(t, authcodeIssuerURL, authcodeAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status)
}
