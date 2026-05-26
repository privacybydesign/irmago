package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"

	"github.com/stretchr/testify/require"
)

// TestYesnoAttributeBecomesBoolean asserts that attributes tagged with
// displayHint="yesno" in the IRMA scheme are presented as boolean
// AttributeValues across all client-facing surfaces: issuance result,
// disclosure plan, persisted logs, and GetCredentials().
//
// This test is RED today (assertions describe the target behavior) and
// becomes green once buildAttributeValue learns to map "yes"/"no" raw
// values to *Bool for yesno-tagged attributes.
func TestYesnoAttributeBecomesBoolean(t *testing.T) {
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issueRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.personalData"),
		Attributes: map[string]string{
			"firstName":     "Alice",
			"familyName":    "Smith",
			"over_18":       "Yes",
			"over_21":       "NO",
			"nationalityNL": "yes",
		},
	}})

	expectedAttrs := []expectedAttr{
		{
			Path:        []any{"firstName"},
			DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"},
			Value:       strVal("Alice"),
		},
		{
			Path:        []any{"familyName"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
			Value:       strVal("Smith"),
		},
		{
			Path:        []any{"over_18"},
			DisplayName: &clientmodels.TranslatedString{"en": "Over 18", "nl": "Ouder dan 18"},
			Value:       boolVal(true),
		},
		{
			Path:        []any{"over_21"},
			DisplayName: &clientmodels.TranslatedString{"en": "Over 21", "nl": "Ouder dan 21"},
			Value:       boolVal(false),
		},
		{
			Path:        []any{"nationalityNL"},
			DisplayName: &clientmodels.TranslatedString{"en": "Dutch nationality", "nl": "Nederlandse nationaliteit"},
			Value:       boolVal(true),
		},
	}

	// 1. Issuance session: OfferedCredentials must show yesno attrs as Bool.
	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, issueRequest))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	require.Len(t, session.OfferedCredentials, 1)
	require.Equal(t, "test.test.personalData", session.OfferedCredentials[0].CredentialId)
	requireAttrsInOrder(t, session.OfferedCredentials[0].Attributes, expectedAttrs...)

	grantPermission(t, c, session.Id)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// 2. GetCredentials() must expose yesno attrs as Bool.
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	var stored *clientmodels.Credential
	for _, cred := range creds {
		if cred.CredentialId == "test.test.personalData" {
			stored = cred
			break
		}
	}
	require.NotNil(t, stored, "personalData credential should be available in GetCredentials")
	requireAttrsInOrder(t, stored.Attributes, expectedAttrs...)

	// 3. Disclosure session: DisclosurePlan must show yesno attrs as Bool.
	disclosureRequest := irma.NewDisclosureRequest()
	disclosureRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.personalData.firstName"),
				irma.NewAttributeRequest("test.test.personalData.familyName"),
				irma.NewAttributeRequest("test.test.personalData.over_18"),
				irma.NewAttributeRequest("test.test.personalData.over_21"),
				irma.NewAttributeRequest("test.test.personalData.nationalityNL"),
			},
		},
	}

	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, disclosureRequest))
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	require.NotNil(t, session.DisclosurePlan)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 1)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions, 1)

	bundle := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Len(t, bundle.Credentials, 1)
	owned := bundle.Credentials[0]
	require.Equal(t, "test.test.personalData", owned.CredentialId)
	requireAttrsInOrder(t, owned.Attributes, expectedAttrs...)

	grantPermission(t, c, session.Id, makeDisclosureChoice(bundle))
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// 4. Persisted disclosure log must mirror the Bool typing.
	requireNewestDisclosureLogAttrs(t, c, "test.test.personalData", expectedAttrs)
}
