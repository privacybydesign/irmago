package irma

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/assert"
)

// TestCredentialType_ResolveTexts_IssueURLSurvivesAnUntranslatedLocale pins the
// split ResolveTexts makes: Name and Category share a language, the issue URL
// does not. Folding the URL back into the bundle would drop the "get this
// credential" link for every locale that translates the name but not the URL —
// the resolver-level equivalent is covered by
// clientmodels.TestResolvePtr_FallsBackIndependentlyOfTheTextBundle, but only
// this test fails if the URL is refolded here.
func TestCredentialType_ResolveTexts_IssueURLSurvivesAnUntranslatedLocale(t *testing.T) {
	category := TranslatedString{"en": "Education"}                      // untranslated
	issueURL := TranslatedString{"en": "https://issuer.example.com/get"} // not a translation
	ct := &CredentialType{
		Name:     TranslatedString{"en": "Student card", "nl": "Studentenkaart"},
		Category: &category,
		IssueURL: &issueURL,
	}

	name, gotCategory, gotIssueURL := ct.ResolveTexts("nl")

	assert.Equal(t, "Studentenkaart", name)
	assert.Nil(t, gotCategory, "bundled text must not mix languages")
	assert.NotNil(t, gotIssueURL, "a URL is not a translation — it must survive an untranslated locale")
	assert.Equal(t, "https://issuer.example.com/get", *gotIssueURL)
}

// TestAttributeType_ResolveTexts_BundlesNameAndDescription pins the other half:
// an attribute's name and description are both displayed text, so they resolve
// from one language rather than falling back per field.
func TestAttributeType_ResolveTexts_BundlesNameAndDescription(t *testing.T) {
	at := &AttributeType{
		Name:        TranslatedString{"en": "Date of birth", "nl": "Geboortedatum"},
		Description: TranslatedString{"en": "The day you were born"}, // untranslated
	}

	displayName, description := at.ResolveTexts("nl")

	assert.Equal(t, "Geboortedatum", *displayName)
	assert.Nil(t, description, "bundled text must not mix languages")
}

// TestIssuer_ToTrustedParty_MapsSchemeStatusToARung pins the IRMA half of the
// display mapping: an issuer in a valid scheme is vouched for by Yivi itself, one
// in an invalid scheme by nobody. The trust mechanism is untouched.
func TestIssuer_ToTrustedParty_MapsSchemeStatusToARung(t *testing.T) {
	for _, tc := range []struct {
		status   SchemeManagerStatus
		expected clientmodels.TrustLevel
	}{
		{SchemeManagerStatusValid, clientmodels.TrustLevel_High},
		{SchemeManagerStatusInvalidSignature, clientmodels.TrustLevel_Low},
		{SchemeManagerStatusParsingError, clientmodels.TrustLevel_Low},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			conf := &Configuration{SchemeManagers: map[SchemeManagerIdentifier]*SchemeManager{
				NewSchemeManagerIdentifier("test"): {
					ID:     "test",
					Name:   TranslatedString{"en": "Test scheme"},
					Status: tc.status,
				},
			}}
			issuer := &Issuer{
				ID:              "test-issuer",
				SchemeManagerID: "test",
				Name:            TranslatedString{"en": "Test issuer"},
			}

			party := issuer.ToTrustedParty(conf, "en")

			assert.Equal(t, tc.expected, party.TrustLevel)
			assert.NotNil(t, party.Parent)
			assert.Equal(t, tc.expected, party.Parent.TrustLevel,
				"the scheme manager is ranked by the same status as the issuer under it")
		})
	}
}
