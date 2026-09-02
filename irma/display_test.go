package irma

import (
	"testing"

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

// TestTranslatedString_Resolve pins that scheme text indexed through Resolve
// follows the shared fallback chain for any language, so French and German
// users see their translation when present and English otherwise — never an
// empty string because a caller indexed the map with a literal "en".
func TestTranslatedString_Resolve(t *testing.T) {
	ts := TranslatedString{"en": "Email address", "nl": "E-mailadres", "fr": "Adresse e-mail", "de": "E-Mail-Adresse"}

	assert.Equal(t, "Adresse e-mail", ts.Resolve("fr"))
	assert.Equal(t, "Adresse e-mail", ts.Resolve("fr-BE"))
	assert.Equal(t, "E-Mail-Adresse", ts.Resolve("de-CH"))
	assert.Equal(t, "Email address", ts.Resolve("pt"), "untranslated language falls back to English")
	assert.Equal(t, "Email address", ts.Resolve(""))

	assert.Equal(t, "", TranslatedString(nil).Resolve("fr"))
}
