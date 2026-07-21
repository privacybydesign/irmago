package irma

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialTypeClientFaq(t *testing.T) {
	t.Run("converts all FAQ texts", func(t *testing.T) {
		ct := &CredentialType{
			FAQIntro:   &TranslatedString{"en": "intro", "nl": "introductie"},
			FAQPurpose: &TranslatedString{"en": "purpose"},
			FAQContent: &TranslatedString{"en": "content"},
			FAQHowto:   &TranslatedString{"en": "howto"},
		}

		faq := ct.ClientFaq()

		require.NotNil(t, faq)
		assert.Equal(t, clientmodels.TranslatedString{"en": "intro", "nl": "introductie"}, *faq.Intro)
		assert.Equal(t, clientmodels.TranslatedString{"en": "purpose"}, *faq.Purpose)
		assert.Equal(t, clientmodels.TranslatedString{"en": "content"}, *faq.Content)
		assert.Equal(t, clientmodels.TranslatedString{"en": "howto"}, *faq.HowTo)
	})

	t.Run("keeps missing FAQ texts nil", func(t *testing.T) {
		ct := &CredentialType{
			FAQIntro: &TranslatedString{"en": "intro"},
		}

		faq := ct.ClientFaq()

		require.NotNil(t, faq)
		assert.NotNil(t, faq.Intro)
		assert.Nil(t, faq.Purpose)
		assert.Nil(t, faq.Content)
		assert.Nil(t, faq.HowTo)
	})

	t.Run("returns nil without any FAQ content", func(t *testing.T) {
		assert.Nil(t, (&CredentialType{}).ClientFaq())
	})
}
