package irma

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialTypeClientFaq(t *testing.T) {
	t.Run("converts all FAQ texts", func(t *testing.T) {
		ct := &CredentialType{
			FAQIntro:   &TranslatedString{"en": "intro", "nl": "inleiding"},
			FAQPurpose: &TranslatedString{"en": "purpose"},
			FAQContent: &TranslatedString{"en": "content"},
			FAQHowto:   &TranslatedString{"en": "howto"},
		}

		faq := ct.ClientFaq("nl")

		require.NotNil(t, faq)
		assert.Equal(t, "inleiding", *faq.Intro)
		assert.Nil(t, faq.Purpose, "bundled text must not mix languages")
		assert.Nil(t, faq.Content, "bundled text must not mix languages")
		assert.Nil(t, faq.HowTo, "bundled text must not mix languages")
	})

	t.Run("falls back to a language every field has", func(t *testing.T) {
		ct := &CredentialType{
			FAQIntro:   &TranslatedString{"en": "intro"},
			FAQPurpose: &TranslatedString{"en": "purpose"},
			FAQContent: &TranslatedString{"en": "content"},
			FAQHowto:   &TranslatedString{"en": "howto"},
		}

		faq := ct.ClientFaq("nl")

		require.NotNil(t, faq)
		assert.Equal(t, "intro", *faq.Intro)
		assert.Equal(t, "purpose", *faq.Purpose)
		assert.Equal(t, "content", *faq.Content)
		assert.Equal(t, "howto", *faq.HowTo)
	})

	t.Run("returns nil without any FAQ content", func(t *testing.T) {
		assert.Nil(t, (&CredentialType{}).ClientFaq("nl"))
	})
}
