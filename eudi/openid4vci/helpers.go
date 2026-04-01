package openid4vci

import (
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"golang.org/x/text/language"
)

const FallbackLocale = "en"

func ToTranslateableList[T Display | CredentialDisplay | CredentialIssuerDisplay](displays []T) []Translateable {
	translations := make([]Translateable, len(displays))
	for i, display := range displays {
		translations[i] = any(display).(Translateable)
	}
	return translations
}

func convertDisplayToTranslatedString(displays []Translateable) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	var nonLocaleValue *string = nil

	for _, display := range displays {
		locale := display.GetLocale()
		if locale == nil {
			result[""] = display.GetName() // If no locale is provided, we can still include the translation with an empty string as the key, but it won't be used for display
			t := display.GetName()         // Store the non-locale value to use as fallback if no translation for the fallback locale is provided
			nonLocaleValue = &t
			continue
		}

		lang, err := language.Parse(*locale)
		if err != nil {
			continue
		}

		base, _ := lang.Base()

		// TODO: this overwrites translations for the same base language (i.e. en-US would overwrite en-GB), because the app only handles base languages
		result[base.String()] = display.GetName()
	}

	if _, exists := result[FallbackLocale]; !exists && nonLocaleValue != nil {
		result[FallbackLocale] = *nonLocaleValue
	}

	return result
}

// newTranslatedString returns a TranslatedString containing the specified string for each supported language,
// or nil when attr is nil.
func newTranslatedString(value *string) clientmodels.TranslatedString {
	if value == nil {
		return nil
	}
	return map[string]string{
		"":   *value, // raw value
		"en": *value,
		"nl": *value,
	}
}

// isUniqueStrings checks if all strings in the slice are unique (case-sensitive or insensitive)
func isUniqueStrings(slice []string, caseInsensitive bool) bool {
	seen := make(map[string]bool)

	for _, str := range slice {
		// Normalize case if case-insensitive check is required
		key := str
		if caseInsensitive {
			key = strings.ToLower(str)
		}

		if seen[key] {
			return false // Duplicate found
		}
		seen[key] = true
	}
	return true
}
