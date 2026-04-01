package openid4vci

import (
	"reflect"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

var locale_EN = "en"
var locale_EN_US = "en-US"
var locale_EN_GB = "en-GB"
var locale_FR = "fr"
var locale_FR_FR = "fr-FR"
var locale_ES = "es"
var invalid_Locale = "invalid_locale"

func Test_convertDisplayToTranslatedString(t *testing.T) {
	tests := []struct {
		name     string
		displays []Display
		want     clientmodels.TranslatedString
	}{
		{
			name: "single display, single locale",
			displays: []Display{
				{
					Name:   "Issuer Name",
					Locale: &locale_EN,
				},
			},
			want: clientmodels.TranslatedString{
				"en": "Issuer Name",
			},
		},
		{
			name: "multiple displays, multiple locales",
			displays: []Display{
				{
					Name:   "Issuer Name",
					Locale: &locale_EN_US,
				},
				{
					Name:   "Nom de l'émetteur",
					Locale: &locale_FR_FR,
				},
				{
					Name:   "Nombre del emisor",
					Locale: &locale_ES,
				},
			},
			want: clientmodels.TranslatedString{
				"en": "Issuer Name",
				"fr": "Nom de l'émetteur",
				"es": "Nombre del emisor",
			},
		},
		{
			name: "displays with duplicate base languages",
			displays: []Display{
				{
					Name:   "Issuer Name",
					Locale: &locale_EN_US,
				},
				{
					Name:   "Another Issuer Name",
					Locale: &locale_EN_GB,
				},
				{
					Name:   "Nom de l'émetteur",
					Locale: &locale_FR,
				},
			},
			want: clientmodels.TranslatedString{
				"en": "Another Issuer Name", // Last one wins
				"fr": "Nom de l'émetteur",
			},
		},
		{
			name: "display without locale, should be ignored",
			displays: []Display{
				{
					Name:   "Issuer Name",
					Locale: nil,
				},
				{
					Name:   "Another Issuer Name",
					Locale: &locale_EN_US,
				},
			},
			want: clientmodels.TranslatedString{
				"":   "Issuer Name",
				"en": "Another Issuer Name",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			displays := ToTranslateableList(tt.displays)
			got := convertDisplayToTranslatedString(displays)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertDisplayToTranslatedString() = %v, want %v", got, tt.want)
			}
		})
	}
}
