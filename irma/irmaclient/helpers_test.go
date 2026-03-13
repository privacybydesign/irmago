package irmaclient

import (
	"reflect"
	"testing"

	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/irma"
)

var Locale_EN = "en"
var Locale_EN_US = "en-US"
var Locale_EN_GB = "en-GB"
var Locale_FR = "fr"
var Locale_FR_FR = "fr-FR"
var Locale_ES = "es"
var Invalid_Locale = "invalid_locale"

func Test_convertDisplayToTranslatedString(t *testing.T) {
	tests := []struct {
		name     string
		displays []openid4vci.Display
		want     irma.TranslatedString
	}{
		{
			name: "single display, single locale",
			displays: []openid4vci.Display{
				{
					Name:   "Issuer Name",
					Locale: &Locale_EN,
				},
			},
			want: irma.TranslatedString{
				"en": "Issuer Name",
			},
		},
		{
			name: "multiple displays, multiple locales",
			displays: []openid4vci.Display{
				{
					Name:   "Issuer Name",
					Locale: &Locale_EN_US,
				},
				{
					Name:   "Nom de l'émetteur",
					Locale: &Locale_FR_FR,
				},
				{
					Name:   "Nombre del emisor",
					Locale: &Locale_ES,
				},
			},
			want: irma.TranslatedString{
				"en": "Issuer Name",
				"fr": "Nom de l'émetteur",
				"es": "Nombre del emisor",
			},
		},
		{
			name: "displays with duplicate base languages",
			displays: []openid4vci.Display{
				{
					Name:   "Issuer Name",
					Locale: &Locale_EN_US,
				},
				{
					Name:   "Another Issuer Name",
					Locale: &Locale_EN_GB,
				},
				{
					Name:   "Nom de l'émetteur",
					Locale: &Locale_FR,
				},
			},
			want: irma.TranslatedString{
				"en": "Another Issuer Name", // Last one wins
				"fr": "Nom de l'émetteur",
			},
		},
		{
			name: "display without locale, should be ignored",
			displays: []openid4vci.Display{
				{
					Name:   "Issuer Name",
					Locale: nil,
				},
				{
					Name:   "Another Issuer Name",
					Locale: &Locale_EN_US,
				},
			},
			want: irma.TranslatedString{
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
