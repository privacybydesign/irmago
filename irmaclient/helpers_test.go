package irmaclient

import (
	"reflect"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
)

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
					Locale: "en",
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
					Locale: "en-US",
				},
				{
					Name:   "Nom de l'émetteur",
					Locale: "fr-FR",
				},
				{
					Name:   "Nombre del emisor",
					Locale: "es",
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
					Locale: "en-US",
				},
				{
					Name:   "Another Issuer Name",
					Locale: "en-GB",
				},
				{
					Name:   "Nom de l'émetteur",
					Locale: "fr",
				},
			},
			want: irma.TranslatedString{
				"en": "Another Issuer Name", // Last one wins
				"fr": "Nom de l'émetteur",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertDisplayToTranslatedString(tt.displays)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertDisplayToTranslatedString() = %v, want %v", got, tt.want)
			}
		})
	}
}
