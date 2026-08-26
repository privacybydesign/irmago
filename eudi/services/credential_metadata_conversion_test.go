package services

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/stretchr/testify/require"
)

// convertCredentialMetadata is where an issuer's published display metadata
// crosses into storage, and therefore the one place every locale but one could be
// dropped without anything downstream noticing.
//
// The display resolvers are tested against storage fixtures built by hand, so
// they prove the wallet *renders* whatever locales are stored. They say nothing
// about how many arrived. A conversion that kept only the first entry — or only
// English — would leave every one of those tests green while the issuer's Dutch
// was thrown away at issuance, which is exactly the shape of the metadata-loss
// defects this path has already produced twice.
//
// The wallet translates nothing of its own. Honouring what the issuer published
// is the whole contract, so "all of it is stored" is the property worth pinning.
func TestConvertCredentialMetadata_KeepsEveryLocale(t *testing.T) {
	locale := func(s string) *string { return &s }

	config := metadata.CredentialConfiguration{
		CredentialMetadata: &metadata.CredentialMetadata{
			Display: metadata.CredentialDisplays{
				{Display: metadata.Display{Name: "Proof of Age", Locale: locale("en")}},
				{Display: metadata.Display{Name: "Leeftijdsbewijs", Locale: locale("nl")}},
			},
			Claims: []metadata.ClaimsDescription{
				{
					Path: metadata.ClaimsPathPointer{"eu.europa.ec.av.1", "age_over_18"},
					Display: []metadata.Display{
						{Name: "Age Over 18", Locale: locale("en")},
						{Name: "Ouder dan 18", Locale: locale("nl")},
					},
				},
			},
		},
	}

	stored := convertCredentialMetadata(config)
	require.NotNil(t, stored)

	// Credential display: both locales, with their names intact.
	require.Len(t, stored.Display, 2, "every published credential display entry must be stored")
	credentialNames := map[string]string{}
	for _, d := range stored.Display {
		require.True(t, d.Locale.Valid, "a published locale must not be stored as null")
		credentialNames[d.Locale.V] = d.Name
	}
	require.Equal(t, map[string]string{"en": "Proof of Age", "nl": "Leeftijdsbewijs"}, credentialNames)

	// Claim display: both locales on the claim too, which is the level the
	// per-attribute labels on the consent screen come from.
	require.Len(t, stored.Claims, 1)
	require.Len(t, stored.Claims[0].Display, 2, "every published claim display entry must be stored")
	claimNames := map[string]string{}
	for _, d := range stored.Claims[0].Display {
		require.True(t, d.Locale.Valid)
		claimNames[d.Locale.V] = d.Name
	}
	require.Equal(t, map[string]string{"en": "Age Over 18", "nl": "Ouder dan 18"}, claimNames)

	// The claim path survives as the two-component mdoc form. A label never
	// replaces it, and matching is what it is used for.
	var path []any
	require.NoError(t, json.Unmarshal(stored.Claims[0].Path, &path))
	require.Equal(t, []any{"eu.europa.ec.av.1", "age_over_18"}, path)
}

// An issuer publishing no locale at all is legal — `locale` is OPTIONAL — and
// must be stored as an absent locale rather than silently relabelled, so the
// resolver's "any translation" last resort can still find it.
func TestConvertCredentialMetadata_KeepsAnUnlabelledDisplay(t *testing.T) {
	config := metadata.CredentialConfiguration{
		CredentialMetadata: &metadata.CredentialMetadata{
			Display: metadata.CredentialDisplays{
				{Display: metadata.Display{Name: "Proof of Age"}},
			},
		},
	}

	stored := convertCredentialMetadata(config)

	require.Len(t, stored.Display, 1)
	require.Equal(t, "Proof of Age", stored.Display[0].Name)
	require.False(t, stored.Display[0].Locale.Valid,
		"an omitted locale must stay absent, not become a guessed one")
}

// The legacy OID4VCI shape must reach storage identically. An issuer on draft <= 15
// puts display and claims on the configuration itself; CredentialConfiguration's
// UnmarshalJSON normalises that into CredentialMetadata, and this checks the
// normalisation carries every locale rather than only the first.
func TestConvertCredentialMetadata_LegacyShapeKeepsEveryLocale(t *testing.T) {
	const legacy = `{
		"format": "mso_mdoc",
		"doctype": "eu.europa.ec.av.1",
		"display": [
			{ "name": "Proof of Age", "locale": "en" },
			{ "name": "Leeftijdsbewijs", "locale": "nl" }
		],
		"claims": [
			{
				"path": ["eu.europa.ec.av.1", "age_over_18"],
				"display": [
					{ "name": "Age Over 18", "locale": "en" },
					{ "name": "Ouder dan 18", "locale": "nl" }
				]
			}
		]
	}`

	var config metadata.CredentialConfiguration
	require.NoError(t, json.Unmarshal([]byte(legacy), &config))
	require.NotNil(t, config.CredentialMetadata,
		"the legacy shape must be normalised into CredentialMetadata")

	stored := convertCredentialMetadata(config)

	require.Len(t, stored.Display, 2)
	require.Len(t, stored.Claims, 1)
	require.Len(t, stored.Claims[0].Display, 2)
}
