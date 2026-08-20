package openid4vci

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/stretchr/testify/require"
)

// TestMerge_VciFillsMissingClaimTranslation is the headline case: VCT has
// English + German for the email claim; VCI also has Spanish. The merged
// result must surface en/de from VCT and es from VCI.
func TestMerge_VciFillsMissingClaimTranslation(t *testing.T) {
	en, de, es := "en", "de", "es"

	vct := &typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{{Locale: en, Name: "Email"}},
		Claims: []typemetadata.ClaimMetadata{
			{
				Path: []any{"email"},
				Display: []typemetadata.ClaimDisplayEntry{
					{Locale: en, Name: "Email"},
					{Locale: de, Name: "E-Mail"},
				},
			},
		},
	}
	vci := &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Name: "Email (VCI)", Locale: &en},
		},
		Claims: []metadata.ClaimsDescription{
			{
				Path: metadata.ClaimsPathPointer{"email"},
				Display: []metadata.Display{
					{Name: "Email (VCI)", Locale: &en},
					{Name: "Correo electrónico", Locale: &es},
				},
			},
		},
	}

	out := Merge(vct, vci)

	require.Len(t, out.Claims, 1)
	require.Len(t, out.Claims[0].Display, 3, "en + de from VCT and es from VCI must coexist")
	require.Equal(t, "Email", out.Claims[0].Display[0].Name)
	require.Equal(t, "en", *out.Claims[0].Display[0].Locale)
	require.Equal(t, "E-Mail", out.Claims[0].Display[1].Name)
	require.Equal(t, "de", *out.Claims[0].Display[1].Locale)
	require.Equal(t, "Correo electrónico", out.Claims[0].Display[2].Name)
	require.Equal(t, "es", *out.Claims[0].Display[2].Locale)
}

// TestMerge_ClaimUnion exercises the union semantics: a claim only in VCI
// (no VCT counterpart) must appear in the merged result, with its
// Mandatory flag preserved.
func TestMerge_ClaimUnion(t *testing.T) {
	mandatory := true
	en := "en"

	vct := &typemetadata.VctTypeMetadata{
		Claims: []typemetadata.ClaimMetadata{
			{Path: []any{"email"}, Display: []typemetadata.ClaimDisplayEntry{{Locale: en, Name: "Email"}}},
		},
	}
	vci := &metadata.CredentialMetadata{
		Claims: []metadata.ClaimsDescription{
			{Path: metadata.ClaimsPathPointer{"email"}, Display: []metadata.Display{{Name: "Email (VCI)", Locale: &en}}},
			{
				Path:      metadata.ClaimsPathPointer{"dob"},
				Mandatory: &mandatory,
				Display:   []metadata.Display{{Name: "Date of birth", Locale: &en}},
			},
		},
	}

	out := Merge(vct, vci)

	require.Len(t, out.Claims, 2)
	require.Equal(t, metadata.ClaimsPathPointer{"email"}, out.Claims[0].Path)
	require.Equal(t, metadata.ClaimsPathPointer{"dob"}, out.Claims[1].Path)
	require.NotNil(t, out.Claims[1].Mandatory)
	require.True(t, *out.Claims[1].Mandatory, "VCI Mandatory must carry through for VCI-only claims")
	require.Equal(t, "Date of birth", out.Claims[1].Display[0].Name)
}

// TestMerge_LanguageOnlyMatchingCollapses verifies that VCT en-US and VCI en
// collapse to the same language key and VCT wins.
func TestMerge_LanguageOnlyMatchingCollapses(t *testing.T) {
	enUS := "en-US"
	en := "en"

	vct := &typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{{Locale: enUS, Name: "VCT"}},
	}
	vci := &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Name: "VCI", Locale: &en},
		},
	}

	out := Merge(vct, vci)

	require.Len(t, out.Display, 1, "language-only matching must collapse en-US and en")
	require.Equal(t, "VCT", out.Display[0].Name)
	require.Equal(t, "en-US", *out.Display[0].Display.Locale, "VCT's full tag must survive on the output")
}

// TestMerge_VctOrderPreserved verifies that VCT-defined claims appear in
// VCT's order and VCI-only claims are appended in VCI's relative order.
func TestMerge_VctOrderPreserved(t *testing.T) {
	en := "en"
	vct := &typemetadata.VctTypeMetadata{
		Claims: []typemetadata.ClaimMetadata{
			{Path: []any{"A"}, Display: []typemetadata.ClaimDisplayEntry{{Locale: en, Name: "A"}}},
			{Path: []any{"B"}, Display: []typemetadata.ClaimDisplayEntry{{Locale: en, Name: "B"}}},
			{Path: []any{"C"}, Display: []typemetadata.ClaimDisplayEntry{{Locale: en, Name: "C"}}},
		},
	}
	vci := &metadata.CredentialMetadata{
		Claims: []metadata.ClaimsDescription{
			{Path: metadata.ClaimsPathPointer{"C"}},
			{Path: metadata.ClaimsPathPointer{"B"}},
			{Path: metadata.ClaimsPathPointer{"A"}},
			{Path: metadata.ClaimsPathPointer{"D"}, Display: []metadata.Display{{Name: "D", Locale: &en}}},
		},
	}

	out := Merge(vct, vci)
	require.Len(t, out.Claims, 4)
	require.Equal(t, metadata.ClaimsPathPointer{"A"}, out.Claims[0].Path)
	require.Equal(t, metadata.ClaimsPathPointer{"B"}, out.Claims[1].Path)
	require.Equal(t, metadata.ClaimsPathPointer{"C"}, out.Claims[2].Path)
	require.Equal(t, metadata.ClaimsPathPointer{"D"}, out.Claims[3].Path)
}

// TestMerge_CredentialLevelDisplayFieldLevelFallback verifies the field-level
// fallback at the credential-display level: for a locale present in both
// sources, VCT wins each field it specifies (Name, BackgroundColor) while any
// field VCT leaves empty (Description, BackgroundImage) is inherited from the
// VCI entry for that locale.
func TestMerge_CredentialLevelDisplayFieldLevelFallback(t *testing.T) {
	en, es := "en", "es"
	vct := &typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{
			{Locale: en, Name: "Card (VCT)", BackgroundColor: "#000000"},
		},
	}
	vci := &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			// Same locale as VCT — VCT wins Name/BackgroundColor, but the
			// fields VCT leaves empty (Description, BackgroundImage) are
			// inherited from this VCI entry.
			{
				Name: "Card (VCI)", Locale: &en,
				Description:     "Description (VCI)",
				BackgroundImage: &metadata.RemoteImage{Uri: "https://example/bg.png"},
			},
			// VCI-only locale survives unchanged.
			{
				Name: "Tarjeta", Locale: &es,
				Description:     "Descripción (VCI)",
				BackgroundImage: &metadata.RemoteImage{Uri: "https://example/bg-es.png"},
			},
		},
	}

	out := Merge(vct, vci)

	require.Len(t, out.Display, 2)
	require.Equal(t, "Card (VCT)", out.Display[0].Name, "VCT wins the fields it specifies")
	require.Equal(t, "#000000", out.Display[0].BackgroundColor)
	require.Equal(t, "Description (VCI)", out.Display[0].Description, "VCI fills the Description field VCT leaves empty")
	require.NotNil(t, out.Display[0].BackgroundImage, "VCI fills the BackgroundImage field VCT leaves empty")
	require.Equal(t, "https://example/bg.png", out.Display[0].BackgroundImage.Uri)

	require.Equal(t, "Tarjeta", out.Display[1].Name)
	require.Equal(t, "Descripción (VCI)", out.Display[1].Description, "VCI-only locale survives intact")
	require.NotNil(t, out.Display[1].BackgroundImage)
}

// TestMerge_VciLogoInheritedWhenVctOmitsIt is the regression case for the
// dropped credential logo: the VCT display entry for a locale carries a name
// but no logo, while the VCI entry for the same locale carries the logo. The
// merged entry must keep VCT's name and inherit VCI's logo instead of dropping
// it wholesale.
func TestMerge_VciLogoInheritedWhenVctOmitsIt(t *testing.T) {
	en, nl := "en", "nl"
	vct := &typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{
			{Locale: en, Name: "Employee (VCT)"}, // name only, no logo
			{Locale: nl, Name: "Werknemer (VCT)"},
		},
	}
	vci := &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{
				Name: "Employee (VCI)", Locale: &en,
				Logo: &metadata.RemoteImage{Uri: "data:image/svg+xml;base64,AAAA", AltText: "logo"},
			},
			{
				Name: "Werknemer (VCI)", Locale: &nl,
				Logo: &metadata.RemoteImage{Uri: "data:image/svg+xml;base64,BBBB"},
			},
		},
	}

	out := Merge(vct, vci)

	require.Len(t, out.Display, 2)
	require.Equal(t, "Employee (VCT)", out.Display[0].Name, "VCT name still wins")
	require.NotNil(t, out.Display[0].Logo, "VCI logo must be inherited when VCT omits it")
	require.Equal(t, "data:image/svg+xml;base64,AAAA", out.Display[0].Logo.Uri)
	require.Equal(t, "logo", out.Display[0].Logo.AltText)
	require.Equal(t, "Werknemer (VCT)", out.Display[1].Name)
	require.NotNil(t, out.Display[1].Logo)
	require.Equal(t, "data:image/svg+xml;base64,BBBB", out.Display[1].Logo.Uri)
}

// TestMerge_VctLogoWinsOverVciLogo verifies the field stays VCT-authoritative:
// when VCT supplies its own logo, VCI's logo for the same locale is ignored.
func TestMerge_VctLogoWinsOverVciLogo(t *testing.T) {
	en := "en"
	vct := &typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{
			{Locale: en, Name: "Card", Logo: &typemetadata.RemoteImage{URI: "https://vct/logo.png"}},
		},
	}
	vci := &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{
				Name: "Card (VCI)", Locale: &en,
				Logo: &metadata.RemoteImage{Uri: "https://vci/logo.png"},
			},
		},
	}

	out := Merge(vct, vci)

	require.Len(t, out.Display, 1)
	require.NotNil(t, out.Display[0].Logo)
	require.Equal(t, "https://vct/logo.png", out.Display[0].Logo.Uri, "VCT logo wins the field it specifies")
}

// TestMerge_NilLocaleConflation verifies that VCI's nil-locale entries
// share a key with VCI's empty-string-locale entries. (VCT entries with
// empty locale cannot occur because ParseVctTypeMetadata rejects them.)
func TestMerge_NilLocaleConflation(t *testing.T) {
	empty := ""
	vci := &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Name: "Nil-locale"}, // Locale is nil
			{Name: "Empty-locale", Locale: &empty},
		},
	}

	out := Merge(nil, vci)

	require.Len(t, out.Display, 1, "nil and empty-string locale must share a key")
	require.Equal(t, "Nil-locale", out.Display[0].Name, "first entry wins for repeated keys")
}

// TestMerge_BCP47Canonicalisation verifies that en-us and EN-US collide on
// "en" regardless of casing.
func TestMerge_BCP47Canonicalisation(t *testing.T) {
	vctTag := "en-us"
	vciTag := "EN-US"
	vct := &typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{{Locale: vctTag, Name: "VCT"}},
	}
	vci := &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Name: "VCI", Locale: &vciTag},
		},
	}
	out := Merge(vct, vci)
	require.Len(t, out.Display, 1)
	require.Equal(t, "VCT", out.Display[0].Name)
}

// TestMerge_MandatoryFromVciOnMatchedClaim verifies that Mandatory is taken
// from VCI when both sources define the claim — VCT has no notion of it.
func TestMerge_MandatoryFromVciOnMatchedClaim(t *testing.T) {
	en := "en"
	mandatory := true
	vct := &typemetadata.VctTypeMetadata{
		Claims: []typemetadata.ClaimMetadata{
			{Path: []any{"email"}, Display: []typemetadata.ClaimDisplayEntry{{Locale: en, Name: "Email"}}},
		},
	}
	vci := &metadata.CredentialMetadata{
		Claims: []metadata.ClaimsDescription{
			{
				Path:      metadata.ClaimsPathPointer{"email"},
				Mandatory: &mandatory,
				Display:   []metadata.Display{{Name: "Email (VCI)", Locale: &en}},
			},
		},
	}
	out := Merge(vct, vci)
	require.Len(t, out.Claims, 1)
	require.NotNil(t, out.Claims[0].Mandatory)
	require.True(t, *out.Claims[0].Mandatory)
}

// TestMerge_PathFromVctOnMatchedClaim verifies the Path identity choice on
// matched claims (cosmetic — both inputs canonicalise equal).
func TestMerge_PathFromVctOnMatchedClaim(t *testing.T) {
	en := "en"
	vct := &typemetadata.VctTypeMetadata{
		Claims: []typemetadata.ClaimMetadata{
			{Path: []any{"address", "country"}, Display: []typemetadata.ClaimDisplayEntry{{Locale: en, Name: "Country"}}},
		},
	}
	vci := &metadata.CredentialMetadata{
		Claims: []metadata.ClaimsDescription{
			{Path: metadata.ClaimsPathPointer{"address", "country"}, Display: []metadata.Display{{Name: "Country (VCI)", Locale: &en}}},
		},
	}
	out := Merge(vct, vci)
	require.Len(t, out.Claims, 1)
	require.Equal(t, metadata.ClaimsPathPointer{"address", "country"}, out.Claims[0].Path)
}

// TestMerge_NumericPathCoercion verifies that JSON-unmarshaled float64(2)
// matches Go int(2) when claims at an array index appear in both sources.
func TestMerge_NumericPathCoercion(t *testing.T) {
	en, nl := "en", "nl"
	vct := &typemetadata.VctTypeMetadata{
		Claims: []typemetadata.ClaimMetadata{
			{
				Path:    []any{"nationalities", float64(0)},
				Display: []typemetadata.ClaimDisplayEntry{{Locale: en, Name: "Primary nationality"}},
			},
		},
	}
	vci := &metadata.CredentialMetadata{
		Claims: []metadata.ClaimsDescription{
			{
				Path:    metadata.ClaimsPathPointer{"nationalities", 0}, // int, not float64
				Display: []metadata.Display{{Name: "Eerste nationaliteit", Locale: &nl}},
			},
		},
	}
	out := Merge(vct, vci)
	require.Len(t, out.Claims, 1, "float64 and int at the same position must merge into one claim")
	require.Len(t, out.Claims[0].Display, 2, "VCT en plus VCI nl must coexist on the merged claim")
}

// TestMerge_WildcardOnlyMatchesWildcard verifies that a null wildcard in
// one source does NOT match an enumerated element in the other; both
// claims appear separately in the union.
func TestMerge_WildcardOnlyMatchesWildcard(t *testing.T) {
	en := "en"
	vct := &typemetadata.VctTypeMetadata{
		Claims: []typemetadata.ClaimMetadata{
			{Path: []any{"nationalities", nil}, Display: []typemetadata.ClaimDisplayEntry{{Locale: en, Name: "Any nationality"}}},
		},
	}
	vci := &metadata.CredentialMetadata{
		Claims: []metadata.ClaimsDescription{
			{Path: metadata.ClaimsPathPointer{"nationalities", "DE"}, Display: []metadata.Display{{Name: "German nationality", Locale: &en}}},
		},
	}
	out := Merge(vct, vci)
	require.Len(t, out.Claims, 2, "wildcard and enumerated index are distinct paths and must not merge")
}

// TestMerge_NilInputs covers degenerate inputs: either side absent or both
// absent must produce a well-formed empty CredentialMetadata.
func TestMerge_NilInputs(t *testing.T) {
	empty := Merge(nil, nil)
	require.Empty(t, empty.Display)
	require.Empty(t, empty.Claims)

	en := "en"
	vctOnly := Merge(&typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{{Locale: en, Name: "Only VCT"}},
	}, nil)
	require.Len(t, vctOnly.Display, 1)
	require.Equal(t, "Only VCT", vctOnly.Display[0].Name)

	vciOnly := Merge(nil, &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Name: "Only VCI", Locale: &en},
		},
	})
	require.Len(t, vciOnly.Display, 1)
	require.Equal(t, "Only VCI", vciOnly.Display[0].Name)
}

// TestMerge_TwoPhaseIsolation simulates the architectural requirement that
// both enrichment phases compute against the immutable VCI baseline. The
// pre-issuance VCT (vctA) carries one locale; the post-issuance VCT (vctB)
// carries a different one. Running Merge(vctB, vci) directly (without
// inheriting from a prior merge result) must drop vctA's locale entirely.
func TestMerge_TwoPhaseIsolation(t *testing.T) {
	en, de, es := "en", "de", "es"
	vci := &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Name: "VCI (es)", Locale: &es},
		},
	}
	vctA := &typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{{Locale: en, Name: "Pre-issuance"}},
	}
	vctB := &typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{{Locale: de, Name: "Post-issuance"}},
	}

	pre := Merge(vctA, vci)
	require.Len(t, pre.Display, 2)

	// Post-issuance pass merges against the same VCI baseline — NOT against
	// `pre`. The English locale from vctA must not leak through.
	post := Merge(vctB, vci)
	require.Len(t, post.Display, 2)
	names := []string{post.Display[0].Name, post.Display[1].Name}
	require.Contains(t, names, "Post-issuance")
	require.Contains(t, names, "VCI (es)")
	require.NotContains(t, names, "Pre-issuance", "stale pre-issuance VCT data must not leak into post-issuance merge")
}

// TestMerge_VctOnlyDisplayFields verifies that VCT-only fields
// (BackgroundColor, TextColor, Logo derived from rendering.simple.logo)
// flow through to the merged credential display unchanged.
func TestMerge_VctOnlyDisplayFields(t *testing.T) {
	vct := &typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{
			{
				Locale:          "en-US",
				Name:            "Email",
				Description:     "An email credential",
				Logo:            &typemetadata.RemoteImage{URI: "https://x/logo.png", AltText: "logo"},
				BackgroundColor: "#FF0000",
				TextColor:       "#FFFFFF",
			},
		},
		Claims: []typemetadata.ClaimMetadata{
			{
				Path:    []any{"email"},
				Display: []typemetadata.ClaimDisplayEntry{{Locale: "en", Name: "Email"}},
			},
		},
	}
	out := Merge(vct, nil)
	require.Len(t, out.Display, 1)
	require.Equal(t, "Email", out.Display[0].Name)
	require.NotNil(t, out.Display[0].Display.Locale)
	require.Equal(t, "en-US", *out.Display[0].Display.Locale)
	require.Equal(t, "An email credential", out.Display[0].Description)
	require.Equal(t, "#FF0000", out.Display[0].BackgroundColor)
	require.Equal(t, "#FFFFFF", out.Display[0].TextColor)
	require.NotNil(t, out.Display[0].Logo)
	require.Equal(t, "https://x/logo.png", out.Display[0].Logo.Uri)
	require.Len(t, out.Claims, 1)
	require.Len(t, out.Claims[0].Display, 1)
	require.Equal(t, "Email", out.Claims[0].Display[0].Name)
}
