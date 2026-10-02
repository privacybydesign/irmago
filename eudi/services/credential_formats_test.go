package services

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/stretchr/testify/require"
)

// TestNewCredentialFormatsRegistersEveryFormat pins the registry's contents:
// every format the wallet supports has a parser, a key binder and a store, and
// the display sources the activity log and logo backfill read cover the same
// formats. The OpenID4VCI session fails a format at runtime when its entry is
// missing, so this is where a dropped entry has to fail instead.
func TestNewCredentialFormatsRegistersEveryFormat(t *testing.T) {
	d := newTestHolderDB(t)
	formats := NewCredentialFormats(
		&eudi.Configuration{},
		nil,
		d,
		filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()),
		NewRevocationService(nil, nil),
		clientmodels.NewCurrentLocale("en"),
	)

	for _, format := range []models.CredentialFormat{models.CredentialFormatSdJwtVc, models.CredentialFormatMsoMdoc} {
		support, ok := formats[format]
		require.True(t, ok, "no support for %q", format)
		require.NotNil(t, support.Parser, "%q has no parser", format)
		require.NotNil(t, support.Keys, "%q has no key binder", format)
		require.NotNil(t, support.Store, "%q has no store", format)
	}
	require.Len(t, formats, 2, "a new format needs a registry entry, a display source and a test row here")
	require.Len(t, NewCredentialDisplaySources(d), len(formats),
		"the read-only display sources must cover the same formats as the registry")
}

func TestMissingDisplayMetadataReason(t *testing.T) {
	display := metadata.CredentialDisplays{{Name: "Age Verification"}}
	claims := []metadata.ClaimsDescription{{Path: metadata.ClaimsPathPointer{"eu.europa.ec.av.1", "age_over_18"}}}

	t.Run("configuration absent names the configuration id", func(t *testing.T) {
		reason := missingDisplayMetadataReason("av-config", metadata.CredentialConfiguration{}, false)

		require.Contains(t, reason, "av-config")
		require.Contains(t, reason, "advertises no credential configuration")
	})

	t.Run("configuration with no display metadata in either placement", func(t *testing.T) {
		// Reaching this case now means the issuer published nothing. Until
		// CredentialConfiguration.UnmarshalJSON normalised the pre-v1.0 placement, it
		// also caught an issuer emitting display/claims directly on the configuration,
		// and the message said so; that reading is no longer possible, so the message
		// must not send anyone looking for a draft mismatch that is handled.
		reason := missingDisplayMetadataReason("av-config", metadata.CredentialConfiguration{
			Format: metadata.CredentialFormatIdentifier_MsoMdoc,
		}, true)

		require.Contains(t, reason, "no display metadata")
		require.NotContains(t, reason, "which is not read")
	})

	t.Run("credential_metadata without display entries", func(t *testing.T) {
		reason := missingDisplayMetadataReason("av-config", metadata.CredentialConfiguration{
			CredentialMetadata: &metadata.CredentialMetadata{Claims: claims},
		}, true)

		require.Contains(t, reason, "no display entries")
	})

	t.Run("display without claims costs the attribute labels only", func(t *testing.T) {
		reason := missingDisplayMetadataReason("av-config", metadata.CredentialConfiguration{
			CredentialMetadata: &metadata.CredentialMetadata{Display: display},
		}, true)

		require.Contains(t, reason, "no claims")
		require.Contains(t, reason, "without labels")
	})

	t.Run("complete display metadata reports nothing", func(t *testing.T) {
		reason := missingDisplayMetadataReason("av-config", metadata.CredentialConfiguration{
			CredentialMetadata: &metadata.CredentialMetadata{Display: display, Claims: claims},
		}, true)

		require.Empty(t, reason)
	})
}
