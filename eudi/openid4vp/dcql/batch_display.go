package dcql

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// The functions in this file operate purely on models.CredentialBatch's
// already format-agnostic fields (display metadata, validity window, batch
// size) — nothing here is specific to any one credential format. They exist
// here, shared by every DcqlCredentialQueryHandler implementation backed by
// this batch model (currently eudi_sdjwt_dcql and mdoc_dcql), instead of
// being copy-pasted into each handler.

// IsBatchValid returns false if the credential batch is expired or not yet
// valid. Unix epoch (time.Unix(0,0)) is treated as "not set" because the
// storage layer currently always marks ExpiresAt/NotBefore as Valid, even
// when the underlying credential has no exp/nbf claim — storing 0 as the
// timestamp.
func IsBatchValid(batch *models.CredentialBatch, now time.Time) bool {
	epoch := time.Unix(0, 0)
	if batch.ExpiresAt.Valid && !batch.ExpiresAt.V.Equal(epoch) && now.After(batch.ExpiresAt.V) {
		return false
	}
	if batch.NotBefore.Valid && !batch.NotBefore.V.Equal(epoch) && now.Before(batch.NotBefore.V) {
		return false
	}
	return true
}

// BatchExpiryUnix returns the batch's expiry as a unix timestamp, or nil if
// the batch does not expire.
func BatchExpiryUnix(batch *models.CredentialBatch) *int64 {
	if batch.ExpiresAt.Valid {
		x := batch.ExpiresAt.V.Unix()
		return &x
	}
	return nil
}

// BatchInstanceCountRemaining returns nil for batch-of-1 credentials
// (infinitely reusable) and a pointer to the remaining count for larger
// batches.
func BatchInstanceCountRemaining(batch *models.CredentialBatch) *uint {
	if batch.BatchSize <= 1 {
		return nil
	}
	return &batch.RemainingCount
}

// BatchDisplayName returns the display name for a credential from its stored
// metadata. Falls back to the VerifiableCredentialType if no display
// metadata is available.
func BatchDisplayName(batch *models.CredentialBatch) clientmodels.TranslatedString {
	if batch.CredentialMetadata != nil {
		ts := clientmodels.TranslatedString{}
		for _, d := range batch.CredentialMetadata.Display {
			locale := clientmodels.DefaultFallbackLanguage
			if d.Locale.Valid {
				if base, ok := metadata.TryGetBaseLanguageFromLocale(d.Locale.V); ok {
					locale = base
				}
			}
			ts[locale] = d.Name
		}
		if len(ts) > 0 {
			return ts
		}
	}
	return clientmodels.TranslatedString{clientmodels.DefaultFallbackLanguage: batch.VerifiableCredentialType}
}

// ClaimDisplayName looks up the display name for a claim from the stored
// credential metadata. Returns an empty TranslatedString when no metadata
// display entry exists for the path — callers treat that as "no display
// name". claimPath may contain concrete array indices; metadata paths may
// contain null wildcards in their place (matched via
// claimPathMatchesMetadataPath).
func ClaimDisplayName(batch *models.CredentialBatch, claimPath []any) clientmodels.TranslatedString {
	if batch.CredentialMetadata == nil {
		return clientmodels.TranslatedString{}
	}
	for _, claim := range batch.CredentialMetadata.Claims {
		if len(claim.Display) == 0 {
			continue
		}
		var path []any
		if err := json.Unmarshal(claim.Path, &path); err != nil {
			continue
		}
		if !ClaimPathMatchesMetadataPath(claimPath, path) {
			continue
		}
		ts := clientmodels.TranslatedString{}
		for _, d := range claim.Display {
			locale := clientmodels.DefaultFallbackLanguage
			if d.Locale.Valid {
				if base, ok := metadata.TryGetBaseLanguageFromLocale(d.Locale.V); ok {
					locale = base
				}
			}
			ts[locale] = d.Name
		}
		if len(ts) > 0 {
			return ts
		}
	}
	return clientmodels.TranslatedString{}
}

// ClaimPathMatchesMetadataPath checks if a concrete claim path matches a
// metadata path that may contain null wildcards. Null in the metadata path
// matches any integer index in the claim path.
func ClaimPathMatchesMetadataPath(claimPath []any, metadataPath []any) bool {
	if len(claimPath) != len(metadataPath) {
		return false
	}
	for i := range claimPath {
		if metadataPath[i] == nil {
			// Null wildcard matches any integer index.
			if !isArrayIndexComponent(claimPath[i]) {
				return false
			}
		} else {
			if fmt.Sprintf("%v", claimPath[i]) != fmt.Sprintf("%v", metadataPath[i]) {
				return false
			}
		}
	}
	return true
}

// isArrayIndexComponent returns true if the path component is a numeric
// array index.
func isArrayIndexComponent(component any) bool {
	switch component.(type) {
	case int, float64:
		return true
	}
	return false
}

// BatchCredentialImage resolves the credential logo from the batch's display
// metadata using the given logo manager. Returns nil if no logo is
// configured or the logo cannot be loaded.
func BatchCredentialImage(batch *models.CredentialBatch, logoManager filesystem.LogoManager) *clientmodels.Image {
	if batch.CredentialMetadata == nil {
		return nil
	}
	for _, display := range batch.CredentialMetadata.Display {
		if display.LogoURI == "" {
			continue
		}
		if img := eudi.LoadLogoImage(logoManager, display.LogoURI); img != nil {
			return img
		}
	}
	return nil
}

// BatchIssuerImage resolves the issuer logo from the batch's issuer display
// metadata using the given logo manager. Returns nil if no logo is
// configured or the logo cannot be loaded.
func BatchIssuerImage(batch *models.CredentialBatch, logoManager filesystem.LogoManager) *clientmodels.Image {
	for _, d := range batch.IssuerDisplay {
		if !d.LogoURI.Valid || d.LogoURI.V == "" {
			continue
		}
		if img := eudi.LoadLogoImage(logoManager, d.LogoURI.V); img != nil {
			return img
		}
	}
	return nil
}

// BatchIssuerTrustedParty builds a TrustedParty from the stored issuer
// display metadata, including the issuer logo if available on disk via the
// given logo manager.
func BatchIssuerTrustedParty(batch *models.CredentialBatch, issuerLogoManager filesystem.LogoManager) clientmodels.TrustedParty {
	name := clientmodels.TranslatedString{}
	for _, d := range batch.IssuerDisplay {
		locale := clientmodels.DefaultFallbackLanguage
		if d.Locale.Valid {
			if base, ok := metadata.TryGetBaseLanguageFromLocale(d.Locale.V); ok {
				locale = base
			}
		}
		name[locale] = d.Name
	}
	return clientmodels.TrustedParty{
		Id:    batch.CredentialIssuer,
		Name:  name,
		Image: BatchIssuerImage(batch, issuerLogoManager),
	}
}
