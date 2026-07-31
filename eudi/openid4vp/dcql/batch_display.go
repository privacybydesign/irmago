package dcql

import (
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// The functions in this file operate purely on models.CredentialBatch's
// already format-agnostic fields (validity window, batch size) — nothing
// here is specific to any one credential format. They exist here, shared by
// every DcqlCredentialQueryHandler implementation backed by this batch model
// (currently eudi_sdjwt_dcql and mdoc_dcql), instead of being copy-pasted
// into each handler.
//
// Display-name/logo resolution (credential name, issuer name, claim names,
// images) lives in eudi/services (ResolveBatchDisplay, LoadResolvedLogo,
// IssuerLogoURIsByLanguage, CredentialLogoURIsByLanguage) instead of here —
// that's where the locale-fallback machinery those depend on already lives.

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
