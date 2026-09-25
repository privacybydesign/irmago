package dcql

import (
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// The functions in this file read an SdJwtVcBatch's validity window and batch
// counts. Today eudi_sdjwt_dcql is their only caller. They live in this
// package rather than back in eudi_sdjwt_dcql on the chance a future SD-JWT
// VC consumer in services needs them: eudi_sdjwt_dcql imports services, so
// services could never import eudi_sdjwt_dcql back without a cycle, and dcql
// has no such import to avoid.
//
// mso_mdoc does not share these: it works over a different batch model
// (MdocBatch, not SdJwtVcBatch) with its own equivalents — services.
// MdocBatchIsValid and the private helpers in mdoc_dcql/handler.go. The two
// formats' batch models have no field in common to write one shared
// implementation over without generics.
//
// Display-name/logo resolution (credential name, issuer name, claim names,
// images) lives in eudi/services (ResolveBatchDisplay, LoadResolvedLogo,
// IssuerLogoURIsByLanguage, CredentialLogoURIsByLanguage) instead of here —
// that's where the locale-fallback machinery those depend on already lives.

// IsBatchValid returns false if the credential batch is expired or not yet
// valid. Unix epoch (time.Unix(0,0)) is treated as "not set" because the
// storage layer currently always marks ExpiresAt/NotBefore as Valid, even
// when the underlying credential states no expiry or not-before of its own
// (an absent exp/nbf claim, an absent validityInfo bound) — storing 0 as the
// timestamp.
func IsBatchValid(batch *models.SdJwtVcBatch, now time.Time) bool {
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
func BatchExpiryUnix(batch *models.SdJwtVcBatch) *int64 {
	if batch.ExpiresAt.Valid {
		x := batch.ExpiresAt.V.Unix()
		return &x
	}
	return nil
}

// BatchInstanceCountRemaining returns nil for batch-of-1 credentials
// (infinitely reusable) and a pointer to the remaining count for larger
// batches.
func BatchInstanceCountRemaining(batch *models.SdJwtVcBatch) *uint {
	if batch.BatchSize <= 1 {
		return nil
	}
	return &batch.RemainingCount
}
