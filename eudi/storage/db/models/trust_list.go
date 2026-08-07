package models

import "time"

// TrustListDocument persists a signed List of Trusted Entities (LoTE) so the
// wallet still knows who is on a recognized list after a restart, and while
// offline.
//
// The signed document is stored rather than its parsed content, for the same
// reason StatusListCacheEntry stores the raw token: it is re-verified against
// the trust anchors in force when it is read, so a revoked list-signing
// certificate invalidates what is already on disk and not merely the next
// download.
//
// There is no expiry column. A list carries its own `next_update`, which the
// lote package reads out of the verified document; a second copy of it here
// would be a value that could disagree with the signed one.
type TrustListDocument struct {
	// ListId is the recognized list's identifier, as configured in the
	// wallet's source set and declared by the document itself; the table key.
	ListId string `gorm:"primaryKey"`

	// RawJws is the unmodified compact JAdES-B-B document. The SQLCipher layer
	// encrypts this at rest.
	RawJws []byte `gorm:"type:bytea;not null"`

	// FetchedAt records when the document was written, for diagnostics.
	FetchedAt time.Time `gorm:"not null"`
}
