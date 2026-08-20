package models

import "time"

// TrustListDocument persists a signed List of Trusted Entities (LoTE) so the
// wallet still knows who is on a recognized list after a restart, and offline.
//
// The signed document is stored rather than its parsed content, as
// StatusListCacheEntry stores the raw token: it is re-verified against the
// anchors in force when it is read, so a revoked list-signing certificate
// invalidates what is already on disk.
//
// There is no expiry column — a list carries its own `next_update`, and a second
// copy here could disagree with the signed one.
type TrustListDocument struct {
	// ListId is the identifier the wallet's source set configures and the document
	// itself declares.
	ListId string `gorm:"primaryKey"`

	// RawJws is the unmodified compact JAdES-B-B document, encrypted at rest by the
	// SQLCipher layer.
	RawJws []byte `gorm:"type:bytea;not null"`

	// FetchedAt is for diagnostics only.
	FetchedAt time.Time `gorm:"not null"`
}
