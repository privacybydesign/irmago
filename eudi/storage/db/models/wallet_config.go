package models

import "time"

// WalletConfigDocument persists a signed wallet config so the wallet still knows
// who is trusted after a restart, and offline.
//
// The signed document is stored rather than its parsed content, as
// StatusListCacheEntry stores the raw token: it is re-verified against the
// environment's signing root when it is read, so a document that no longer
// verifies is dropped rather than trusted.
//
// There is no expiry column — a config carries its own `next_update` and grace
// period, and a second copy here could disagree with the signed one.
type WalletConfigDocument struct {
	// ConfigID is the config's own `id` (walletconfig.Config.ID), which the
	// active environment names in walletconfig.Environment.ConfigID. One
	// document per config id.
	ConfigID string `gorm:"primaryKey"`

	// RawJws is the unmodified compact JWS, encrypted at rest by the SQLCipher
	// layer.
	RawJws []byte `gorm:"type:bytea;not null"`

	// FetchedAt is for diagnostics only.
	FetchedAt time.Time `gorm:"not null"`
}
