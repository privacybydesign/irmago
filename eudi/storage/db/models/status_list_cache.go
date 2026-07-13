package models

import "time"

// StatusListCacheEntry persists a fetched Status List Token JWT so
// the wallet can read credential status across process restarts and
// while offline (within the entry's TTL).
//
// We store the raw signed JWT (not the decoded bit array): re-verify
// happens against the current trust anchors on every cache hit, and
// the entry remains compact. Decompression is performed by the
// statuslist package in-process on each read.
type StatusListCacheEntry struct {
	// URI is the canonical status_list URI from the credential's
	// `status.status_list.uri` claim; the table key.
	URI string `gorm:"primaryKey"`

	// RawJwt is the unmodified signed Status List Token (typ
	// `statuslist+jwt`). The SQLCipher layer encrypts this at rest.
	RawJwt []byte `gorm:"type:bytea;not null"`

	// ExpiresAt is the absolute time at which the cached value
	// becomes stale and the entry must be re-fetched. Set to
	// min(http_max_age, jwt_ttl) clamped to [60s, 24h] (see
	// statuslist.ClampTTL).
	ExpiresAt time.Time `gorm:"not null;index"`

	// FetchedAt records when the entry was written. Useful for
	// diagnostics and for refresh-pacing decisions.
	FetchedAt time.Time `gorm:"not null"`
}
