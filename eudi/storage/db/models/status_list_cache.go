package models

import "time"

// StatusListCacheEntry persists a fetched Status List Token so the wallet
// can read credential status across process restarts and while offline
// (within the entry's TTL).
//
// We store the raw signed token (not the decoded bit array): re-verify
// happens against the current trust anchors on every cache hit, and
// the entry remains compact. Decoding/decompression is performed by the
// statuslist package in-process on each read, which also sniffs the
// encoding (JWT or CWT — see statuslist.looksLikeCWT) back out of these
// bytes; nothing here needs to record which one it is.
type StatusListCacheEntry struct {
	// URI is the canonical status_list URI from the credential's
	// `status.status_list.uri` claim; the table key.
	URI string `gorm:"primaryKey"`

	// RawToken is the unmodified signed Status List Token, whichever encoding
	// the issuer published — a JWT (typ `statuslist+jwt`) or a CWT (COSE
	// protected header 16 `application/statuslist+cwt`). The column keeps its
	// deployed name raw_jwt, from before CWT support: AutoMigrate cannot
	// rename a column. The SQLCipher layer encrypts this at rest.
	RawToken []byte `gorm:"column:raw_jwt;type:bytea;not null"`

	// ExpiresAt is the absolute time at which the cached value
	// becomes stale and the entry must be re-fetched. Set from the
	// token's own ttl/exp (or the HTTP max-age as fallback), clamped
	// to [60s, 24h] (see statuslist.ClampTTL).
	ExpiresAt time.Time `gorm:"not null;index"`

	// FetchedAt records when the entry was written. Useful for
	// diagnostics and for refresh-pacing decisions.
	FetchedAt time.Time `gorm:"not null"`
}
