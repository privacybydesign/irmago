package models

import "time"

// RecognizedTrustListEntry persists one recognized trust list (a LoTE), so the
// wallet can rank parties against it across restarts and while offline, up to
// the list's own NextUpdate.
//
// We store the signed list, not the entries it contains: the signature is
// re-checked against the current anchors on every read, so a list that was
// believable during an earlier run is not believed on that account alone.
type RecognizedTrustListEntry struct {
	// ListId is the list's identifier — the one the wallet recognizes it under,
	// which a stored copy must carry as its own; the table key.
	ListId string `gorm:"primaryKey"`

	// RawJws is the unmodified signed list (typ `lote+jwt`). The SQLCipher
	// layer encrypts it at rest, like every other row.
	RawJws []byte `gorm:"type:bytea;not null"`

	// SequenceNumber is the revision this copy carries. Kept as a column so a
	// rollback can be turned away without verifying the stored copy first.
	SequenceNumber int64 `gorm:"not null"`

	// NextUpdate is when this copy stops counting and has to be re-fetched.
	NextUpdate time.Time `gorm:"not null"`

	// FetchedAt records when the copy was written, for diagnostics.
	FetchedAt time.Time `gorm:"not null"`
}
