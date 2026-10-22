package services

import (
	"fmt"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// MigrateCredentialHashes recomputes the deduplication hash of every stored
// SD-JWT VC batch, rewriting the rows whose hash was computed before the issuer
// became part of it.
//
// Without this, a wallet that already holds credentials would stop recognising
// them: a re-issuance computes the new-style hash, finds no stored batch under
// it, and stores a second copy. The user would see the same credential twice,
// and the older row would never be matched again.
//
// The recomputation is exact rather than a guess, because every input the hash
// takes is already a column: VerifiableCredentialType, IssuerIdentifier and
// ProcessedSdJwtPayload, with Format deciding which hash function applies. That
// is the only reason this can be a migration at all — a hash over anything not
// retained would have needed the credentials re-fetched.
//
// Idempotent: a second run recomputes the same values and writes nothing, so it
// is safe to call on every startup, which is how it is wired.
//
// Collision is not a risk. The new hash covers strictly more input than the old
// one, so it can only tell apart batches the old one conflated — and the old one
// conflated none, since Hash is a unique index and two colliding rows could
// never both have existed.
func MigrateCredentialHashes(store db.SdJwtVcStore) error {
	batches, err := store.GetCredentialBatchList()
	if err != nil {
		return fmt.Errorf("credential hash migration: failed to list batches: %w", err)
	}

	migrated := 0
	for _, batch := range batches {
		want, err := recomputeBatchHash(batch)
		if err != nil {
			// One unreadable row must not stop the rest. A batch whose payload no
			// longer parses cannot be re-hashed, and leaving it alone is the
			// conservative outcome: it keeps working for presentation, and only
			// its duplicate detection stays on the old scheme.
			eudi.Logger.Warnf("credential hash migration: skipping batch %s: %v", batch.ID, err)
			continue
		}
		if want == batch.Hash {
			continue
		}
		if err := store.UpdateBatchHash(batch.ID, want); err != nil {
			return fmt.Errorf("credential hash migration: failed to update batch %s: %w", batch.ID, err)
		}
		migrated++
	}

	if migrated > 0 {
		eudi.Logger.Infof("credential hash migration: rewrote %d of %d credential hashes to include the issuer", migrated, len(batches))
	}
	return nil
}

// recomputeBatchHash computes what a stored batch's hash would be today, with
// the same function issuance uses. Kept next to the migration rather than in the
// SD-JWT service so the two cannot fall out of step without one of them failing
// to compile.
//
// SD-JWT VC only: no mdoc batch was ever stored under the old hash, since mdoc
// storage arrived after the issuer became part of the hash.
func recomputeBatchHash(batch *models.SdJwtVcBatch) (string, error) {
	switch batch.Format {
	case models.CredentialFormatSdJwtVc:
		return hashForSdJwtVc(batch.VerifiableCredentialType, batch.IssuerIdentifier, batch.ProcessedSdJwtPayload)
	default:
		// Includes the empty format, which older rows can carry: a batch was once
		// stored with Format unset when the issuer's metadata lacked the
		// configuration. Guessing a format to hash it under would be worse than
		// leaving it, since the wrong function yields a hash nothing will match.
		return "", fmt.Errorf("unsupported format %q", batch.Format)
	}
}
