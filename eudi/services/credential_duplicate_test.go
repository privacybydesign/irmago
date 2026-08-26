package services

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// batchStillUsable decides whether an identical re-issuance is refused as a
// duplicate or accepted as a renewal, so what counts as "usable" has to stay the
// same thing dcql.FindCandidates means by it. These cases pin both halves of that
// rule and, more importantly, pin that the renewal path stays open: every
// legitimate renewal of an age-verification credential carries identical
// attributes and therefore arrives with an identical hash, so a wallet that
// refused all of them could never top up a spent batch.
func TestBatchStillUsable(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	nullTime := func(t time.Time) datatypes.NullTime {
		return datatypes.NullTime{V: t, Valid: true}
	}

	tests := []struct {
		name string
		// batch as stored; refuse reports whether an identical re-issuance is
		// rejected rather than allowed to replace it.
		batch  models.CredentialBatch
		refuse bool
		reason string
	}{
		{
			name:   "a batch with instances left and no expiry is still usable",
			batch:  models.CredentialBatch{BatchSize: 100, RemainingCount: 100},
			refuse: true,
			reason: "still has 100 of 100 instances unused",
		},
		{
			name:   "a partly spent batch is still usable",
			batch:  models.CredentialBatch{BatchSize: 100, RemainingCount: 1},
			refuse: true,
			reason: "still has 1 of 100 instances unused",
		},
		{
			// The top-up case. Refusing here is what would leave a wallet
			// permanently unable to present.
			name:   "a spent batch may be replaced",
			batch:  models.CredentialBatch{BatchSize: 100, RemainingCount: 0},
			refuse: false,
		},
		{
			// The renewal case: attributes never change, so the hash matches and
			// only the expiry distinguishes this from a duplicate.
			name: "an expired batch may be replaced even with instances left",
			batch: models.CredentialBatch{
				BatchSize: 100, RemainingCount: 100,
				ExpiresAt: nullTime(now.Add(-time.Hour)),
			},
			refuse: false,
		},
		{
			name: "a batch not yet valid may be replaced",
			batch: models.CredentialBatch{
				BatchSize: 100, RemainingCount: 100,
				NotBefore: nullTime(now.Add(time.Hour)),
			},
			refuse: false,
		},
		{
			name: "a batch expiring in the future is still usable",
			batch: models.CredentialBatch{
				BatchSize: 100, RemainingCount: 100,
				ExpiresAt: nullTime(now.Add(time.Hour)),
			},
			refuse: true,
			reason: "still has 100 of 100 instances unused",
		},
		{
			// A batch of one is a reusable credential, not a set of single-use
			// attestations, so replacing it discards nothing and re-issuance is
			// how it gets refreshed. Refusing here would block refresh for the
			// credential's whole validity period -- "still usable" is true of a
			// reusable credential from issuance until expiry -- and the holder
			// would have to delete it to obtain a new one. It is also what keeps
			// ordinary SD-JWT re-issuance working: an issuer that advertises no
			// batch_credential_issuance produces exactly this shape.
			name:   "a batch of one is always replaceable, however fresh",
			batch:  models.CredentialBatch{BatchSize: 1, RemainingCount: 1},
			refuse: false,
		},
		{
			name:   "a batch of one with no remaining count is replaceable too",
			batch:  models.CredentialBatch{BatchSize: 1, RemainingCount: 0},
			refuse: false,
		},
		{
			// A batch of one whose validity is still ahead of it is replaceable
			// for the same reason: BatchSize decides this before expiry is
			// consulted at all.
			name: "a batch of one expiring in the future is still replaceable",
			batch: models.CredentialBatch{
				BatchSize: 1, RemainingCount: 1,
				ExpiresAt: nullTime(now.Add(time.Hour)),
			},
			refuse: false,
		},
		{
			name: "an expired batch of one may be replaced",
			batch: models.CredentialBatch{
				BatchSize: 1, RemainingCount: 0,
				ExpiresAt: nullTime(now.Add(-time.Hour)),
			},
			refuse: false,
		},
		{
			// The smallest real batch: two instances, both unspent. This is the
			// boundary the BatchSize <= 1 guard sits on, so it is worth pinning
			// that protection starts here rather than one higher.
			name:   "a batch of two is protected",
			batch:  models.CredentialBatch{BatchSize: 2, RemainingCount: 2},
			refuse: true,
			reason: "still has 2 of 2 instances unused",
		},
		{
			// dcql.IsBatchValid treats a zero timestamp as unset rather than as
			// 1970, so a batch carrying one must not read as expired.
			name: "an epoch expiry counts as no expiry",
			batch: models.CredentialBatch{
				BatchSize: 100, RemainingCount: 100,
				ExpiresAt: nullTime(time.Unix(0, 0)),
			},
			refuse: true,
			reason: "still has 100 of 100 instances unused",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reason := batchStillUsable(&test.batch, now)

			if !test.refuse {
				require.Empty(t, reason, "batch should have been replaceable")
				return
			}
			require.NotEmpty(t, reason, "batch should have been refused as a duplicate")
			require.Equal(t, test.reason, reason)
		})
	}
}
