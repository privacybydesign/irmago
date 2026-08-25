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
			// A batch of one is reusable rather than single-use, so
			// RemainingCount is not consulted -- the same rule
			// dcql.BatchInstanceCountRemaining encodes by returning nil.
			name:   "a batch of one is usable even with no remaining count",
			batch:  models.CredentialBatch{BatchSize: 1, RemainingCount: 0},
			refuse: true,
			reason: "is still valid",
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
