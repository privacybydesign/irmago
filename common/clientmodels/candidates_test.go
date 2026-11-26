package clientmodels

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortCandidates(t *testing.T) {
	uses := func(n uint) *uint { return &n }
	at := func(n int64) *int64 { return &n }

	tests := []struct {
		name string
		in   []*SelectableCredentialInstance
		want []string // hashes, best first
	}{
		{
			name: "usable before unusable, whatever else",
			in: []*SelectableCredentialInstance{
				{Hash: "a", Usable: false, ExpiryDate: at(900), BatchInstanceCountRemaining: uses(9)},
				{Hash: "b", Usable: true, ExpiryDate: at(100), BatchInstanceCountRemaining: uses(1)},
			},
			want: []string{"b", "a"},
		},
		{
			name: "more uses left first, unlimited before any count",
			in: []*SelectableCredentialInstance{
				{Hash: "one", Usable: true, BatchInstanceCountRemaining: uses(1)},
				{Hash: "five", Usable: true, BatchInstanceCountRemaining: uses(5)},
				{Hash: "unlimited", Usable: true},
			},
			want: []string{"unlimited", "five", "one"},
		},
		{
			name: "same uses: later expiry first, no expiry before any date",
			in: []*SelectableCredentialInstance{
				{Hash: "soon", Usable: true, ExpiryDate: at(100)},
				{Hash: "never", Usable: true},
				{Hash: "later", Usable: true, ExpiryDate: at(200)},
			},
			want: []string{"never", "later", "soon"},
		},
		{
			name: "same expiry: later issuance first, unknown issuance last",
			in: []*SelectableCredentialInstance{
				{Hash: "unknown", Usable: true, ExpiryDate: at(500)},
				{Hash: "old", Usable: true, ExpiryDate: at(500), IssuanceDate: at(10)},
				{Hash: "new", Usable: true, ExpiryDate: at(500), IssuanceDate: at(20)},
			},
			want: []string{"new", "old", "unknown"},
		},
		{
			name: "all equal: hash ascending",
			in: []*SelectableCredentialInstance{
				{Hash: "c", Usable: true},
				{Hash: "a", Usable: true},
				{Hash: "b", Usable: true},
			},
			want: []string{"a", "b", "c"},
		},
		{
			name: "uses outrank expiry, expiry outranks issuance",
			in: []*SelectableCredentialInstance{
				{Hash: "x", Usable: true, BatchInstanceCountRemaining: uses(2), ExpiryDate: at(900), IssuanceDate: at(900)},
				{Hash: "y", Usable: true, BatchInstanceCountRemaining: uses(3), ExpiryDate: at(100), IssuanceDate: at(100)},
				{Hash: "z", Usable: true, BatchInstanceCountRemaining: uses(2), ExpiryDate: at(800), IssuanceDate: at(999)},
			},
			want: []string{"y", "x", "z"},
		},
		{
			name: "unusable ones are ordered by the same rules",
			in: []*SelectableCredentialInstance{
				{Hash: "u1", UnusableReason: UnusableReason_Expired, ExpiryDate: at(100)},
				{Hash: "u2", UnusableReason: UnusableReason_Revoked, ExpiryDate: at(300)},
				{Hash: "ok", Usable: true},
			},
			want: []string{"ok", "u2", "u1"},
		},
		{name: "empty", in: nil, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SortCandidates(tt.in)
			var got []string
			for _, c := range tt.in {
				got = append(got, c.Hash)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
