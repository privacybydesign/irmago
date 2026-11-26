package clientmodels

import (
	"cmp"
	"slices"
)

// SortCandidates puts a slot's candidates best first, in place:
//
//  1. usable before unusable;
//  2. more uses left first (nil BatchInstanceCountRemaining means unlimited and
//     sorts first);
//  3. later ExpiryDate first (no expiry sorts first);
//  4. later IssuanceDate first (an unknown issuance date sorts last);
//  5. Hash ascending, so the order is fully determined.
//
// The first candidate is the one a frontend picks by default, and the one it
// shows for several cards with the same values.
func SortCandidates(candidates []*SelectableCredentialInstance) {
	slices.SortStableFunc(candidates, compareCandidates)
}

func compareCandidates(a, b *SelectableCredentialInstance) int {
	if a.Usable != b.Usable {
		if a.Usable {
			return -1
		}
		return 1
	}
	if c := compareLaterFirst(a.BatchInstanceCountRemaining, b.BatchInstanceCountRemaining, true); c != 0 {
		return c
	}
	if c := compareLaterFirst(a.ExpiryDate, b.ExpiryDate, true); c != 0 {
		return c
	}
	if c := compareLaterFirst(a.IssuanceDate, b.IssuanceDate, false); c != 0 {
		return c
	}
	return cmp.Compare(a.Hash, b.Hash)
}

// compareLaterFirst orders the larger value first. nil sorts before any value
// when nilFirst (unlimited uses, no expiry), else after it (unknown date).
func compareLaterFirst[T cmp.Ordered](a, b *T, nilFirst bool) int {
	nilSide := 1
	if nilFirst {
		nilSide = -1
	}
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return nilSide
	case b == nil:
		return -nilSide
	default:
		return cmp.Compare(*b, *a)
	}
}
