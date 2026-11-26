package irmaclient

import (
	"slices"

	"github.com/privacybydesign/irmago/irma"
)

// The disclosure plan describes a request as choices → options → slots: one
// choice per discon, one option per non-empty con, one slot per credential type
// in a con. SlotCandidates gives what the wallet holds for each slot directly,
// rather than the combinations of instances Candidates returns per con.

// DisconSlots is one discon of a request.
type DisconSlots struct {
	// The discon holds an empty con: it may be answered with nothing.
	Optional bool
	// One per non-empty con, in request order.
	Cons []ConSlots
}

// ConSlots is one non-empty con: the credential types it asks for, in order of
// first appearance.
type ConSlots []CredentialSlot

// CredentialSlot is one credential type of a con.
type CredentialSlot struct {
	Type irma.CredentialTypeIdentifier
	// What the con asks of this type, in request order. A request for only
	// the credential (no attribute) is one entry whose Type names the
	// credential type itself.
	Requests []irma.AttributeRequest
	// The stored instances of this type that satisfy those requests,
	// including the ones that cannot be used for this request now.
	Candidates []SlotCandidate
	// Whether to offer adding a card of this type (addCredSuggestion).
	Obtainable bool
}

// SlotCandidate is one stored instance that fits a slot.
type SlotCandidate struct {
	Hash string
	// Whether the instance can be disclosed for this request; Reason says
	// why not.
	Usable bool
	Reason UnusableReason
}

// UnusableReason says why a stored instance cannot be disclosed for a request.
type UnusableReason string

const (
	UnusableNone UnusableReason = ""
	// The issuer revoked it.
	UnusableRevoked UnusableReason = "revoked"
	// It expired and the request does not accept expired instances of its
	// type (skipExpiryCheck).
	UnusableExpired UnusableReason = "expired"
	// The request asks a non-revocation proof for its type and it was issued
	// without revocation support.
	UnusableNotRevocable UnusableReason = "not_revocable"
)

// SlotCandidates returns, per discon of the request's condiscon, the slots of
// each of its options and the stored instances fitting each slot.
func (client *IrmaClient) SlotCandidates(request irma.SessionRequest) []DisconSlots {
	client.credMutex.Lock()
	defer client.credMutex.Unlock()

	condiscon := request.Disclosure().Disclose
	result := make([]DisconSlots, 0, len(condiscon))
	for _, discon := range condiscon {
		disconSlots := DisconSlots{Cons: []ConSlots{}}
		for _, con := range discon {
			if len(con) == 0 {
				disconSlots.Optional = true
				continue
			}
			disconSlots.Cons = append(disconSlots.Cons, client.conSlots(request, con))
		}
		result = append(result, disconSlots)
	}
	return result
}

func (client *IrmaClient) conSlots(request irma.SessionRequest, con irma.AttributeCon) ConSlots {
	// One slot per type, in order of first appearance. AttributeCon's own
	// CredentialTypes only drops repeats that follow each other.
	var types []irma.CredentialTypeIdentifier
	for _, attr := range con {
		if t := attr.Type.CredentialTypeIdentifier(); !slices.Contains(types, t) {
			types = append(types, t)
		}
	}

	slots := ConSlots{}
	for _, credTypeID := range types {
		slot := CredentialSlot{Type: credTypeID, Candidates: []SlotCandidate{}}
		for _, attr := range con {
			if attr.Type.CredentialTypeIdentifier() == credTypeID {
				slot.Requests = append(slot.Requests, attr)
			}
		}

		for _, attrs := range client.attributes[credTypeID] {
			satisfies, _ := client.satisfiesCon(request, attrs, con)
			if !satisfies {
				continue
			}
			cred, _, _ := client.credentialByHash(attrs.Hash())
			reason := unusableReason(
				attrs.Revoked,
				attrs.IsValid() || slices.Contains(request.Disclosure().SkipExpiryCheck, credTypeID),
				!request.Base().RequestsRevocation(credTypeID) || (cred != nil && cred.NonRevocationWitness != nil),
			)
			slot.Candidates = append(slot.Candidates, SlotCandidate{
				Hash:   attrs.Hash(),
				Usable: reason == UnusableNone,
				Reason: reason,
			})
		}

		hasUsable := slices.ContainsFunc(slot.Candidates, func(c SlotCandidate) bool { return c.Usable })
		slot.Obtainable = client.addCredSuggestion(request, credTypeID, hasUsable)
		slots = append(slots, slot)
	}
	return slots
}

// unusableReason decides, for one stored instance and one request, whether it
// can be disclosed: the same rule as satisfiesCon's usable, with the reason
// kept. A revoked instance is reported as revoked first, since adding it again
// is the fix either way.
//
// validForRequest is true when the instance has not expired or the request
// accepts expired instances of its type; revocationOk is true when the request
// asks no non-revocation proof for its type or the instance can give one.
func unusableReason(revoked, validForRequest, revocationOk bool) UnusableReason {
	switch {
	case revoked:
		return UnusableRevoked
	case !validForRequest:
		return UnusableExpired
	case !revocationOk:
		return UnusableNotRevocable
	default:
		return UnusableNone
	}
}
