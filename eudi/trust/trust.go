// Package trust holds the vocabulary of the trust ladder: the evidence one
// party's identity check produced, and the verdict the wallet draws from it.
//
// The ladder has three rungs (clientmodels.TrustLevel) and answers one
// question: how strongly is this party vouched for? It never answers whether
// the party is who it claims to be — that is the identity gate, which runs
// first and fails the session outright when it rejects a party (see
// [github.com/privacybydesign/irmago/eudi.PartyValidationFailed]).
//
// Evaluation is fail-soft by construction: no signature in this package returns
// an error, so no evaluation path can fail a session. A channel that is
// unavailable contributes no evidence, and the party lands on a lower rung.
package trust

import (
	"context"
	"crypto/x509"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// Evidence is what the identity gate produced about one party, in the terms the
// evaluation channels key on. Every field is optional: absent evidence is
// simply a channel that has nothing to say about this party.
type Evidence struct {
	// Certificate is the validated end-entity certificate the party
	// authenticated with, or nil when it identified itself some other way (a
	// DID, or issuer metadata alone).
	//
	// Non-nil means the chain already verified against the Yivi trust anchors
	// — the gate ran before evaluation and would have failed the session
	// otherwise — so a certificate here is Yivi vouching for the party.
	Certificate *x509.Certificate

	// Identifiers are the party's stable identifiers, most specific first: the
	// OpenID4VP `client_id`, the credential issuer URL, a DID. The
	// recognized-list channel matches its entries against these.
	Identifiers []string
}

// Verdict is one party's rung, plus what put it there.
type Verdict struct {
	// Level is the strongest vouching found across the channels.
	Level clientmodels.TrustLevel
	// Listing is the recognized-list entry the verdict was granted on, or nil
	// when no list vouched for the party. It carries the curated display
	// metadata that outranks what the party asserts about itself.
	Listing *Listing
}

// Listing is a party's entry on a recognized trust list.
type Listing struct {
	// ListId identifies the recognized list the entry was found on.
	ListId string
	// Name is the curated display name of the party.
	Name clientmodels.TranslatedString
	// LogoURI is the curated logo, empty when the entry carries none.
	LogoURI string
	// OnboardedByYivi marks an entry Yivi itself vouches for. Meaningful only
	// on Yivi's own list.
	OnboardedByYivi bool
}

// Role is the capacity a party is trusted in. Trust as an issuer and trust as a
// verifier are separate grants, so every lookup names one.
type Role int

const (
	// RoleIssuer is the capacity to issue credentials.
	RoleIssuer Role = iota
	// RoleVerifier is the capacity to ask for them.
	RoleVerifier
)

// Lister is the recognized-list channel, in the terms this package evaluates
// in: one pinned state of the lists, asked about one party at a time.
type Lister interface {
	// Lookup returns the entry that vouches for this party in this role, or nil
	// when no recognized list does. Like everything else in this package it
	// cannot fail: a list that could not be read vouches for nobody.
	Lookup(role Role, ev Evidence) *Listing
}

// View evaluates parties against one pinned state of the world. A session takes
// a View once and asks it about every party it meets, so a list refresh landing
// mid-session cannot change that session's verdicts.
//
// The party's role is the method rather than a parameter, because trust as an
// issuer and trust as a verifier are separate grants and a caller must not be
// able to forget which one it is asking about.
type View interface {
	Verifier(ev Evidence) Verdict
	Issuer(ev Evidence) Verdict
}

// Evaluator hands out one pinned View per session.
type Evaluator interface {
	Snapshot(ctx context.Context) View
}

// NewView returns a View over the evaluation channels, reading the
// recognized-list channel from lister. A nil lister leaves the certificate
// channel on its own, which is what a wallet that recognizes no list runs.
func NewView(lister Lister) View {
	return channels{lister: lister}
}

// channels evaluates both channels and takes the stronger of the two. They are
// independent by design: a party Yivi certified stays high while the list is
// unreachable, and a party the list grants reaches medium without ever holding
// a certificate.
type channels struct {
	lister Lister
}

// Verifier implements [View].
func (v channels) Verifier(ev Evidence) Verdict { return v.evaluate(RoleVerifier, ev) }

// Issuer implements [View].
func (v channels) Issuer(ev Evidence) Verdict { return v.evaluate(RoleIssuer, ev) }

func (v channels) evaluate(role Role, ev Evidence) Verdict {
	verdict := Verdict{Level: clientmodels.TrustLevel_Low}

	// The certificate channel. A certificate here already validated against the
	// Yivi anchors, so it is Yivi vouching for the party. It draws no
	// distinction between the two roles: a certificate is issued for one role
	// and the gate already checked it was used in that role.
	if ev.Certificate != nil {
		verdict.Level = clientmodels.TrustLevel_High
	}

	// The recognized-list channel. The listing is carried whatever the rung
	// works out to, because what a list says a party is called outranks what the
	// party says about itself even when a certificate put it on a higher rung.
	if v.lister != nil {
		if listing := v.lister.Lookup(role, ev); listing != nil {
			verdict.Listing = listing
			if rank(clientmodels.TrustLevel_Medium) > rank(verdict.Level) {
				verdict.Level = clientmodels.TrustLevel_Medium
			}
		}
	}

	return verdict
}

// rank orders the rungs so the channels can be compared. Unevaluated is not a
// rung and ranks below every verdict.
func rank(level clientmodels.TrustLevel) int {
	switch level {
	case clientmodels.TrustLevel_High:
		return 3
	case clientmodels.TrustLevel_Medium:
		return 2
	case clientmodels.TrustLevel_Low:
		return 1
	default:
		return 0
	}
}
