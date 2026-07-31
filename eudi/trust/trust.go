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

// Listing is a party's entry on a recognized trust list. Nothing produces one
// yet: the recognized-list channel is a later slice, and until it lands every
// Verdict carries a nil Listing.
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

// CertificateView is the certificate channel on its own: a party that
// authenticated with a certificate validated against the Yivi anchors is
// vouched for by Yivi and reaches high; anything else reaches low. It draws no
// distinction between the two roles, because a certificate is issued for one
// role and the gate already checked it was used in that role.
type CertificateView struct{}

// Verifier implements [View].
func (CertificateView) Verifier(ev Evidence) Verdict { return certificateVerdict(ev) }

// Issuer implements [View].
func (CertificateView) Issuer(ev Evidence) Verdict { return certificateVerdict(ev) }

func certificateVerdict(ev Evidence) Verdict {
	if ev.Certificate != nil {
		return Verdict{Level: clientmodels.TrustLevel_High}
	}
	return Verdict{Level: clientmodels.TrustLevel_Low}
}
