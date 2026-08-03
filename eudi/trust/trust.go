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

// Listing is a party's entry on a recognized trust list, produced by the
// recognized-list channel (the lote package). A Verdict carries a nil Listing
// when no list vouched for the party, which includes every verdict the wallet
// draws while it holds no usable list.
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

// Role is which of the two grants a party is being asked about. It exists for
// [ListSnapshot], where the role has to travel as data; callers of [View] name
// the role by picking a method instead.
type Role string

const (
	RoleIssuer   Role = "issuer"
	RoleVerifier Role = "verifier"
)

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

// ListSnapshot is the recognized-list channel, pinned to one state of the
// wallet's lists. It answers with the entry that grants the party in that role,
// or nil when no list grants it — including when there is no usable list at
// all, which is what makes an unreachable or expired list absent evidence
// rather than a failure.
//
// Implemented by the lote package; declared here so the evaluation seam does
// not depend on the list format.
type ListSnapshot interface {
	Lookup(role Role, ev Evidence) *Listing
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

// NewView combines the channels into the view a session evaluates against. A
// nil snapshot leaves only the certificate channel, which is what the wallet
// runs on before it has ever fetched a list.
func NewView(lists ListSnapshot) View {
	return layeredView{lists: lists}
}

// layeredView is the whole ladder: the certificate channel and the
// recognized-list channel, each asked independently, the party landing on
// whichever rung is higher. Independence is the point — a scheme-certified
// party stays high while the list is down, and a listed party stays medium
// while it holds no certificate.
type layeredView struct {
	lists ListSnapshot
}

// Verifier implements [View].
func (v layeredView) Verifier(ev Evidence) Verdict { return v.evaluate(RoleVerifier, ev) }

// Issuer implements [View].
func (v layeredView) Issuer(ev Evidence) Verdict { return v.evaluate(RoleIssuer, ev) }

func (v layeredView) evaluate(role Role, ev Evidence) Verdict {
	verdict := certificateVerdict(ev)
	if v.lists == nil {
		return verdict
	}
	listing := v.lists.Lookup(role, ev)
	if listing == nil {
		return verdict
	}
	verdict.Listing = listing
	// Being on a recognized list is medium. Yivi's own list can say more, but
	// that is the marking's job and it is not read here yet.
	if levelRank(clientmodels.TrustLevel_Medium) > levelRank(verdict.Level) {
		verdict.Level = clientmodels.TrustLevel_Medium
	}
	return verdict
}

// levelRank orders the rungs so channels can be combined by taking the
// strongest. Unevaluated ranks below every verdict: it is the absence of one.
func levelRank(l clientmodels.TrustLevel) int {
	switch l {
	case clientmodels.TrustLevel_Low:
		return 1
	case clientmodels.TrustLevel_Medium:
		return 2
	case clientmodels.TrustLevel_High:
		return 3
	default:
		return 0
	}
}
