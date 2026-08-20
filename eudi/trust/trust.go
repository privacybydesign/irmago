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
	"crypto/sha256"
	"crypto/x509"
	"sync"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// Evidence is what the identity gate produced about one party, in the terms the
// evaluation channels key on. Every field is optional: absent evidence is
// simply a channel that has nothing to say about this party.
type Evidence struct {
	// Certificate is the certificate that attests the party's key: the
	// end-entity certificate an x5c party presented, or the certificate a DID
	// party's verification method carries over its key (RFC 7517 §4.7). Nil
	// when the party carries none — a bare DID, or issuer metadata alone. How
	// the party authenticated (a certificate, or a DID) is not the question
	// here; whether a certificate vouches for its key is.
	//
	// A certificate here is a claim, not a verdict: the certificate channel
	// classifies it against the wallet's anchors at evaluation time, and only
	// a chain that validates to an anchor confers that anchor's level. A leaf
	// that chains to nothing is evidentially a self-asserted key — it lifts no
	// rung, and the recognized-list channel can still match the party on it.
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
	// CertificateLevel is the certificate channel's own contribution: the
	// level conferred by the anchor the party's chain validated to, or
	// unevaluated when no anchored certificate vouches for the party.
	//
	// It is reported separately from Level so the two channels can be told
	// apart — Level alone cannot say whether a high rung came from an anchor or
	// from a listing. Note that the protocol paths do not read it to decide
	// attested-ness: each identity gate establishes that for itself, because it
	// needs the answer before a verdict exists (an unanchored certificate's
	// authorization is not worth enforcing, which is a gate decision).
	CertificateLevel clientmodels.TrustLevel
}

// CuratedLogoURI is the logo the granting listing names, or "" when no list
// vouched for the party or its entry carries none. It exists so that every
// composition path reaches for the curated logo the same way, rather than each
// one guarding on Listing before dereferencing it.
func (v Verdict) CuratedLogoURI() string {
	if v.Listing == nil {
		return ""
	}
	return v.Listing.LogoURI
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
	// Level is the rung this listing confers: the level the granting list's
	// source is configured with. Yivi's own LoTE confers high — being listed
	// there is being onboarded, so Yivi cannot name a party on its list
	// without vouching for it — and any other recognized list confers what
	// its source declares.
	Level clientmodels.TrustLevel
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
//
// Snapshot takes no context: pinning is a read of state the wallet already
// holds, never a fetch, so there is nothing for a cancellation to cut short.
type Evaluator interface {
	Snapshot() View
}

// SnapshotOf pins the view to evaluate one pass against, tolerating the absence
// of an evaluator: a wallet component built without one ranks nobody rather than
// failing the read it was asked for. It exists so that fallback is stated once,
// here, instead of every caller spelling out what a viewless wallet does.
func SnapshotOf(evaluator Evaluator) View {
	if evaluator == nil {
		// No channels at all: every party ranks low, because nothing is
		// consulted that could vouch for one.
		return NewView(nil, nil, nil)
	}
	return evaluator.Snapshot()
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

// CertificateClassifier is the certificate channel's evidence source: it
// reports the level conferred by the anchor a leaf certificate's chain
// validates to right now, or unevaluated when the leaf does not chain to any
// anchor the wallet holds — a broken chain, a revoked certificate, an unknown
// root. Classification never errors: a chain that does not hold up is absent
// evidence, and the party lands where the other channels put it.
//
// Implemented by the wallet's TrustModel, which holds the anchor pools and the
// level each anchored root confers: Yivi's own roots confer high, an anchored
// third-party CA confers medium (or high, once promoted under contract).
// Classification is per anchor set, so trust as an issuer and trust as a
// verifier each consult their own classifier.
type CertificateClassifier interface {
	Classify(leaf *x509.Certificate) clientmodels.TrustLevel
}

// NewView combines the channels into the view a session evaluates against. A
// nil snapshot leaves only the certificate channel, which is what the wallet
// runs on before it has ever fetched a list; a nil classifier leaves that
// role's certificate channel dark, which only a wallet without trust models
// (in practice: a test) does.
func NewView(lists ListSnapshot, issuerCerts, verifierCerts CertificateClassifier) View {
	return &layeredView{
		lists:         lists,
		issuerCerts:   issuerCerts,
		verifierCerts: verifierCerts,
		classified:    map[classifiedKey]clientmodels.TrustLevel{},
	}
}

// layeredView is the whole ladder: the certificate channel and the
// recognized-list channel, each asked independently, the party landing on
// whichever rung is higher. Independence is the point — a Yivi-certified
// party stays high while the list is down, and a listed party keeps its
// listing's rung while it holds no certificate.
type layeredView struct {
	lists         ListSnapshot
	issuerCerts   CertificateClassifier
	verifierCerts CertificateClassifier

	// classified memoizes the certificate channel's answers for the life of the
	// view. A view is pinned to one state of the world, so asking about the same
	// certificate twice must give the same answer twice — which makes remembering
	// it a saving with no semantics of its own. The saving is the point: one
	// classification is a chain build plus a revocation scan, and the paths that
	// rank a whole wallet ask about one issuer's certificate once per credential.
	mu         sync.Mutex
	classified map[classifiedKey]clientmodels.TrustLevel
}

// classifiedKey identifies one certificate asked about in one role. The roles are
// separate grants consulting separate anchor sets, so a level found for one says
// nothing about the other.
type classifiedKey struct {
	role Role
	leaf [sha256.Size]byte
}

// Verifier implements [View].
func (v *layeredView) Verifier(ev Evidence) Verdict { return v.evaluate(RoleVerifier, ev) }

// Issuer implements [View].
func (v *layeredView) Issuer(ev Evidence) Verdict { return v.evaluate(RoleIssuer, ev) }

func (v *layeredView) evaluate(role Role, ev Evidence) Verdict {
	verdict := Verdict{
		Level:            clientmodels.TrustLevel_Low,
		CertificateLevel: v.classify(role, ev.Certificate),
	}
	if Stronger(verdict.CertificateLevel, verdict.Level) {
		verdict.Level = verdict.CertificateLevel
	}
	if v.lists == nil {
		return verdict
	}
	listing := v.lists.Lookup(role, ev)
	if listing == nil {
		return verdict
	}
	verdict.Listing = listing
	if Stronger(listing.Level, verdict.Level) {
		verdict.Level = listing.Level
	}
	return verdict
}

// classify is the certificate channel: the level the role's anchor set confers
// on the party's leaf, or unevaluated when the party presented no certificate,
// the role has no classifier, or the chain does not hold up.
func (v *layeredView) classify(role Role, leaf *x509.Certificate) clientmodels.TrustLevel {
	if leaf == nil {
		return clientmodels.TrustLevel_Unevaluated
	}
	classifier := v.issuerCerts
	if role == RoleVerifier {
		classifier = v.verifierCerts
	}
	if classifier == nil {
		return clientmodels.TrustLevel_Unevaluated
	}

	key := classifiedKey{role: role, leaf: sha256.Sum256(leaf.Raw)}

	// Held across the classification so concurrent askers about one certificate
	// wait for the first answer rather than each building the chain themselves.
	v.mu.Lock()
	defer v.mu.Unlock()
	if level, ok := v.classified[key]; ok {
		return level
	}
	level := classifier.Classify(leaf)
	v.classified[key] = level
	return level
}

// Stronger reports whether a outranks b on the ladder. It is how independent
// channels combine — the party lands on the strongest rung any channel earns
// it — and unevaluated ranks below every verdict: it is the absence of one.
func Stronger(a, b clientmodels.TrustLevel) bool {
	return levelRank(a) > levelRank(b)
}

// levelRank orders the rungs so channels can be combined by taking the
// strongest.
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
