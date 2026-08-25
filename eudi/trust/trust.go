// Package trust holds the vocabulary of the trust ladder: the evidence one
// party's identity check produced, and the verdict the wallet draws from it.
//
// The ladder has three rungs (clientmodels.TrustLevel) and answers only how
// strongly a party is vouched for, never whether it is who it claims to be —
// that is the identity gate, which runs first and fails the session outright
// (see [github.com/privacybydesign/irmago/eudi.PartyValidationFailed]).
//
// Evaluation is fail-soft by construction: no signature here returns an error,
// so no evaluation path can fail a session. An unavailable channel contributes
// no evidence and the party lands on a lower rung.
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
	// Certificate attests the party's key: the end-entity certificate an x5c
	// party presented, or the one a DID party's verification method carries
	// (RFC 7517 §4.7). Nil for a bare DID or issuer metadata alone.
	//
	// It is a claim, not a verdict: only a chain validating to an anchor confers
	// that anchor's level, and a leaf chaining to nothing lifts no rung while
	// still being matchable by the recognized-list channel.
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
	// Listing is the entry the verdict was granted on, or nil when no list vouched
	// for the party. It carries the curated display metadata, which outranks what
	// the party asserts about itself.
	Listing *Listing
	// CertificateLevel is the certificate channel's own contribution, reported
	// separately because Level alone cannot say whether a high rung came from an
	// anchor or from a listing. Unevaluated when no anchored certificate vouches
	// for the party. The identity gates do not read it — each establishes
	// attested-ness for itself, before a verdict exists.
	CertificateLevel clientmodels.TrustLevel
}

// CuratedLogoURI is the logo the granting listing names, or "" when no list
// vouched for the party or its entry carries none.
func (v Verdict) CuratedLogoURI() string {
	if v.Listing == nil {
		return ""
	}
	return v.Listing.LogoURI
}

// Listing is a party's entry on a recognized trust list, produced by the lote
// package. A Verdict carries nil when no list vouched for the party, which
// includes every verdict drawn while the wallet holds no usable list.
type Listing struct {
	// SourceKey is the local key of the source that granted this listing — the
	// wallet's own identifier for the list, not anything the document declares.
	// Carried for diagnostics; nothing app-facing reads it.
	SourceKey string

	Name    clientmodels.TranslatedString
	LogoURI string

	// Level is the rung this listing confers: the level the granting list's source
	// is configured with. Yivi's own LoTE confers high — being listed there is
	// being onboarded — and any other list confers what its source declares.
	Level clientmodels.TrustLevel
}

// Role is which of the two grants a party is being asked about. It exists for
// [ListSnapshot], where the role travels as data; callers of [View] pick a
// method instead.
type Role string

const (
	RoleIssuer   Role = "issuer"
	RoleVerifier Role = "verifier"
)

// View evaluates parties against one pinned state of the world. A session takes
// a View once, so a list refresh landing mid-session cannot change its verdicts.
// The role is a method rather than a parameter because issuing and verifying are
// separate grants.
type View interface {
	Verifier(ev Evidence) Verdict
	Issuer(ev Evidence) Verdict
}

// Evaluator hands out one pinned View per session. Snapshot takes no context:
// pinning reads state the wallet already holds, never fetches.
type Evaluator interface {
	Snapshot() View
}

// SnapshotOf pins the view to evaluate one pass against, tolerating a missing
// evaluator: a wallet component built without one ranks nobody rather than
// failing the read it was asked for.
func SnapshotOf(evaluator Evaluator) View {
	if evaluator == nil {
		return NewView(nil, nil, nil)
	}
	return evaluator.Snapshot()
}

// ListSnapshot is the recognized-list channel, pinned to one state of the
// wallet's lists. Nil when no list grants the party — including when there is no
// usable list at all, which is what makes an unreachable or expired list absent
// evidence rather than a failure.
//
// Implemented by the lote package; declared here so the evaluation seam does not
// depend on the list format.
type ListSnapshot interface {
	Lookup(role Role, ev Evidence) *Listing
}

// CertificateClassifier is the certificate channel's evidence source: the level
// conferred by the anchor a leaf's chain validates to right now, or unevaluated
// when it chains to nothing the wallet holds. It never errors — a chain that does
// not hold up is absent evidence.
//
// Implemented by the wallet's TrustModel, per anchor set, so the two roles
// consult separate classifiers.
type CertificateClassifier interface {
	Classify(leaf *x509.Certificate) clientmodels.TrustLevel
}

// NewView combines the channels into the view a session evaluates against. A nil
// snapshot leaves only the certificate channel, which is what the wallet runs on
// before it has ever fetched a list; a nil classifier leaves that role's
// certificate channel dark.
func NewView(lists ListSnapshot, issuerCerts, verifierCerts CertificateClassifier) View {
	return &layeredView{
		lists:         lists,
		issuerCerts:   issuerCerts,
		verifierCerts: verifierCerts,
		classified:    map[classifiedKey]clientmodels.TrustLevel{},
	}
}

// layeredView is the whole ladder: both channels asked independently, the party
// landing on whichever rung is higher. Independence is the point — a certified
// party stays high while the list is down, and a listed one keeps its rung while
// it holds no certificate.
type layeredView struct {
	lists         ListSnapshot
	issuerCerts   CertificateClassifier
	verifierCerts CertificateClassifier

	// classified memoizes the certificate channel's answers for the life of the
	// view, which is pinned to one state of the world and so must answer the same
	// twice anyway. One classification is a chain build plus a revocation scan,
	// and ranking a whole wallet asks about one issuer once per credential.
	mu         sync.Mutex
	classified map[classifiedKey]clientmodels.TrustLevel
}

// classifiedKey identifies one certificate asked about in one role. The roles
// consult separate anchor sets, so a level found for one says nothing about the
// other.
type classifiedKey struct {
	role Role
	leaf [sha256.Size]byte
}

func (v *layeredView) Verifier(ev Evidence) Verdict { return v.evaluate(RoleVerifier, ev) }
func (v *layeredView) Issuer(ev Evidence) Verdict   { return v.evaluate(RoleIssuer, ev) }

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

// classify is the certificate channel: the level the role's anchor set confers on
// the leaf, or unevaluated when nothing anchors it.
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

	// Held across the classification so concurrent askers wait for the first
	// answer rather than each building the chain.
	v.mu.Lock()
	defer v.mu.Unlock()
	if level, ok := v.classified[key]; ok {
		return level
	}
	level := classifier.Classify(leaf)
	v.classified[key] = level
	return level
}

// Stronger reports whether a outranks b on the ladder: how independent channels
// combine. Unevaluated ranks below every verdict, being the absence of one.
func Stronger(a, b clientmodels.TrustLevel) bool {
	return levelRank(a) > levelRank(b)
}

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
