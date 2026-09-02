// Package trust ranks the parties a wallet meets against the wallet config: the
// evidence one party's identity check produced goes in, a verdict on how
// strongly the party is vouched for comes out.
//
// The ladder has three rungs (clientmodels.TrustLevel) and answers only how
// strongly a party is vouched for, never whether it is who it claims to be. That
// is the identity gate, which runs first in the protocol code and fails the
// session outright (see eudi.PartyValidationFailed). A party that passes the
// gate but chains to no anchor and is listed nowhere is not a failure: it is
// absent evidence, and the party ranks low.
//
// Evaluation is fail-soft by construction: no function here returns an error
// for a party, so no evaluation can fail a session on its own. What a verdict
// means for a session — refuse, warn, proceed — is the policy's word, applied by
// CheckMinimum.
package trust

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
)

// Evidence is what the identity gate established about one party, in the terms
// the config's handles match on. Every field is optional: absent evidence is a
// handle type that has nothing to say about this party.
type Evidence struct {
	// Certificate is the end-entity certificate the party authenticated with: the
	// x5c leaf of a signed request or credential. Nil for a party that
	// authenticated by DID alone.
	//
	// It is a claim, not a verdict: only a chain validating to an anchored CA
	// confers that CA's level, and a leaf chaining to nothing lifts no rung while
	// still being matchable by an x509_cert handle.
	Certificate *x509.Certificate

	// DID is the DID the party authenticated with, when it did. Matched exactly
	// against did handles.
	DID string
}

// Verdict is one party's rung, plus what put it there.
type Verdict struct {
	// Level is the effective level: the strongest vouching found across the
	// matching entities, low when nothing matched.
	Level clientmodels.TrustLevel

	// Entity is the strongest matching entity, or nil when no entity vouches for
	// the party. It carries the curated name, logo and constraints, which outrank
	// what the party asserts about itself.
	Entity *walletconfig.TrustedEntity

	// Anchored reports whether the party's certificate validated to an anchor of
	// its role, which is what makes the certificate's own contents — a name, a
	// logo, an authorization — attested rather than self-asserted.
	Anchored bool

	// Chain is the certificate chain that validated, leaf first, when Anchored.
	Chain []*x509.Certificate
}

// IsVouchedFor reports whether somebody beyond the party itself vouches for it.
func (v Verdict) IsVouchedFor() bool {
	return v.Level.IsVouchedFor()
}

// IssuanceConstraint is the listed constraint on what the party may issue, or
// nil when the list places none. A list constraint replaces whatever the party's
// certificate says it may do; absence means the certificate's own authorization
// applies, and without one the party is unconstrained.
func (v Verdict) IssuanceConstraint() *walletconfig.IssuanceConstraint {
	if v.Entity == nil || v.Entity.Constraints == nil {
		return nil
	}
	return v.Entity.Constraints.Issuance
}

// DisclosureConstraint is the listed constraint on what the party may request,
// with the same precedence as IssuanceConstraint.
func (v Verdict) DisclosureConstraint() *walletconfig.DisclosureConstraint {
	if v.Entity == nil || v.Entity.Constraints == nil {
		return nil
	}
	return v.Entity.Constraints.Disclosure
}

// SessionType is what a policy minimum applies to.
type SessionType string

const (
	SessionIssuance   SessionType = "issuance"
	SessionDisclosure SessionType = "disclosure"
)

// ErrBelowMinimumTrustLevel marks a session refused because the party's level is
// below the policy's minimum for the session type. Wrapped around the details so
// the session error carries a code the app can switch on.
var ErrBelowMinimumTrustLevel = errors.New("trust level below the policy minimum")

// CheckMinimum applies the policy: nil when level reaches the minimum for the
// session type, an error wrapping ErrBelowMinimumTrustLevel otherwise. Whether
// to warn at a passing level short of high is the app's call, off the level.
func CheckMinimum(policy walletconfig.Policy, session SessionType, level clientmodels.TrustLevel) error {
	minimum := policy.MinimumTrustLevel.Issuance
	if session == SessionDisclosure {
		minimum = policy.MinimumTrustLevel.Disclosure
	}
	if Rank(level) < Rank(minimum) {
		return fmt.Errorf("%w: the party is %s, %s requires at least %s", ErrBelowMinimumTrustLevel, level, session, minimum)
	}
	return nil
}

// Stronger reports whether a outranks b on the ladder. Unevaluated ranks below
// every rung, being the absence of one.
func Stronger(a, b clientmodels.TrustLevel) bool {
	return Rank(a) > Rank(b)
}

// Rank is a level's position on the ladder: 0 for unevaluated, then 1 to 3.
func Rank(level clientmodels.TrustLevel) int {
	switch level {
	case clientmodels.TrustLevel_Low:
		return 1
	case clientmodels.TrustLevel_Medium:
		return 2
	case clientmodels.TrustLevel_High:
		return 3
	}
	return 0
}

// View evaluates parties against one pinned state of the world. A session takes
// a View once, so a config refresh landing mid-session cannot change its
// verdicts. Issuing and verifying are separate grants, hence two methods.
type View interface {
	Issuer(evidence Evidence) Verdict
	Verifier(evidence Evidence) Verdict
	// Policy is the policy in force for this view.
	Policy() walletconfig.Policy
	// Freshness is where the config behind this view stands.
	Freshness() walletconfig.Freshness
	// AppUpdateRequired reports whether the config's minimum app build is above
	// the build this wallet runs, in which case OpenID4VC sessions are refused.
	AppUpdateRequired() bool
}

// Evaluator hands out one pinned View per session. Snapshot takes no context:
// pinning reads state the wallet already holds, never fetches.
type Evaluator interface {
	Snapshot() View
}

// ChainValidator builds a chain from a leaf to one role's anchors. Implemented by
// the wallet's TrustModel, per role. An error means no chain validated — an
// unknown authority, an expired or revoked certificate — and the view treats
// every error alike: absent evidence.
type ChainValidator interface {
	ValidateChain(leaf *x509.Certificate) ([][]*x509.Certificate, error)

	// InstalledAnchor reports whether root is an anchor installed locally — the
	// developer, staging and test seam that stands in for a CA the wallet config
	// would otherwise list — rather than one the config delivered. No entity
	// vouches for what chains to such an anchor, so the ladder ranks it as under
	// Yivi's own CA: high. A released wallet installs nothing locally.
	InstalledAnchor(root *x509.Certificate) bool
}

// ErrAppUpdateRequired marks an OpenID4VC session refused because the wallet
// build is below the config's minimum.
var ErrAppUpdateRequired = errors.New("the wallet build is below the minimum this configuration requires")

// NewView pins a snapshot together with the chain validators of both roles.
// appBuild is the build this wallet runs; zero disables the minimum app build
// gate, for builds that do not know their number.
func NewView(snapshot walletconfig.Snapshot, issuerChains, verifierChains ChainValidator, appBuild int64) View {
	return &view{
		snapshot:       snapshot,
		issuerChains:   issuerChains,
		verifierChains: verifierChains,
		appBuild:       appBuild,
		chains:         map[chainKey]chainResult{},
	}
}

type view struct {
	snapshot       walletconfig.Snapshot
	issuerChains   ChainValidator
	verifierChains ChainValidator
	appBuild       int64

	// chains memoizes chain building per leaf and role for the life of the
	// view: ranking a whole wallet asks about one issuer once per credential.
	mu     sync.Mutex
	chains map[chainKey]chainResult
}

type chainKey struct {
	role walletconfig.Role
	leaf string
}

type chainResult struct {
	chains [][]*x509.Certificate
	ok     bool
}

func (v *view) Issuer(evidence Evidence) Verdict {
	return v.evaluate(walletconfig.RoleIssuer, evidence)
}
func (v *view) Verifier(evidence Evidence) Verdict {
	return v.evaluate(walletconfig.RoleVerifier, evidence)
}
func (v *view) Policy() walletconfig.Policy       { return v.snapshot.Policy() }
func (v *view) Freshness() walletconfig.Freshness { return v.snapshot.Freshness }

func (v *view) AppUpdateRequired() bool {
	return v.appBuild > 0 && v.snapshot.MinimumAppBuild() > v.appBuild
}

// evaluate is the whole ladder for one role. The x509_ca handles are matched
// through the role's chain validator; x509_cert and did handles by exact match.
// The party lands on the highest level any matching entity confers.
func (v *view) evaluate(role walletconfig.Role, evidence Evidence) Verdict {
	verdict := Verdict{Level: clientmodels.TrustLevel_Low}

	if evidence.Certificate != nil {
		if chains, ok := v.validate(role, evidence.Certificate); ok {
			verdict.Anchored = true
			verdict.Chain = chains[0]
		}
	}

	consider := func(entity *walletconfig.TrustedEntity, listedHandlesInForce bool) {
		if !entity.HasRole(role) || !matches(entity, evidence, verdict.Chain, listedHandlesInForce) {
			return
		}
		if verdict.Entity == nil || Stronger(entity.TrustLevel, verdict.Entity.TrustLevel) {
			verdict.Entity = entity
		}
	}

	// Built-in entities are compiled into the build and always in force.
	for i := range v.snapshot.Environment.BuiltinEntities {
		consider(&v.snapshot.Environment.BuiltinEntities[i], true)
	}
	if v.snapshot.Config != nil {
		// An expired config's individual listings and level elevations no longer
		// count; its CA anchors keep working, because a certificate does not
		// expire when a list does (the max(certificate, list) doctrine).
		listedHandlesInForce := v.snapshot.Freshness != walletconfig.Expired
		for i := range v.snapshot.Config.TrustedEntities {
			consider(&v.snapshot.Config.TrustedEntities[i], listedHandlesInForce)
		}
	}

	switch {
	case verdict.Entity != nil:
		verdict.Level = verdict.Entity.TrustLevel
	case verdict.Anchored && v.installedAnchor(role, verdict.Chain[len(verdict.Chain)-1]):
		verdict.Level = clientmodels.TrustLevel_High
	}
	return verdict
}

func (v *view) installedAnchor(role walletconfig.Role, root *x509.Certificate) bool {
	validator := v.issuerChains
	if role == walletconfig.RoleVerifier {
		validator = v.verifierChains
	}
	return validator != nil && validator.InstalledAnchor(root)
}

// validate builds the chain for a leaf once per view and role.
func (v *view) validate(role walletconfig.Role, leaf *x509.Certificate) ([][]*x509.Certificate, bool) {
	validator := v.issuerChains
	if role == walletconfig.RoleVerifier {
		validator = v.verifierChains
	}
	if validator == nil {
		return nil, false
	}

	key := chainKey{role: role, leaf: string(leaf.Raw)}
	v.mu.Lock()
	defer v.mu.Unlock()
	if result, ok := v.chains[key]; ok {
		return result.chains, result.ok
	}
	chains, err := validator.ValidateChain(leaf)
	result := chainResult{chains: chains, ok: err == nil && len(chains) > 0}
	v.chains[key] = result
	return result.chains, result.ok
}

// matches reports whether any handle of the entity recognizes the party. An
// x509_ca handle matches when the validated chain passes through its root and,
// when it lists intermediates, through one of them: two entities under one root
// are told apart by the CA each of them names. Listed handles (x509_cert, did)
// count only while listedHandlesInForce.
func matches(entity *walletconfig.TrustedEntity, evidence Evidence, chain []*x509.Certificate, listedHandlesInForce bool) bool {
	for i := range entity.Handles {
		handle := &entity.Handles[i]
		switch handle.Type {
		case walletconfig.HandleTypeX509CA:
			if chain != nil && chainMatchesCA(chain, handle) {
				return true
			}
		case walletconfig.HandleTypeX509Cert:
			if listedHandlesInForce && evidence.Certificate != nil && handle.Certificate != nil &&
				handle.Certificate.Certificate != nil && bytes.Equal(handle.Certificate.Raw, evidence.Certificate.Raw) {
				return true
			}
		case walletconfig.HandleTypeDID:
			if listedHandlesInForce && evidence.DID != "" && handle.DID == evidence.DID {
				return true
			}
		}
	}
	return false
}

func chainMatchesCA(chain []*x509.Certificate, handle *walletconfig.Handle) bool {
	if handle.RootCertificate == nil || handle.RootCertificate.Certificate == nil {
		return false
	}
	if !chainContains(chain, handle.RootCertificate.Certificate) {
		return false
	}
	if len(handle.Intermediates) == 0 {
		return true
	}
	return slices.ContainsFunc(handle.Intermediates, func(intermediate walletconfig.Certificate) bool {
		return intermediate.Certificate != nil && chainContains(chain, intermediate.Certificate)
	})
}

func chainContains(chain []*x509.Certificate, certificate *x509.Certificate) bool {
	return slices.ContainsFunc(chain, func(link *x509.Certificate) bool {
		return bytes.Equal(link.Raw, certificate.Raw)
	})
}
