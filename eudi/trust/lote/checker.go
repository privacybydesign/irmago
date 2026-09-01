package lote

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/sirupsen/logrus"
)

// Source is one recognized list the wallet consults: where to get it, what it
// must call itself, and what a grant on it is worth.
type Source struct {
	// Key is how the wallet files this source's document: a local identifier,
	// never published and never compared against anything in the document. Any
	// stable, unique, non-empty string does. It is deliberately not the list's
	// `SchemeName`: that is a public, format-prescribed field its operator may
	// reword, and tying storage to it would make a rename cost an app release.
	Key string

	// LoTEType is the `LoTEType` URI (clause 6.3.3) the document must declare.
	// It is what stops one recognized list's document — correctly signed, just
	// not this list — being served in another's place, which the shared anchor
	// pool cannot catch on its own. It names the *kind* of list, so staging and
	// production share it and it cannot tell those two apart; their separate
	// signing CAs do. Unset skips the check.
	LoTEType string

	URL string

	// Confers is the rung a granted entry on this list earns a party — a property
	// of the source, not the entry, because vouching is the operator's word.
	// Yivi's own LoTE confers high; any other list confers what it was compiled
	// in as. Unset lifts no rung, though the entry still carries its curated
	// display metadata.
	//
	// On a source that delivers anchors it is the ceiling instead: the most a CA
	// entry on the list may confer, whatever the entry says. Unset caps at medium.
	Confers clientmodels.TrustLevel

	// Delivers says what a document from this source may put into the wallet:
	// party listings (the zero value) or trust anchors. A source delivers one or
	// the other, never both — a party list whose services turn out to be CAs
	// installs nothing, and an anchor list's party services grant nobody — so a
	// document reaching the wrong source cannot do the other one's work.
	Delivers Delivery

	// SignerSKI pins the subject key identifier of the certificate the list must
	// be signed with, on top of the anchor set. The anchor set says which CA may
	// sign lists; this says which certificate under it signs this one. Required
	// on an anchor source: the party list's daily key must not be able to sign a
	// document the wallet installs anchors from. Empty pins nothing.
	SignerSKI []byte
}

// Delivery is what a Source's documents may deliver.
type Delivery int

const (
	// DeliversParties is a list of parties: entries the wallet matches sessions
	// against. The zero value, so an existing Source is one.
	DeliversParties Delivery = iota
	// DeliversAnchors is a list of CAs: entries the wallet installs as trust
	// anchors in the role's pool.
	DeliversAnchors
)

func (d Delivery) String() string {
	switch d {
	case DeliversParties:
		return "parties"
	case DeliversAnchors:
		return "anchors"
	}
	return fmt.Sprintf("Delivery(%d)", int(d))
}

// ValidateSources reports what is wrong with a source set before a Checker is
// built on it: an empty or duplicate Key (the storage key, and the map the held
// lists live in), an empty URL, an empty LoTEType (which would disable the type
// check that keeps two lists apart), or an anchor source without a signer pin.
func ValidateSources(sources []Source) error {
	var errs []error
	keys := map[string]bool{}
	for i, source := range sources {
		at := fmt.Sprintf("source %d (%q)", i, source.Key)
		switch {
		case source.Key == "":
			errs = append(errs, fmt.Errorf("source %d: Key is empty", i))
		case keys[source.Key]:
			errs = append(errs, fmt.Errorf("%s: Key is used by another source", at))
		}
		keys[source.Key] = true
		if source.URL == "" {
			errs = append(errs, fmt.Errorf("%s: URL is empty", at))
		}
		if source.LoTEType == "" {
			errs = append(errs, fmt.Errorf("%s: LoTEType is empty, which disables the check that keeps two lists apart", at))
		}
		if source.Delivers == DeliversAnchors && len(source.SignerSKI) == 0 {
			errs = append(errs, fmt.Errorf("%s: an anchor source must pin its signer (SignerSKI)", at))
		}
	}
	return errors.Join(errs...)
}

// Config is what a Checker needs. Only Sources and X509Context have no sensible
// default.
type Config struct {
	// A party granted on any source is granted.
	Sources []Source

	// The pinned anchors a list's signing chain must validate against.
	X509Context eudi_jwt.X509VerificationContext

	// Store persists the signed documents. Nil keeps them in memory only, so the
	// wallet re-fetches on every start.
	Store Store

	// HTTPClient is used for list downloads. Nil falls back to http.DefaultClient,
	// bounded by the package's own fetch timeout.
	HTTPClient *http.Client

	// Now supplies the clock the currency checks read. Nil falls back to time.Now.
	Now func() time.Time
}

// Checker holds the wallet's recognized lists and hands out snapshots of them.
// It never fetches on the evaluation path — [Checker.Snapshot] reads what it
// already holds and returns immediately, so a session is never slowed down or
// failed by the state of a trust list. Downloading is [Checker.Refresh]'s job.
//
// A Checker is safe for concurrent use.
type Checker struct {
	cfg Config

	// loadOnce defers reading the persisted lists to first use. The wallet builds
	// its trust models — the anchors a stored list is re-verified against — after
	// the services that use them, so a constructor-time load would find an empty
	// anchor set and throw every stored list away on every start.
	loadOnce sync.Once

	mu sync.RWMutex
	// held is the last list that verified, per source, current or not: an expired
	// list's sequence number is still the floor a replay has to clear, and
	// Snapshot is where currency is applied. The verified bytes are kept
	// alongside so a byte-identical re-issue needs no re-marshalling.
	held map[string]*verifiedList
}

// NewChecker builds a Checker. Persisted lists are read and re-verified against
// the anchors on first use; one that no longer verifies is dropped.
//
// Sources that fail [ValidateSources] are dropped with a warning rather than
// consulted half-configured: the checker is fail-soft, so a misconfigured source
// is absent evidence here, and client.New is where it is an error.
func NewChecker(cfg Config) *Checker {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Checker{
		cfg:  cfg,
		held: map[string]*verifiedList{},
	}
	if err := ValidateSources(cfg.Sources); err != nil {
		c.logger().Warnf("lote: dropping misconfigured sources: %v", err)
		valid := make([]Source, 0, len(cfg.Sources))
		for _, source := range cfg.Sources {
			if ValidateSources(append(slices.Clone(valid), source)) == nil {
				valid = append(valid, source)
			}
		}
		c.cfg.Sources = valid
	}
	return c
}

// logger is where the checker writes its fail-soft notes. eudi.Logger is nil
// until client.New assigns it, so a Checker built directly — by a test, or an
// embedder — would otherwise panic on the very paths meant never to fail.
func (c *Checker) logger() *logrus.Logger {
	if eudi.Logger != nil {
		return eudi.Logger
	}
	return discardingLogger()
}

var discardingLogger = sync.OnceValue(func() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
})

func (c *Checker) loadPersisted() {
	if c.cfg.Store == nil {
		return
	}
	c.loadOnce.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, source := range c.cfg.Sources {
			raw, ok := c.cfg.Store.Get(source.Key)
			if !ok {
				continue
			}
			verified, err := verify(raw, c.cfg.X509Context, source.SignerSKI)
			if err != nil {
				c.logger().Warnf("lote: stored list %q no longer verifies, dropping it: %v", source.Key, err)
				continue
			}
			if err := declaresType(source, verified.list); err != nil {
				c.logger().Warnf("lote: stored list under %q %v, dropping it", source.Key, err)
				continue
			}
			c.held[source.Key] = verified
		}
	})
}

// Refresh downloads every configured list, concurrently, and adopts the ones
// that hold up. Sources are independent: a failing one keeps whatever the wallet
// already held for it. The returned error names the sources that failed, for the
// caller's log; it is not a session-facing failure.
//
// changed reports whether any list's entries came back different, which is the
// only kind of refresh that can change a verdict the wallet already showed — a
// re-issue saying the same thing about the same parties never wakes the app.
func (c *Checker) Refresh(ctx context.Context) (bool, error) {
	c.loadPersisted()

	type outcome struct {
		changed bool
		err     error
	}
	outcomes := make([]outcome, len(c.cfg.Sources))

	var wg sync.WaitGroup
	for i, source := range c.cfg.Sources {
		wg.Go(func() {
			changed, err := c.refreshSource(ctx, source)
			outcomes[i] = outcome{changed: changed, err: err}
		})
	}
	wg.Wait()

	// Reported in configuration order, not completion order.
	changed := false
	var failures []error
	for i, source := range c.cfg.Sources {
		if err := outcomes[i].err; err != nil {
			c.logger().Warnf("lote: refreshing %q: %v", source.Key, err)
			failures = append(failures, fmt.Errorf("%s: %w", source.Key, err))
			continue
		}
		changed = changed || outcomes[i].changed
	}
	return changed, errors.Join(failures...)
}

// declaresType reports whether this document is the kind of list this source
// publishes. The document's own `SchemeName` is deliberately not checked: it is
// the operator's to reword, and a document claiming to be a list it is not can
// only reach here by being signed under an anchor the wallet already trusts.
func declaresType(source Source, list *List) error {
	if source.LoTEType != "" && list.SchemeInformation.LoTEType != source.LoTEType {
		return fmt.Errorf("declares LoTEType %q, expected %q",
			list.SchemeInformation.LoTEType, source.LoTEType)
	}
	return nil
}

// refreshSource adopts the fetched list if it holds up, reporting whether its
// entries differ from the ones the wallet held.
func (c *Checker) refreshSource(ctx context.Context, source Source) (bool, error) {
	raw, err := Fetch(ctx, c.cfg.HTTPClient, source.URL)
	if err != nil {
		return false, fmt.Errorf("fetch: %w", err)
	}

	verified, err := verify(raw, c.cfg.X509Context, source.SignerSKI)
	if err != nil {
		return false, err
	}

	if err := declaresType(source, verified.list); err != nil {
		return false, err
	}

	if !verified.current(c.cfg.Now()) {
		return false, fmt.Errorf("expired: next_update was %s", verified.list.SchemeInformation.NextUpdate.Format(time.RFC3339))
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	previous, held := c.held[source.Key]

	// A re-issue may repeat a sequence number but never go backwards: that is a
	// replay, which would silently un-list everyone added since.
	if held && verified.list.SchemeInformation.SequenceNumber < previous.list.SchemeInformation.SequenceNumber {
		return false, fmt.Errorf("sequence number regressed from %d to %d",
			previous.list.SchemeInformation.SequenceNumber, verified.list.SchemeInformation.SequenceNumber)
	}

	// Identical bytes are already held and persisted. Checked before the store
	// write, which is the expensive half.
	if held && bytes.Equal(previous.rawJws, verified.rawJws) {
		return false, nil
	}

	if c.cfg.Store != nil {
		if err := c.cfg.Store.Put(source.Key, verified.rawJws); err != nil {
			// The list is good; only persisting it failed. Use it for this run.
			c.logger().Warnf("lote: persisting list %q: %v", source.Key, err)
		}
	}
	c.held[source.Key] = verified

	// A first fetch is not a change: no verdict from this list was showing.
	if !held {
		return false, nil
	}
	// A held list past its next_update was already out of every snapshot, so a
	// re-issue lifts every party on it even when the entries are the same.
	return !previous.current(c.cfg.Now()) || entriesDiffer(previous, verified), nil
}

// entriesDiffer reports whether two issues of the same list say different things
// about the parties on it. The scheme information is not compared: a new sequence
// number and a later next_update are what every re-issue carries.
//
// Comparing marshalled entities also reports a mere reorder as a change. That is
// the cheap side of the trade — a spurious wake-up costs a redraw, while missing
// a real change leaves a delisted issuer showing a rung it no longer holds.
func entriesDiffer(previous, current *verifiedList) bool {
	previousEntities, err := json.Marshal(previous.list.Entities)
	if err != nil {
		return true
	}
	currentEntities, err := json.Marshal(current.list.Entities)
	if err != nil {
		return true
	}
	return !bytes.Equal(previousEntities, currentEntities)
}

// Snapshot pins the lists a single session evaluates against. It never blocks on
// the network and never fails: an absent, unreadable or expired list is simply not
// in it.
func (c *Checker) Snapshot() trust.ListSnapshot {
	c.loadPersisted()
	now := c.cfg.Now()

	c.mu.RLock()
	defer c.mu.RUnlock()

	pinned := make([]pinnedList, 0, len(c.cfg.Sources))
	for _, source := range c.cfg.Sources {
		// An anchor list grants no party, whatever it carries.
		if source.Delivers != DeliversParties {
			continue
		}
		held, ok := c.currentList(source, now)
		if !ok {
			continue
		}
		pinned = append(pinned, pinnedList{source: source, list: held.list})
	}
	return snapshot{lists: pinned}
}

// currentList is the held list for a source if there is one and it is current.
// Called with c.mu held.
func (c *Checker) currentList(source Source, now time.Time) (*verifiedList, bool) {
	held, ok := c.held[source.Key]
	if !ok {
		return nil, false
	}
	if !held.current(now) {
		c.logger().Infof("lote: list %q is past its next_update, ignoring it", source.Key)
		return nil, false
	}
	return held, true
}

// Anchor is one CA a recognized anchor list delivers: the certificate the wallet
// installs as a trust anchor in the role's pool, the level it confers, and where
// the CRLs it issues are published.
type Anchor struct {
	SourceKey   string
	Role        trust.Role
	Certificate *x509.Certificate
	// Confers is the entry's level capped by the source's ceiling.
	Confers               clientmodels.TrustLevel
	CRLDistributionPoints []string
}

// Anchors lists the CAs every current anchor-delivering list grants, in
// configuration order. Like Snapshot it reads what the checker holds and never
// fetches; an absent, expired or unverifiable list contributes nothing, and a
// withdrawn service, or one whose certificate does not parse, is skipped.
//
// A party-delivering list's CA services are not here: a source delivers one kind
// of thing, and installing an anchor is the more consequential kind.
func (c *Checker) Anchors() []Anchor {
	c.loadPersisted()
	now := c.cfg.Now()

	c.mu.RLock()
	defer c.mu.RUnlock()

	var anchors []Anchor
	for _, source := range c.cfg.Sources {
		if source.Delivers != DeliversAnchors {
			continue
		}
		held, ok := c.currentList(source, now)
		if !ok {
			continue
		}
		ceiling := source.Confers
		if ceiling == clientmodels.TrustLevel_Unevaluated {
			ceiling = clientmodels.TrustLevel_Medium
		}
		for i := range held.list.Entities {
			entity := &held.list.Entities[i]
			for j := range entity.Services {
				info := &entity.Services[j].Information
				role, ok := info.Type.AnchorRole()
				if !ok || !info.IsGranted() {
					continue
				}
				for _, listed := range info.DigitalIdentity.X509Certificates {
					cert, err := x509.ParseCertificate(listed.Val)
					if err != nil {
						c.logger().Warnf("lote: anchor list %q: certificate of %q does not parse, skipping it: %v",
							source.Key, entity.Information.Name.Translated()["en"], err)
						continue
					}
					anchors = append(anchors, Anchor{
						SourceKey:             source.Key,
						Role:                  role,
						Certificate:           cert,
						Confers:               capLevel(info.Confers(), ceiling),
						CRLDistributionPoints: info.CRLDistributionPoints(),
					})
				}
			}
		}
	}
	return anchors
}

// capLevel is level, unless it outranks ceiling.
func capLevel(level, ceiling clientmodels.TrustLevel) clientmodels.TrustLevel {
	if trust.Stronger(level, ceiling) {
		return ceiling
	}
	return level
}
