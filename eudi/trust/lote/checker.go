package lote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/trust"
)

// Source is one recognized list the wallet consults: where to get it, what it
// must call itself, and what a grant on it is worth.
type Source struct {
	// ListId is the identifier the fetched document must declare in
	// `scheme_information.list_identifier`. Binding the two stops one
	// recognized list's document — correctly signed, just not this list — from
	// being served in another's place.
	ListId string

	// URL is where the signed list is published.
	URL string

	// Confers is the rung a granted entry on this list earns a party. It is a
	// property of the source rather than of the entry, because vouching is the
	// list operator's word and every entry carries the same amount of it:
	// Yivi's own LoTE confers high — being listed there is being onboarded,
	// Yivi cannot name a party on its list without vouching for it — and any
	// other recognized list confers what whoever compiled it in decided that
	// operator's word is worth.
	//
	// Unset confers nothing: a granted entry still carries its curated display
	// metadata, but lifts no rung.
	Confers clientmodels.TrustLevel
}

// Config is what a Checker needs. Only Sources and X509Context have no sensible
// default.
type Config struct {
	// Sources are the recognized lists, in no particular order — a party
	// granted on any of them is granted.
	Sources []Source

	// X509Context supplies the pinned anchors a list's signing chain must
	// validate against.
	X509Context eudi_jwt.X509VerificationContext

	// Store persists the signed documents. Nil keeps them in memory only, so
	// the wallet re-fetches on every start.
	Store Store

	// HTTPClient is used for list downloads. Nil falls back to
	// http.DefaultClient, bounded by FetchTimeoutDefault.
	HTTPClient *http.Client

	// Now supplies the clock the currency checks read. Nil falls back to
	// time.Now.
	Now func() time.Time
}

// Checker holds the wallet's recognized lists and hands out snapshots of them.
//
// It never fetches on the evaluation path: [Checker.Snapshot] reads whatever
// the checker currently holds and returns immediately, so a session is never
// slowed down, and never failed, by the state of a trust list. Downloading is
// [Checker.Refresh]'s job, driven by the app or by a background schedule.
//
// A Checker is safe for concurrent use.
type Checker struct {
	// cfg is the configuration as normalized by NewChecker, so the defaults are
	// applied in one place rather than re-derived per use.
	cfg Config

	// loadOnce defers reading the persisted lists to the first use rather than
	// doing it in the constructor. The wallet builds its trust models — the
	// anchors a stored list is re-verified against — after it builds the
	// services that use them, so a constructor-time load would find an empty
	// anchor set and throw every stored list away on every start.
	loadOnce sync.Once

	mu sync.RWMutex
	// held is the last list that verified, per source, whether or not it is
	// still current. An expired list is kept because its sequence number is
	// still the floor a replayed older list has to clear; Snapshot is where
	// currency is applied. The verified bytes are kept alongside the parsed
	// list so a re-issue that is byte-identical can be recognized without
	// re-marshalling anything.
	held map[string]*verifiedList
}

// NewChecker builds a Checker. The lists already persisted are read and
// re-verified against the anchors on first use; one that no longer verifies is
// dropped, exactly as if it had never been fetched.
func NewChecker(cfg Config) *Checker {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	return &Checker{
		cfg:  cfg,
		held: map[string]*verifiedList{},
	}
}

func (c *Checker) loadPersisted() {
	if c.cfg.Store == nil {
		return
	}
	c.loadOnce.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, source := range c.cfg.Sources {
			raw, ok := c.cfg.Store.Get(source.ListId)
			if !ok {
				continue
			}
			verified, err := verify(raw, c.cfg.X509Context)
			if err != nil {
				eudi.Logger.Warnf("lote: stored list %q no longer verifies, dropping it: %v", source.ListId, err)
				continue
			}
			if verified.list.SchemeInformation.ListIdentifier != source.ListId {
				eudi.Logger.Warnf("lote: stored list under %q declares %q, dropping it",
					source.ListId, verified.list.SchemeInformation.ListIdentifier)
				continue
			}
			c.held[source.ListId] = verified
		}
	})
}

// Refresh downloads every configured list and adopts the ones that hold up.
//
// Sources are independent: one list being unreachable or bad does not touch the
// others, and a source that fails keeps whatever the wallet already held for
// it. The returned error reports the sources that failed, for the caller's log;
// it is not a session-facing failure, and callers on a schedule are expected to
// log it and carry on.
//
// changed counts the lists whose *entries* came back different, which is the
// only kind of refresh that can change a verdict the wallet already showed. A
// re-issue that says the same thing about the same parties — a fresh
// next_update, a new sequence number, a new signature — counts zero, so
// re-confirmation never wakes the app.
// Sources are refreshed concurrently: they are independent downloads, so a slow
// or unreachable one must not add its timeout to every other source's wait.
func (c *Checker) Refresh(ctx context.Context) (int, error) {
	c.loadPersisted()

	type outcome struct {
		changed bool
		err     error
	}
	outcomes := make([]outcome, len(c.cfg.Sources))

	var wg sync.WaitGroup
	for i, source := range c.cfg.Sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			changed, err := c.refreshSource(ctx, source)
			outcomes[i] = outcome{changed: changed, err: err}
		}()
	}
	wg.Wait()

	// Reported in configuration order, so the log reads the same way whatever
	// order the downloads happened to finish in.
	changed := 0
	var failures []error
	for i, source := range c.cfg.Sources {
		if err := outcomes[i].err; err != nil {
			eudi.Logger.Warnf("lote: refreshing %q: %v", source.ListId, err)
			failures = append(failures, fmt.Errorf("%s: %w", source.ListId, err))
			continue
		}
		if outcomes[i].changed {
			changed++
		}
	}
	return changed, errors.Join(failures...)
}

// refreshSource fetches one source and adopts the list if it holds up,
// reporting whether the entries it carries differ from the ones the wallet held.
func (c *Checker) refreshSource(ctx context.Context, source Source) (bool, error) {
	raw, err := fetch(ctx, c.cfg.HTTPClient, source.URL)
	if err != nil {
		return false, fmt.Errorf("fetch: %w", err)
	}

	verified, err := verify(raw, c.cfg.X509Context)
	if err != nil {
		return false, err
	}

	// The document must be the list this source publishes, not another
	// correctly signed one.
	if got := verified.list.SchemeInformation.ListIdentifier; got != source.ListId {
		return false, fmt.Errorf("declares list identifier %q, expected %q", got, source.ListId)
	}

	if !verified.current(c.cfg.Now()) {
		return false, fmt.Errorf("expired: next_update was %s", verified.list.SchemeInformation.NextUpdate.Format(time.RFC3339))
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	previous, held := c.held[source.ListId]

	// A re-issue may repeat a sequence number (the same issue served twice) but
	// never go backwards: that is an older list being replayed, which would
	// silently un-list everyone added since.
	if held && verified.list.SchemeInformation.SequenceNumber < previous.list.SchemeInformation.SequenceNumber {
		return false, fmt.Errorf("sequence number regressed from %d to %d",
			previous.list.SchemeInformation.SequenceNumber, verified.list.SchemeInformation.SequenceNumber)
	}

	if c.cfg.Store != nil {
		if err := c.cfg.Store.Put(source.ListId, verified.rawJws); err != nil {
			// The list is good; only persisting it failed. Use it for this run
			// rather than throwing away a valid download over a storage problem.
			eudi.Logger.Warnf("lote: persisting list %q: %v", source.ListId, err)
		}
	}
	c.held[source.ListId] = verified

	// A first fetch is not a change: the wallet showed no verdict from this list
	// before, so there is nothing it has to go back on.
	if !held {
		return false, nil
	}
	return entriesDiffer(previous, verified), nil
}

// entriesDiffer reports whether two issues of the same list say different things
// about the parties on it. The scheme information is deliberately not compared:
// a new sequence number and a later next_update are what every re-issue carries,
// and they say nothing about anybody.
//
// The comparison is over the marshalled entities, so it also reports a change
// when the operator merely reorders them — a wake-up the wallet does not
// strictly need. That is the accepted side of the trade: list content changes
// are human acts, rare enough that a spurious one costs a redraw, while missing
// a real one leaves a delisted issuer showing a rung it no longer holds.
func entriesDiffer(previous, current *verifiedList) bool {
	// An operator re-serving the identical document is the common case, and
	// identical bytes cannot say anything different about anybody.
	if bytes.Equal(previous.rawJws, current.rawJws) {
		return false
	}
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

// Snapshot pins the lists a single session evaluates against. It never blocks
// on the network and never fails: lists that are absent, unreadable or past
// their NextUpdate are simply not in it, and a party they would have granted
// falls back to what the other channels say.
func (c *Checker) Snapshot() trust.ListSnapshot {
	c.loadPersisted()
	now := c.cfg.Now()

	c.mu.RLock()
	defer c.mu.RUnlock()

	pinned := make([]pinnedList, 0, len(c.cfg.Sources))
	for _, source := range c.cfg.Sources {
		held, ok := c.held[source.ListId]
		if !ok {
			continue
		}
		if !held.current(now) {
			eudi.Logger.Infof("lote: list %q is past its next_update, ignoring it", source.ListId)
			continue
		}
		pinned = append(pinned, pinnedList{source: source, list: held.list})
	}
	return snapshot{lists: pinned}
}
