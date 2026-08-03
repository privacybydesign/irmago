package lote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/internal/common"
	"golang.org/x/sync/singleflight"
)

// Checker is the recognized-list channel: it keeps the wallet's copy of every
// recognized list current, and hands out the snapshots sessions evaluate
// against.
//
// A Checker is safe for concurrent use.
type Checker struct {
	lists []RecognizedList
	store Store

	// httpClient fetches the lists. Nil means the wallet's shared client.
	httpClient *http.Client
	// nowFn is the clock the validity window is read against.
	nowFn func() time.Time

	// sf collapses the concurrent fetches of two sessions starting at once.
	sf singleflight.Group

	// mu guards nextFetch, read and written from every session goroutine.
	mu sync.Mutex
	// nextFetch is when a list may be fetched again, per list identifier. It
	// bounds how often a wallet whose list endpoint is down pays the fetch
	// timeout: once per fetchBackoff, not once per session.
	nextFetch map[string]time.Time
}

// NewChecker returns a Checker over the given recognized lists. An empty set is
// the dark case: every snapshot it hands out is empty, so the channel
// contributes nothing and parties are ranked by the other channels alone.
func NewChecker(lists []RecognizedList, store Store) *Checker {
	if store == nil {
		store = NewInMemoryStore()
	}
	return &Checker{
		lists:     lists,
		store:     store,
		nowFn:     time.Now,
		nextFetch: map[string]time.Time{},
	}
}

// Snapshot pins the list state a single session evaluates against: it resolves
// every recognized list once, here, so a refresh landing halfway through cannot
// change what that session decided about a party it already ranked.
//
// Resolving a list can mean fetching it — the wallet has no copy yet, or the
// copy it has is past its NextUpdate. That fetch is bounded and fail-soft: a
// list that does not resolve is left out of the snapshot, and the parties it
// would have vouched for are ranked without it.
func (c *Checker) Snapshot(ctx context.Context) *Snapshot {
	snapshot := &Snapshot{}
	for _, list := range c.lists {
		content := c.resolve(ctx, list)
		if content == nil {
			continue
		}
		snapshot.entries = append(snapshot.entries, flatten(list.Id, content)...)
	}
	return snapshot
}

// resolve returns the list's current content, or nil when the wallet has none
// it may believe.
func (c *Checker) resolve(ctx context.Context, list RecognizedList) *List {
	if stored := c.load(list); stored != nil {
		return stored
	}
	if !c.mayFetch(list.Id) {
		return nil
	}
	return c.fetch(ctx, list)
}

// load returns the stored copy of the list when it still holds up: its
// signature against the anchors as they are now, its identifier against the one
// the wallet recognizes it under, and its NextUpdate against the clock.
func (c *Checker) load(list RecognizedList) *List {
	stored, err := c.store.Get(list.Id)
	if err != nil {
		c.logf("reading stored trust list %q failed: %v", list.Id, err)
		return nil
	}
	if stored == nil {
		return nil
	}
	content, err := c.validate(stored.Raw, list)
	if err != nil {
		// The stored copy is no longer believable — the anchors moved, or it
		// simply expired. Left in place: the next fetch overwrites it, and
		// until then it is not consulted.
		c.logf("stored trust list %q is not usable: %v", list.Id, err)
		return nil
	}
	return content
}

// fetch downloads the list, checks it, and persists it when it is both
// believable and not a rollback of the copy already stored. Every failure
// returns nil: an unreachable or rejected list is absent evidence.
func (c *Checker) fetch(ctx context.Context, list RecognizedList) *List {
	// Two sessions starting at once fetch once.
	result, err, _ := c.sf.Do(list.Id, func() (any, error) {
		raw, err := c.download(ctx, list.URL)
		if err != nil {
			return nil, err
		}
		content, err := c.validate(raw, list)
		if err != nil {
			return nil, err
		}
		stored, err := c.store.Get(list.Id)
		if err != nil {
			return nil, fmt.Errorf("reading the stored copy failed: %v", err)
		}
		if stored != nil && content.SchemeInformation.SequenceNumber < stored.SequenceNumber {
			return nil, fmt.Errorf(
				"sequence number regressed from %d to %d",
				stored.SequenceNumber, content.SchemeInformation.SequenceNumber,
			)
		}
		if err := c.store.Put(list.Id, &StoredList{
			Raw:            raw,
			SequenceNumber: content.SchemeInformation.SequenceNumber,
			NextUpdate:     content.SchemeInformation.NextUpdate,
		}); err != nil {
			// The list is already verified, so the session gets to use it; only
			// the next process start pays for the write having failed.
			c.logf("persisting trust list %q failed, proceeding: %v", list.Id, err)
		}
		return content, nil
	})
	if err != nil {
		c.logf("trust list %q is unavailable, parties will be ranked without it: %v", list.Id, err)
		return nil
	}
	return result.(*List)
}

// validate is everything that has to hold for a copy of a list to count: the
// signature under the list's own anchors, the identifier binding it to the list
// the wallet recognizes, and the validity window.
func (c *Checker) validate(raw []byte, list RecognizedList) (*List, error) {
	content, err := verifyList(raw, list.Anchors)
	if err != nil {
		return nil, err
	}
	if content.SchemeInformation.ListIdentifier != list.Id {
		return nil, fmt.Errorf(
			"list identifier %q does not match the recognized list %q",
			content.SchemeInformation.ListIdentifier, list.Id,
		)
	}
	if now := c.nowFn(); !now.Before(content.SchemeInformation.NextUpdate) {
		return nil, fmt.Errorf("list expired at %s", content.SchemeInformation.NextUpdate)
	}
	return content, nil
}

// download GETs the signed list, bounded in both time and size.
func (c *Checker) download(ctx context.Context, url string) ([]byte, error) {
	client := c.httpClient
	if client == nil {
		client = common.HTTPClient
	}

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("endpoint returned %s", response.Status)
	}

	// The signature is what decides whether these bytes are a trust list, so
	// the response's content type is not checked: it would only add a failure
	// mode that a misconfigured proxy could trip without changing what the
	// wallet believes.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read the response: %v", err)
	}
	if int64(len(body)) > maxBodyBytes {
		return nil, fmt.Errorf("response exceeds the %d byte cap", maxBodyBytes)
	}
	return body, nil
}

// mayFetch reports whether the list's backoff has run out, and starts a new one
// when it has. Called once per attempt, so a failing endpoint is retried on a
// timer rather than on every session.
func (c *Checker) mayFetch(listId string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowFn()
	if next, ok := c.nextFetch[listId]; ok && now.Before(next) {
		return false
	}
	c.nextFetch[listId] = now.Add(fetchBackoff)
	return true
}

func (c *Checker) logf(message string, args ...any) {
	// Nil when the package is used without irma, as the unit tests do.
	if common.Logger != nil {
		common.Logger.Warnf("lote: "+message, args...)
	}
}

// ========================================================================
// Snapshot
// ========================================================================

// Snapshot is one pinned state of every recognized list, as the entries a party
// can be matched against. It implements [trust.Lister].
//
// A Snapshot is immutable once handed out, which is what makes a session's
// verdicts stable for its whole duration.
type Snapshot struct {
	entries []entry
}

// entry is one granted, role-typed grant, flattened out of the provider it
// belongs to so that matching does not have to walk the list structure.
type entry struct {
	listId                 string
	role                   trust.Role
	name                   clientmodels.TranslatedString
	logoURI                string
	onboardedByYivi        bool
	organizationIdentifier string
	identities             []DigitalIdentity
}

// flatten turns a list's providers into the entries that vouch for something:
// services of a role the wallet asks about, whose grant is in force. Anything
// else — a withdrawn grant, a service type from a profile this wallet does not
// implement — is dropped here, so a lookup can never match it.
func flatten(listId string, list *List) []entry {
	var entries []entry
	for _, provider := range list.Providers {
		for _, service := range provider.Services {
			if service.Status != StatusGranted {
				continue
			}
			var role trust.Role
			switch service.Type {
			case ServiceTypeIssuer:
				role = trust.RoleIssuer
			case ServiceTypeVerifier:
				role = trust.RoleVerifier
			default:
				continue
			}
			name := service.Name
			if len(name) == 0 {
				name = provider.Name
			}
			entries = append(entries, entry{
				listId:                 listId,
				role:                   role,
				name:                   name,
				logoURI:                service.LogoURI,
				onboardedByYivi:        slices.Contains(service.AdditionalInformation, QualifierOnboardedByYivi),
				organizationIdentifier: provider.OrganizationIdentifier,
				identities:             service.Identities,
			})
		}
	}
	return entries
}

// Lookup implements [trust.Lister]: it returns the entry that vouches for this
// party in this role, or nil when no recognized list does.
func (s *Snapshot) Lookup(role trust.Role, evidence trust.Evidence) *trust.Listing {
	for _, entry := range s.entries {
		if entry.role == role && entry.matches(evidence) {
			return &trust.Listing{
				ListId:          entry.listId,
				Name:            entry.name,
				LogoURI:         entry.logoURI,
				OnboardedByYivi: entry.onboardedByYivi,
			}
		}
	}
	return nil
}

// matches reports whether this entry is about the party the evidence describes.
// Any one key matching is enough — an entry lists the several ways one party
// authenticates, not several conditions it has to meet.
func (e entry) matches(evidence trust.Evidence) bool {
	if certificate := evidence.Certificate; certificate != nil {
		for _, identity := range e.identities {
			if der := identity.certificateDer(); der != nil && bytes.Equal(der, certificate.Raw) {
				return true
			}
			if ski := identity.ski(); ski != nil && len(certificate.SubjectKeyId) > 0 &&
				bytes.Equal(ski, certificate.SubjectKeyId) {
				return true
			}
		}
		if e.organizationIdentifier != "" &&
			e.organizationIdentifier == organizationIdentifier(certificate) {
			return true
		}
	}

	// Identifiers outside X.509 match by value, in whichever space the entry
	// declares them to be in; see the OtherIdType constants.
	for _, identity := range e.identities {
		if identity.OtherId == nil || identity.OtherId.Value == "" {
			continue
		}
		if slices.Contains(evidence.Identifiers, identity.OtherId.Value) {
			return true
		}
	}
	return false
}
