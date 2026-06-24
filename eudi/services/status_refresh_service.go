package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/storage/db"
)

// StatusRefreshService keeps the LastKnownStatus column on every
// stored IssuedCredentialInstance up to date by periodically (or
// on-demand) re-fetching the referenced Status List Tokens.
//
// Failures during a sweep are logged and swallowed — the previous
// LastKnownStatus persists until the next successful refresh.
type StatusRefreshService interface {
	// RefreshAll iterates over every instance with a status_list
	// reference, groups by URI to coalesce HTTP traffic, calls
	// Checker.Refresh once per URI, and writes back the per-instance
	// status into the DB. Returns the first irrecoverable error;
	// per-URI fetch errors are logged but don't abort the sweep.
	RefreshAll(ctx context.Context) error

	// StartTicker spawns a goroutine that calls RefreshAll on the
	// given interval. The returned function stops the ticker and
	// returns after the in-flight RefreshAll (if any) completes.
	// interval <= 0 returns a no-op stop function.
	StartTicker(ctx context.Context, interval time.Duration) (stop func())
}

type statusRefreshService struct {
	store   db.CredentialStore
	checker *statuslist.Checker
}

func NewStatusRefreshService(store db.CredentialStore, checker *statuslist.Checker) StatusRefreshService {
	return &statusRefreshService{store: store, checker: checker}
}

func (s *statusRefreshService) RefreshAll(ctx context.Context) error {
	if s.checker == nil {
		return nil
	}
	instances, err := s.store.ListInstancesWithStatusReference()
	if err != nil {
		return fmt.Errorf("load instances: %w", err)
	}
	if len(instances) == 0 {
		return nil
	}

	// Group by (URI, ExpectedIssuer) so a single status list URI
	// shared across many credentials only fetches once. The
	// expected-issuer is the credential's issuer URL — kept inside
	// the key so a malicious cross-issuer URI re-use can't borrow
	// another issuer's cache slot.
	type key struct{ uri, iss string }
	groups := map[key][]db.CredentialStatusInstance{}
	for _, inst := range instances {
		k := key{uri: inst.StatusListURI, iss: inst.IssuerURL}
		groups[k] = append(groups[k], inst)
	}

	for k, group := range groups {
		// Each group hits Refresh once; the Checker handles the
		// fetch + verify + decode and caches the result. We then
		// look up each idx individually via Check, which now reads
		// from the warm cache (no extra HTTP traffic).
		if _, err := s.checker.Refresh(ctx, statuslist.Reference{URI: k.uri}, k.iss); err != nil {
			eudi.Logger.Warnf("status refresh: refresh %s failed: %v", k.uri, err)
			continue
		}
		now := time.Now()
		for _, inst := range group {
			st, err := s.checker.Check(ctx, statuslist.Reference{URI: k.uri, Index: inst.StatusListIdx}, k.iss)
			if err != nil {
				eudi.Logger.Warnf("status refresh: check idx %d on %s failed: %v", inst.StatusListIdx, k.uri, err)
				continue
			}
			if err := s.store.UpdateInstanceStatus(inst.InstanceID, uint8(st), now); err != nil {
				eudi.Logger.Warnf("status refresh: writeback failed for instance %s: %v", inst.InstanceID, err)
			}
		}
	}
	return nil
}

func (s *statusRefreshService) StartTicker(ctx context.Context, interval time.Duration) func() {
	if interval <= 0 {
		return func() {}
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-t.C:
				if err := s.RefreshAll(ctx); err != nil {
					eudi.Logger.Warnf("status refresh tick: %v", err)
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(stopCh) })
		<-doneCh
	}
}
