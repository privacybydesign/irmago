package services

import (
	"context"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/internal/common"
	"gorm.io/datatypes"
)

// RevocationService is the single home for Token Status List revocation. It
// owns the status-list Checker and the credential store, and exposes the three
// ways the wallet consults revocation:
//
//   - IsRevoked: a cached (no-fetch) check for one instance, used by the
//     OpenID4VP disclosure planner;
//   - RefreshStatuses: the background sweep that re-fetches and writes back each
//     stored instance's LastKnownStatus, and keeps the status-list cache warm;
//   - BatchRevocation: per-batch flags derived from stored status, for the
//     credential list view.
//
// All three share one revocation policy (see statusRevoked): anything other
// than VALID counts as revoked (INVALID, SUSPENDED, application-specific),
// except UNKNOWN (no status information yet), which stays advisory not-revoked.
type RevocationService struct {
	checker *statuslist.Checker
	store   db.CredentialStore
}

// NewRevocationService returns a service backed by the given Token Status List
// Checker and credential store. A nil checker disables the cached-read and
// refresh paths (IsRevoked returns false, RefreshStatuses is a no-op); the
// stored-status path (BatchRevocation) still works.
func NewRevocationService(checker *statuslist.Checker, store db.CredentialStore) *RevocationService {
	return &RevocationService{checker: checker, store: store}
}

// statusRevoked is the one revocation policy shared by every path: a credential
// is usable only when it reads VALID. INVALID, SUSPENDED, and any
// application-specific status all count as revoked (fail-closed on anything the
// issuer flags). UNKNOWN is the sole exception — it means "no status
// information" (cold cache / not yet checked), not a bad status, so it stays
// advisory not-revoked (see IsRevoked and the cold-cache behaviour).
// TODO: the client model has no separate suspended state, so suspension is
// surfaced as "revoked" for now — add a distinct suspended state (clientmodels
// + frontend) to show it as temporary rather than permanent.
func statusRevoked(s statuslist.Status) bool {
	return s != statuslist.StatusValid && s != statuslist.StatusUnknown
}

// IsRevoked reports whether the instance's credential reads INVALID according
// to the locally cached Token Status List — no network fetch. An instance
// without a status_list reference is never revoked. A missing or
// undeterminable cached status reads as NOT revoked: the flag is advisory, the
// cache is kept warm by RefreshStatuses, and the verifier's own status check is
// the backstop.
//
// The check never blocks disclosure — revocation is surfaced as a flag for the
// frontend, with the verifier as the backstop.
func (s *RevocationService) IsRevoked(instance *models.IssuedCredentialInstance) bool {
	if s.checker == nil || instance.StatusListURI == nil || instance.StatusListIdx == nil {
		return false
	}
	ref := statuslist.Reference{URI: *instance.StatusListURI, Index: *instance.StatusListIdx}
	status, err := s.checker.CheckCached(ref)
	if err != nil {
		eudi.Logger.Warnf("revocation: cached status read for instance %s: %v", instance.ID, err)
		return false // advisory: undeterminable status -> not flagged
	}
	return statusRevoked(status)
}

// RefreshStatuses re-fetches Token Status Lists and updates stored statuses,
// checking one representative instance per batch rather than every copy. A
// batch's instances are the same logical credential and are revoked together
// (draft-ietf-oauth-status-list §13.2), so one entry's bit determines the whole
// batch's status; re-checking every copy would be redundant work.
//
// Representatives are grouped by status list URI so a list shared across many
// batches is fetched once.
//
// Fail-soft: per-URI and per-instance errors are logged and skipped, leaving
// the previous LastKnownStatus in place. A nil checker makes this a no-op.
func (s *RevocationService) RefreshStatuses(ctx context.Context) error {
	if s.checker == nil {
		return nil
	}
	instances, err := s.store.ListInstancesWithStatusReference()
	if err != nil {
		return fmt.Errorf("load instances: %w", err)
	}

	// Keep one representative instance per batch. Any copy gives the same
	// answer under the whole-batch-revoked assumption, so the first seen wins.
	seenBatch := make(map[datatypes.UUID]struct{}, len(instances))
	representatives := make([]db.CredentialStatusInstance, 0, len(instances))
	for _, inst := range instances {
		if _, ok := seenBatch[inst.BatchID]; ok {
			continue
		}
		seenBatch[inst.BatchID] = struct{}{}
		representatives = append(representatives, inst)
	}

	groups := map[string][]db.CredentialStatusInstance{}
	for _, inst := range representatives {
		groups[inst.StatusListURI] = append(groups[inst.StatusListURI], inst)
	}

	for uri, group := range groups {
		// One Refresh per URI populates the cache; the per-idx Check calls
		// below then read from the warm cache (no extra HTTP traffic).
		if _, err := s.checker.Refresh(ctx, statuslist.Reference{URI: uri}); err != nil {
			eudi.Logger.Warnf("status refresh: refresh %s failed: %v", common.SanitizeForLog(uri), err)
			continue
		}
		now := time.Now()
		for _, inst := range group {
			st, err := s.checker.Check(ctx, statuslist.Reference{URI: uri, Index: inst.StatusListIdx})
			if err != nil {
				eudi.Logger.Warnf("status refresh: check idx %d on %s failed: %v", inst.StatusListIdx, common.SanitizeForLog(uri), err)
				continue
			}
			if err := s.store.UpdateInstanceStatus(inst.InstanceID, uint8(st), now); err != nil {
				eudi.Logger.Warnf("status refresh: writeback failed for instance %s: %v", inst.InstanceID, err)
			}
		}
	}
	return nil
}

// BatchRevocation returns, keyed by batch hash, which batches support revocation
// (carry any status reference) and which are currently revoked, derived from the
// stored LastKnownStatus that RefreshStatuses maintains. A batch's instances are
// the same credential and are revoked together, so a batch is revoked as soon as
// any status-referenced instance reads a non-VALID status (see statusRevoked),
// and supports revocation if it carries any status reference at all. A lifted
// suspension is reflected on the next RefreshStatuses sweep.
func (s *RevocationService) BatchRevocation() (revoked, revocable map[string]bool, err error) {
	statuses, err := s.store.ListStatusReferencedInstanceStatuses()
	if err != nil {
		return nil, nil, err
	}
	revoked = map[string]bool{}
	revocable = map[string]bool{}
	for _, st := range statuses {
		revocable[st.Hash] = true
		if statusRevoked(statuslist.Status(st.LastKnownStatus)) {
			revoked[st.Hash] = true
		}
	}
	return revoked, revocable, nil
}
