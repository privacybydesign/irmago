package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/bitstringstatus"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/internal/common"
	"gorm.io/datatypes"
)

// RevocationService is the single home for credential revocation across every
// credential format. It owns the status-list checkers and one status store per
// format. Every format works the same way: RefreshStatuses checks each stored
// instance and records its batch's status on it, and everything else reads only
// that stored status:
//
//   - IsStoredStatusRevoked: the flag for one instance, used by the OpenID4VP
//     disclosure planners;
//   - BatchRevocation: per-batch flags, for the credential list view.
//
// Both share one revocation policy (see statusRevoked): anything other than
// VALID counts as revoked (INVALID, SUSPENDED, application-specific), except
// UNKNOWN (no status information yet), which stays advisory not-revoked.
type RevocationService struct {
	checker *statuslist.Checker
	stores  []db.CredentialStatusStore

	// bitstring and bitstringStores cover W3C Bitstring Status List entries;
	// see WithBitstringStatus.
	bitstring       *bitstringstatus.Checker
	bitstringStores []db.BitstringStatusStore
}

// NewRevocationService returns a service backed by the given Token Status
// List Checker, consulting every given store for status-referenced
// instances. A nil checker makes RefreshStatuses skip these stores; the stored
// status is still read. One store per credential
// format that carries a Token Status List reference (SD-JWT VC, mso_mdoc and
// SD-JWT-secured VCDM).
func NewRevocationService(checker *statuslist.Checker, stores ...db.CredentialStatusStore) *RevocationService {
	return &RevocationService{checker: checker, stores: stores}
}

// statusRevoked is the one revocation policy shared by every path: a credential
// is usable only when it reads VALID. INVALID, SUSPENDED, and any
// application-specific status all count as revoked (fail-closed on anything the
// issuer flags). UNKNOWN is the sole exception — it means "no status
// information" (not yet checked), not a bad status, so it stays advisory
// not-revoked.
// TODO: the client model has no separate suspended state, so suspension is
// surfaced as "revoked" for now — add a distinct suspended state (clientmodels
// + frontend) to show it as temporary rather than permanent.
func statusRevoked(s statuslist.Status) bool {
	return s != statuslist.StatusValid && s != statuslist.StatusUnknown
}

// IsStoredStatusRevoked applies the revocation policy to an instance's stored
// status, which RefreshStatuses keeps up to date. The flag never blocks
// disclosure: it is shown to the user, and the verifier's own status check is
// the backstop.
func (s *RevocationService) IsStoredStatusRevoked(status uint8) bool {
	return statusRevoked(statuslist.Status(status))
}

// RefreshStatuses re-fetches the status lists and updates stored statuses.
// Every instance is checked against its own status entry, and each batch's
// worst status is stored on every instance of the batch: a batch's instances
// are the same logical credential and are revoked together
// (draft-ietf-oauth-status-list §13.2), so one revoked instance revokes the
// batch. The credential list and disclosure, which read an instance's stored
// status, therefore always agree.
//
// Each status list is fetched once per store's sweep, however many instances
// point at it. A URI happening to be shared *across* formats still costs one
// extra fetch — an acceptable rarity, since batches of different formats are
// never the same credential.
//
// Fail-soft: an instance whose list cannot be fetched or read counts with its
// previous stored status, so a failure never clears a revocation, and a batch
// none of whose instances could be checked is left alone. A store that cannot
// list its instances is skipped the same way, but its error is returned after
// the other stores have been swept. A nil checker skips the Token Status List
// stores. Cancelling ctx is the one thing that does stop the sweep, keeping
// whatever was already written back.
//
// Returns how many batches' statuses moved. Re-confirmations and failures
// count for nothing; callers use the count to decide whether anything happened
// worth telling the app about. A cut-short sweep returns both: the changes it
// did write back, and the cancellation. Both matter — the writebacks are
// committed, so a caller that discards the count on an error loses those
// changes for good.
//
// The Bitstring stores (see WithBitstringStatus) are swept after the Token
// Status List ones, the same way.
func (s *RevocationService) RefreshStatuses(ctx context.Context) (changed int, err error) {
	var sweeps []func() (int, error)
	if s.checker != nil {
		for _, store := range s.stores {
			sweeps = append(sweeps, func() (int, error) { return s.refreshStoreStatuses(ctx, store) })
		}
	}
	if s.bitstring != nil {
		for _, store := range s.bitstringStores {
			sweeps = append(sweeps, func() (int, error) { return s.refreshBitstringStatuses(ctx, store) })
		}
	}

	var errs []error
	for _, sweep := range sweeps {
		n, err := sweep()
		changed += n
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return changed, err
		}
		// One format's store failing to load says nothing about the others,
		// so they are still swept; the failure is reported once the sweep is
		// done.
		errs = append(errs, err)
	}
	return changed, errors.Join(errs...)
}

// refreshStoreStatuses runs one store's sweep; see RefreshStatuses.
func (s *RevocationService) refreshStoreStatuses(ctx context.Context, store db.CredentialStatusStore) (changed int, err error) {
	instances, err := store.ListInstancesWithStatusReference()
	if err != nil {
		return 0, fmt.Errorf("load instances: %w", err)
	}

	// One Refresh per URI populates the cache; the per-instance Check calls
	// below then read from the warm cache (no extra HTTP traffic).
	refreshed := map[string]bool{}
	for _, inst := range instances {
		uri := inst.StatusListURI
		if _, seen := refreshed[uri]; seen {
			continue
		}
		// Stop between URIs, so shutdown does not wait on the remaining ones.
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if _, err := s.checker.Refresh(ctx, statuslist.Reference{URI: uri}); err != nil {
			// A fetch aborted by cancellation is not a fail-soft per-URI error:
			// it means the sweep was cut short, which the caller has to be able
			// to tell from a sweep that looked at everything.
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			eudi.Logger.Warnf("status refresh: refresh %s failed: %v", common.SanitizeForLog(uri), err)
			refreshed[uri] = false
			continue
		}
		refreshed[uri] = true
	}

	for _, batch := range groupByBatch(instances, func(inst db.CredentialStatusInstance) datatypes.UUID { return inst.BatchID }) {
		var combined batchStatus
		swept := make([]sweptInstance, len(batch))
		for i, inst := range batch {
			swept[i] = sweptInstance{id: inst.InstanceID, lastKnown: inst.LastKnownStatus}
			if !refreshed[inst.StatusListURI] {
				combined.addStored(inst.LastKnownStatus)
				continue
			}
			st, err := s.checker.Check(ctx, statuslist.Reference{URI: inst.StatusListURI, Index: inst.StatusListIdx})
			if err != nil {
				eudi.Logger.Warnf("status refresh: check idx %d on %s failed: %v", inst.StatusListIdx, common.SanitizeForLog(inst.StatusListURI), err)
				combined.addStored(inst.LastKnownStatus)
				continue
			}
			combined.addChecked(st)
		}
		if storeBatchStatus(store, swept, combined) {
			changed++
		}
	}
	return changed, nil
}

// sweptInstance is what storeBatchStatus needs of one instance a sweep looked at.
type sweptInstance struct {
	id        datatypes.UUID
	lastKnown uint8
}

// batchStatus combines a sweep's findings for one batch into the status every
// instance of the batch gets: the worst one, so one revoked instance revokes
// the batch. An instance that could not be checked counts with its stored
// status, so a failed check never clears a revocation.
type batchStatus struct {
	status  statuslist.Status
	checked bool
}

func (b *batchStatus) addChecked(s statuslist.Status) {
	b.status = statuslist.WorseStatus(b.status, s)
	b.checked = true
}

func (b *batchStatus) addStored(s uint8) {
	b.status = statuslist.WorseStatus(b.status, statuslist.Status(s))
}

// storeBatchStatus writes a batch's combined status to every instance of the
// batch, and reports whether any instance's stored status moved. A batch none
// of whose instances could be checked is left alone: nothing was learned, and
// the write would record a check that did not happen.
func storeBatchStatus(store interface {
	UpdateInstanceStatus(instanceID datatypes.UUID, status uint8, checkedAt time.Time) error
}, batch []sweptInstance, combined batchStatus) bool {
	if !combined.checked {
		return false
	}
	// Written either way, so a re-confirmation still records that the wallet
	// looked; only a different value counts as a change.
	now := time.Now()
	moved := false
	for _, inst := range batch {
		if err := store.UpdateInstanceStatus(inst.id, uint8(combined.status), now); err != nil {
			eudi.Logger.Warnf("status refresh: writeback failed for instance %s: %v", inst.id, err)
			continue
		}
		if uint8(combined.status) != inst.lastKnown {
			moved = true
		}
	}
	return moved
}

// groupByBatch splits instances into their batches, in the order each batch
// first appears.
func groupByBatch[T any](instances []T, batchOf func(T) datatypes.UUID) [][]T {
	index := map[datatypes.UUID]int{}
	var batches [][]T
	for _, inst := range instances {
		id := batchOf(inst)
		i, ok := index[id]
		if !ok {
			i = len(batches)
			index[id] = i
			batches = append(batches, nil)
		}
		batches[i] = append(batches[i], inst)
	}
	return batches
}

// BatchRevocation returns, keyed by batch hash, which of store's batches support
// revocation (carry any status reference) and which are currently revoked,
// derived from the stored LastKnownStatus that RefreshStatuses maintains. Each
// format's credential list passes its own store. A batch's instances are the
// same credential and are revoked together, so a batch is revoked as soon as
// any status-referenced instance reads a non-VALID status (see statusRevoked),
// and supports revocation if it carries any status reference at all. A lifted
// suspension is reflected on the next RefreshStatuses sweep.
func (s *RevocationService) BatchRevocation(store db.CredentialStatusStore) (revoked, revocable map[string]bool, err error) {
	statuses, err := store.ListStatusReferencedInstanceStatuses()
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
