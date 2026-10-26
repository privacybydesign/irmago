package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/bitstringstatus"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/internal/common"
	"gorm.io/datatypes"
)

// WithBitstringStatus extends the service to W3C Bitstring Status List entries,
// which SD-JWT-secured VCDM credentials can carry instead of, or next to, an
// IETF reference. checker fetches the lists; RefreshStatuses then also sweeps
// the given stores. Returns s, for chaining onto NewRevocationService.
func (s *RevocationService) WithBitstringStatus(checker *bitstringstatus.Checker, stores ...db.BitstringStatusStore) *RevocationService {
	s.bitstring = checker
	s.bitstringStores = stores
	return s
}

// refreshBitstringStatuses is refreshStoreStatuses for a BitstringStatusStore:
// every instance checked, each list fetched once per sweep, and each batch's
// worst status stored on all of its instances. An instance's status combines
// all of its references, its IETF one included.
func (s *RevocationService) refreshBitstringStatuses(ctx context.Context, store db.BitstringStatusStore) (changed int, err error) {
	instances, err := store.ListInstancesWithBitstringStatus()
	if err != nil {
		return 0, fmt.Errorf("load instances: %w", err)
	}

	sweep := &bitstringSweep{
		service:            s,
		refreshedTokenURIs: map[string]bool{},
		lists:              map[string]bitstringstatus.ListCredentialSubject{},
	}
	for _, batch := range groupByBatch(instances, func(inst db.BitstringStatusInstance) datatypes.UUID { return inst.BatchID }) {
		var combined batchStatus
		swept := make([]sweptInstance, len(batch))
		for i, inst := range batch {
			swept[i] = sweptInstance{id: inst.InstanceID, lastKnown: inst.LastKnownStatus}
			if ctx.Err() != nil {
				return changed, ctx.Err()
			}
			status, ok := sweep.check(ctx, inst)
			if ctx.Err() != nil {
				return changed, ctx.Err()
			}
			if !ok {
				combined.addStored(inst.LastKnownStatus)
				continue
			}
			combined.addChecked(status)
		}
		if storeBatchStatus(store, swept, combined) {
			changed++
		}
	}
	return changed, nil
}

// bitstringSweep is the state of one store's Bitstring sweep: which lists it
// has already fetched.
type bitstringSweep struct {
	service            *RevocationService
	refreshedTokenURIs map[string]bool
	lists              map[string]bitstringstatus.ListCredentialSubject
}

// check returns the instance's current status, or false when it could not be
// determined (logged), including when its IETF reference has no checker.
func (w *bitstringSweep) check(ctx context.Context, inst db.BitstringStatusInstance) (statuslist.Status, bool) {
	status := statuslist.StatusValid

	if inst.StatusListURI != nil && inst.StatusListIdx != nil {
		checker := w.service.checker
		if checker == nil {
			return 0, false
		}
		ref := statuslist.Reference{URI: *inst.StatusListURI, Index: *inst.StatusListIdx}
		// The first instance on a list re-fetches it; the others read the
		// list that fetch just cached.
		var s statuslist.Status
		var err error
		if w.refreshedTokenURIs[ref.URI] {
			s, err = checker.Check(ctx, ref)
		} else {
			s, err = checker.Refresh(ctx, ref)
		}
		if err != nil {
			eudi.Logger.Warnf("status refresh: %s: %v", common.SanitizeForLog(ref.URI), err)
			return 0, false
		}
		w.refreshedTokenURIs[ref.URI] = true
		status = vcdmsdjwt.WorseStatus(status, s)
	}

	var entries []bitstringstatus.Entry
	if err := json.Unmarshal(inst.Entries, &entries); err != nil {
		eudi.Logger.Warnf("status refresh: stored bitstring entries of instance %s: %v", inst.InstanceID, err)
		return 0, false
	}
	for _, entry := range entries {
		subject, ok := w.lists[entry.StatusListCredential]
		if !ok {
			var err error
			subject, err = w.service.bitstring.Fetch(ctx, entry.StatusListCredential)
			if err != nil {
				eudi.Logger.Warnf("status refresh: %s: %v", common.SanitizeForLog(entry.StatusListCredential), err)
				return 0, false
			}
			w.lists[entry.StatusListCredential] = subject
		}
		value, err := bitstringstatus.Check(entry, subject)
		if err != nil {
			eudi.Logger.Warnf("status refresh: %s: %v", common.SanitizeForLog(entry.StatusListCredential), err)
			return 0, false
		}
		status = vcdmsdjwt.WorseStatus(status, vcdmsdjwt.BitstringEntryStatus(entry, value))
	}
	return status, true
}

// withStatusReferences fills a VCDM instance's status columns from the
// references the credential carries. Called at issuance, right after the
// holder verifier checked those references, so the status is seeded as valid.
func withStatusReferences(inst models.VcdmBatchInstance, refs vcdmsdjwt.StatusReferences, now time.Time) (models.VcdmBatchInstance, error) {
	if !refs.HasAny() {
		return inst, nil
	}
	if ref := refs.TokenStatusList; ref != nil {
		uri, idx := ref.URI, ref.Index
		inst.StatusListURI = &uri
		inst.StatusListIdx = &idx
	}
	if len(refs.Bitstring) > 0 {
		entries, err := json.Marshal(refs.Bitstring)
		if err != nil {
			return inst, fmt.Errorf("failed to marshal bitstring status entries: %w", err)
		}
		inst.BitstringStatusEntries = entries
	}
	inst.HasStatusReference = true
	inst.LastKnownStatus = uint8(statuslist.StatusValid)
	inst.LastStatusCheckAt = &now
	return inst, nil
}
