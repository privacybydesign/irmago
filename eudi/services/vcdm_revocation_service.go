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

// VcdmRevocationService is RevocationService for SD-JWT-secured VCDM
// credentials. It keeps their stored status up to date and reports it, under
// the same policy (statusRevoked), over both mechanisms a VCDM credential can
// name: the IETF Token Status List and the W3C Bitstring Status List.
//
// Unlike RevocationService, IsRevoked reads the stored status rather than a
// cached list. The Bitstring checker keeps no cache, and the stored status is
// what the sweep writes and the credential list shows, so the disclosure plan
// and the list cannot disagree.
type VcdmRevocationService struct {
	tokenStatusList *statuslist.Checker
	bitstring       *bitstringstatus.Checker
	store           db.VcdmStore
}

// NewVcdmRevocationService returns a service over the given checkers and store.
// A nil checker skips that mechanism in the sweep; stored statuses are still
// reported.
func NewVcdmRevocationService(tokenStatusList *statuslist.Checker, bitstring *bitstringstatus.Checker, store db.VcdmStore) *VcdmRevocationService {
	return &VcdmRevocationService{tokenStatusList: tokenStatusList, bitstring: bitstring, store: store}
}

// IsRevoked reports whether the instance's stored status counts as revoked.
func (s *VcdmRevocationService) IsRevoked(instance *models.VcdmBatchInstance) bool {
	return instance.HasStatusReference && statusRevoked(statuslist.Status(instance.LastKnownStatus))
}

// RefreshStatuses re-checks one representative instance per batch and writes
// back its status, like RevocationService.RefreshStatuses: a batch's copies are
// revoked together. Each list is fetched once per sweep. Fail-soft per
// instance; a cancelled ctx stops the sweep and is returned with the count of
// batches whose status changed so far.
func (s *VcdmRevocationService) RefreshStatuses(ctx context.Context) (changed int, err error) {
	instances, err := s.store.ListInstancesWithStatusReference()
	if err != nil {
		return 0, fmt.Errorf("load VCDM instances: %w", err)
	}

	sweep := &vcdmStatusSweep{
		service:            s,
		refreshedTokenURIs: map[string]bool{},
		bitstringLists:     map[string]bitstringstatus.ListCredentialSubject{},
	}
	seenBatch := map[datatypes.UUID]bool{}
	for _, inst := range instances {
		if seenBatch[inst.VcdmBatchID] {
			continue
		}
		seenBatch[inst.VcdmBatchID] = true

		if ctx.Err() != nil {
			return changed, ctx.Err()
		}
		status, ok := sweep.check(ctx, inst)
		if ctx.Err() != nil {
			return changed, ctx.Err()
		}
		if !ok {
			continue
		}
		if err := s.store.UpdateInstanceStatus(inst.ID, uint8(status), time.Now()); err != nil {
			eudi.Logger.Warnf("VCDM status refresh: writeback failed for instance %s: %v", inst.ID, err)
			continue
		}
		if uint8(status) != inst.LastKnownStatus {
			changed++
		}
	}
	return changed, nil
}

// BatchRevocation returns, keyed by batch hash, which batches support
// revocation and which are revoked, from the stored statuses.
func (s *VcdmRevocationService) BatchRevocation() (revoked, revocable map[string]bool, err error) {
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

// vcdmStatusSweep is the state of one RefreshStatuses run: which lists it has
// already fetched.
type vcdmStatusSweep struct {
	service            *VcdmRevocationService
	refreshedTokenURIs map[string]bool
	bitstringLists     map[string]bitstringstatus.ListCredentialSubject
}

// check returns the instance's current status, or false when it could not be
// determined (logged) or a mechanism it uses has no checker.
func (w *vcdmStatusSweep) check(ctx context.Context, inst *models.VcdmBatchInstance) (statuslist.Status, bool) {
	status := statuslist.StatusValid

	if inst.StatusListURI != nil && inst.StatusListIdx != nil {
		checker := w.service.tokenStatusList
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
			eudi.Logger.Warnf("VCDM status refresh: %s: %v", common.SanitizeForLog(ref.URI), err)
			return 0, false
		}
		w.refreshedTokenURIs[ref.URI] = true
		status = vcdmsdjwt.WorseStatus(status, s)
	}

	entries, err := bitstringEntries(inst)
	if err != nil {
		eudi.Logger.Warnf("VCDM status refresh: instance %s: %v", inst.ID, err)
		return 0, false
	}
	if len(entries) > 0 && w.service.bitstring == nil {
		return 0, false
	}
	for _, entry := range entries {
		subject, ok := w.bitstringLists[entry.StatusListCredential]
		if !ok {
			subject, err = w.service.bitstring.Fetch(ctx, entry.StatusListCredential)
			if err != nil {
				eudi.Logger.Warnf("VCDM status refresh: %s: %v", common.SanitizeForLog(entry.StatusListCredential), err)
				return 0, false
			}
			w.bitstringLists[entry.StatusListCredential] = subject
		}
		value, err := bitstringstatus.Check(entry, subject)
		if err != nil {
			eudi.Logger.Warnf("VCDM status refresh: %s: %v", common.SanitizeForLog(entry.StatusListCredential), err)
			return 0, false
		}
		status = vcdmsdjwt.WorseStatus(status, vcdmsdjwt.BitstringEntryStatus(entry, value))
	}
	return status, true
}

func bitstringEntries(inst *models.VcdmBatchInstance) ([]bitstringstatus.Entry, error) {
	if len(inst.BitstringStatusEntries) == 0 {
		return nil, nil
	}
	var entries []bitstringstatus.Entry
	if err := json.Unmarshal(inst.BitstringStatusEntries, &entries); err != nil {
		return nil, fmt.Errorf("stored bitstring status entries: %w", err)
	}
	return entries, nil
}

// withStatusReferences fills the instance's status columns from the references
// the credential carries. Called at issuance, right after the holder verifier
// checked those references, so the status is seeded as valid.
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
