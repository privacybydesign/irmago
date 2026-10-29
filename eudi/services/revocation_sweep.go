package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/bitstringstatus"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmstatus"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/internal/common"
)

// instanceStatus is an instance's current status, from all of its references.
func instanceStatus(ctx context.Context, inst db.CredentialStatusInstance, lists *sweepLists) (statuslist.Status, error) {
	var refs vcdmstatus.StatusReferences
	if inst.StatusListURI != nil && inst.StatusListIdx != nil {
		refs.TokenStatusList = &statuslist.Reference{URI: *inst.StatusListURI, Index: *inst.StatusListIdx}
	}
	if len(inst.BitstringEntries) > 0 {
		if err := json.Unmarshal(inst.BitstringEntries, &refs.Bitstring); err != nil {
			return statuslist.StatusUnknown, fmt.Errorf("stored bitstring entries: %w", err)
		}
	}
	return vcdmstatus.CheckStatus(ctx, refs, inst.Issuer, lists)
}

// errListUnavailable is what sweepLists returns for a list it already failed
// to read in this sweep. The first failure was logged; the instances after it
// only keep their stored status.
var errListUnavailable = errors.New("status list unavailable in this sweep")

// sweepLists is the vcdmstatus.Lists of one store's sweep. It reads every list
// once, however many instances point at it, and remembers a failure too, so a
// slow or broken list costs one fetch per sweep rather than one per instance.
// Bitstring lists are kept per URL and issuer, because a list is only accepted
// for credentials of its own issuer.
type sweepLists struct {
	service *RevocationService
	// tokenLists maps a Token Status List URI to the outcome of refreshing it;
	// a refreshed list is in the checker's cache.
	tokenLists     map[string]error
	bitstringLists map[bitstringListKey]bitstringList
}

type bitstringListKey struct{ url, issuer string }

type bitstringList struct {
	subject bitstringstatus.ListCredentialSubject
	err     error
}

func newSweepLists(s *RevocationService) *sweepLists {
	return &sweepLists{
		service:        s,
		tokenLists:     map[string]error{},
		bitstringLists: map[bitstringListKey]bitstringList{},
	}
}

func (l *sweepLists) TokenStatus(ctx context.Context, ref statuslist.Reference) (statuslist.Status, error) {
	checker := l.service.checker
	if checker == nil {
		return statuslist.StatusUnknown, errors.New("no Token Status List checker configured")
	}
	err, seen := l.tokenLists[ref.URI]
	if !seen {
		// One Refresh per URI populates the checker's cache; the Check calls
		// then read from it, with no extra HTTP traffic.
		if _, err = checker.Refresh(ctx, statuslist.Reference{URI: ref.URI}); err != nil {
			if ctx.Err() != nil {
				return statuslist.StatusUnknown, ctx.Err()
			}
			eudi.Logger.Warnf("status refresh: refresh %s failed: %v", common.SanitizeForLog(ref.URI), err)
		}
		l.tokenLists[ref.URI] = err
	}
	if err != nil {
		return statuslist.StatusUnknown, errListUnavailable
	}
	return checker.Check(ctx, ref)
}

func (l *sweepLists) BitstringValue(ctx context.Context, entry bitstringstatus.Entry, issuer string) (uint, error) {
	checker := l.service.bitstring
	if checker == nil {
		return 0, errors.New("no Bitstring Status List checker configured")
	}
	key := bitstringListKey{url: entry.StatusListCredential, issuer: issuer}
	list, seen := l.bitstringLists[key]
	if !seen {
		list.subject, list.err = checker.Fetch(ctx, entry.StatusListCredential, issuer)
		if list.err != nil && ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if list.err != nil {
			eudi.Logger.Warnf("status refresh: fetch %s failed: %v", common.SanitizeForLog(entry.StatusListCredential), list.err)
		}
		l.bitstringLists[key] = list
	}
	if list.err != nil {
		return 0, errListUnavailable
	}
	return bitstringstatus.Check(entry, list.subject)
}

// withStatusReferences fills a VCDM instance's status columns from the
// references the credential carries. Called at issuance, right after the
// holder verifier checked those references, so the status is seeded as valid.
func withStatusReferences(inst models.VcdmBatchInstance, refs vcdmstatus.StatusReferences, now time.Time) (models.VcdmBatchInstance, error) {
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
	inst.LastKnownStatus = uint8(statuslist.StatusValid)
	inst.LastStatusCheckAt = &now
	return inst, nil
}
