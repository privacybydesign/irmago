// Package vcdmstatus reads and checks the status of a W3C VCDM credential,
// whatever secures it: the W3C Bitstring Status List entries in its
// credentialStatus, and the IETF Token Status List reference a JWT-secured
// credential can carry in its status claim.
package vcdmstatus

import (
	"context"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/bitstringstatus"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
)

// StatusReferences are the status mechanisms a VCDM credential can point to.
// VCDM's own is the W3C `credentialStatus` (Bitstring Status List); as a JWT it
// can also carry the IETF `status.status_list` claim, which is what veramo
// issues.
type StatusReferences struct {
	TokenStatusList *statuslist.Reference

	// Bitstring holds the revocation and suspension entries. Refresh and
	// message entries carry no revocation state, so they are left out.
	Bitstring []bitstringstatus.Entry
}

// HasAny reports whether the credential's status can be checked at all.
func (r StatusReferences) HasAny() bool {
	return r.TokenStatusList != nil || len(r.Bitstring) > 0
}

// ParseStatusReferences reads the status references of a verified document. A
// malformed reference is an error, not an absent one: a credential that tries
// to name its status and fails cannot be shown as unrevocable.
func ParseStatusReferences(document vcdm.Document) (StatusReferences, error) {
	var refs StatusReferences
	if raw, ok := document[statuslist.StatusClaimKey]; ok {
		ref, err := statuslist.ParseStatusClaim(raw)
		if err != nil {
			return StatusReferences{}, err
		}
		refs.TokenStatusList = ref
	}

	entries, err := bitstringstatus.ParseEntries(document[vcdm.CredentialStatusKey])
	if err != nil {
		return StatusReferences{}, err
	}
	for _, entry := range entries {
		if entry.StatusPurpose == bitstringstatus.PurposeRevocation || entry.StatusPurpose == bitstringstatus.PurposeSuspension {
			refs.Bitstring = append(refs.Bitstring, entry)
		}
	}
	return refs, nil
}

// Lists reads the status lists CheckStatus consults. Issuance reads them
// through Checkers; the wallet's status sweep through a cache that fetches each
// list once per sweep.
type Lists interface {
	// TokenStatus returns the status at ref in an IETF Token Status List.
	TokenStatus(ctx context.Context, ref statuslist.Reference) (statuslist.Status, error)
	// BitstringValue returns the value of entry in its W3C Bitstring Status
	// List, which must have been issued by issuer.
	BitstringValue(ctx context.Context, entry bitstringstatus.Entry, issuer string) (uint, error)
}

// CheckStatus returns the credential's current status: StatusValid only when
// every reference reads valid. issuer is the credential's `issuer`, which a
// Bitstring status list must also have. A list that cannot be read is an
// error.
func CheckStatus(ctx context.Context, refs StatusReferences, issuer string, lists Lists) (statuslist.Status, error) {
	status := statuslist.StatusValid
	if refs.TokenStatusList != nil {
		s, err := lists.TokenStatus(ctx, *refs.TokenStatusList)
		if err != nil {
			return statuslist.StatusUnknown, fmt.Errorf("status list check failed: %w", err)
		}
		status = statuslist.WorseStatus(status, s)
	}
	for _, entry := range refs.Bitstring {
		value, err := lists.BitstringValue(ctx, entry, issuer)
		if err != nil {
			return statuslist.StatusUnknown, fmt.Errorf("bitstring status check failed: %w", err)
		}
		status = statuslist.WorseStatus(status, bitstringstatus.EntryStatus(entry, value))
	}
	return status, nil
}

// Checkers reads status lists straight from the two checkers. A reference
// whose checker is nil reads as valid: the check is skipped, as SD-JWT VC skips
// its check without a StatusChecker.
type Checkers struct {
	TokenStatusList *statuslist.Checker
	Bitstring       *bitstringstatus.Checker
}

func (c Checkers) TokenStatus(ctx context.Context, ref statuslist.Reference) (statuslist.Status, error) {
	if c.TokenStatusList == nil {
		return statuslist.StatusValid, nil
	}
	return c.TokenStatusList.Check(ctx, ref)
}

func (c Checkers) BitstringValue(ctx context.Context, entry bitstringstatus.Entry, issuer string) (uint, error) {
	if c.Bitstring == nil {
		return 0, nil
	}
	return c.Bitstring.Check(ctx, entry, issuer)
}
