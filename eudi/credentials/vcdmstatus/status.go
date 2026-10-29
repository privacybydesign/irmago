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

// StatusKey is the JWT claim carrying an IETF Token Status List reference.
const StatusKey = "status"

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
	if raw, ok := document[StatusKey]; ok {
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

// CheckStatus returns the credential's current status: StatusValid only when
// every reference reads valid. A reference whose checker is not configured is
// skipped, as SD-JWT VC skips its check without a StatusChecker. A fetch or
// verification failure is an error. issuer is the credential's `issuer`, which
// a Bitstring status list must also have.
func CheckStatus(
	ctx context.Context,
	refs StatusReferences,
	issuer string,
	tokenStatusList *statuslist.Checker,
	bitstring *bitstringstatus.Checker,
) (statuslist.Status, error) {
	status := statuslist.StatusValid
	if refs.TokenStatusList != nil && tokenStatusList != nil {
		s, err := tokenStatusList.Check(ctx, *refs.TokenStatusList)
		if err != nil {
			return statuslist.StatusUnknown, fmt.Errorf("status list check failed: %w", err)
		}
		status = statuslist.WorseStatus(status, s)
	}
	if bitstring == nil {
		return status, nil
	}
	for _, entry := range refs.Bitstring {
		value, err := bitstring.Check(ctx, entry, issuer)
		if err != nil {
			return statuslist.StatusUnknown, fmt.Errorf("bitstring status check failed: %w", err)
		}
		status = statuslist.WorseStatus(status, bitstringstatus.EntryStatus(entry, value))
	}
	return status, nil
}
