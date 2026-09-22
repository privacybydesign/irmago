package db

import (
	"time"

	"gorm.io/datatypes"
)

// CredentialStatusInstance is an instance's status_list reference.
// BatchID lets callers select a single representative instance per batch, and
// LastKnownStatus lets them tell a status change from a re-confirmation without
// a second read.
type CredentialStatusInstance struct {
	InstanceID      datatypes.UUID
	BatchID         datatypes.UUID
	StatusListURI   string
	StatusListIdx   uint64
	LastKnownStatus uint8
}

// BatchInstanceStatus pairs a batch's deterministic hash with one of its
// instances' last-known Token Status List status. Only instances that carry
// a status_list reference are reported.
type BatchInstanceStatus struct {
	Hash            string
	LastKnownStatus uint8
}

// CredentialStatusStore is the subset of a per-format credential store that
// Token Status List revocation needs: reading which instances carry a
// status_list reference and writing back what the wallet last observed for
// one. SdJwtVcStore and MdocStore both implement it — their instance tables
// differ (issued_credential_instances vs mdoc_batch_instances, joined
// through a different batch table for the hash), but the shape
// RevocationService needs from either is identical, which is what lets one
// RevocationService serve every credential format instead of each format
// growing its own revocation sweep.
type CredentialStatusStore interface {
	// ListInstancesWithStatusReference returns every instance with a
	// (status_list.uri, status_list.idx) pair, along with the status the
	// wallet last recorded for it.
	ListInstancesWithStatusReference() ([]CredentialStatusInstance, error)

	// ListStatusReferencedInstanceStatuses returns the (batch hash,
	// last_known_status) pair for every instance carrying a Token Status List
	// reference. Used to surface per-credential revocation in the credential
	// list without loading full instances.
	ListStatusReferencedInstanceStatuses() ([]BatchInstanceStatus, error)

	// UpdateInstanceStatus writes last_known_status and last_status_check_at
	// on a single instance. Returns ErrNotFound on no match.
	UpdateInstanceStatus(instanceID datatypes.UUID, status uint8, checkedAt time.Time) error
}
