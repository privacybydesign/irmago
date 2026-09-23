package db

import (
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
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

// statusTables names where one format keeps its instances and their batches,
// so both stores share the CredentialStatusStore queries below. The status
// columns themselves are named the same in every instance table.
type statusTables struct {
	instanceModel any
	instances     string // instance table
	batches       string // batch table
	batchFK       string // instance column pointing at the batch
}

var (
	sdJwtVcStatusTables = statusTables{
		instanceModel: &models.SdJwtVcBatchInstance{},
		instances:     "issued_credential_instances",
		batches:       "credential_batches",
		batchFK:       "credential_batch_id",
	}
	mdocStatusTables = statusTables{
		instanceModel: &models.MdocBatchInstance{},
		instances:     "mdoc_batch_instances",
		batches:       "mdoc_batches",
		batchFK:       "mdoc_batch_id",
	}
)

func (t statusTables) listInstancesWithStatusReference(db *gorm.DB) ([]CredentialStatusInstance, error) {
	var out []CredentialStatusInstance
	err := db.
		Model(t.instanceModel).
		Select("id AS instance_id, " +
			t.batchFK + " AS batch_id, " +
			"status_list_uri AS status_list_uri, " +
			"status_list_idx AS status_list_idx, " +
			"last_known_status AS last_known_status").
		Where("status_list_uri IS NOT NULL AND status_list_idx IS NOT NULL").
		Scan(&out).Error
	return out, err
}

func (t statusTables) listStatusReferencedInstanceStatuses(db *gorm.DB) ([]BatchInstanceStatus, error) {
	var out []BatchInstanceStatus
	err := db.
		Model(t.instanceModel).
		Select(t.batches + ".hash AS hash, " +
			t.instances + ".last_known_status AS last_known_status").
		Joins("JOIN " + t.batches + " ON " + t.batches + ".id = " + t.instances + "." + t.batchFK).
		Where(t.instances + ".status_list_uri IS NOT NULL").
		Scan(&out).Error
	return out, err
}

func (t statusTables) updateInstanceStatus(db *gorm.DB, instanceID datatypes.UUID, status uint8, checkedAt time.Time) error {
	if instanceID.IsNil() {
		return fmt.Errorf("instanceID is required")
	}
	res := db.Model(t.instanceModel).
		Where("id = ?", instanceID).
		Updates(map[string]any{
			"last_known_status":    status,
			"last_status_check_at": checkedAt,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
