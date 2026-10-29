package sdjwt_dcql

import (
	"time"

	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
)

// The engine serves both SD-JWT-secured data models, which keep their
// credentials in different tables (SdJwtVcBatch, VcdmBatch). It reads them
// through BatchStore, as the Batch and Instance views below; one adapter per
// table does the mapping. The views carry exactly what the engine reads, in the
// SD-JWT VC storage shape, so the claim matching, display and disclosure code
// is shared rather than written twice.

// Batch is the engine's read-only view of one stored SD-JWT-secured batch.
type Batch struct {
	ID     datatypes.UUID
	Format models.CredentialFormat

	// CredentialType is the type identity a DCQL vct_values entry is matched
	// against: the `vct` for SD-JWT VC, the @context+type composite for VCDM.
	CredentialType string
	Hash           string

	// CredentialIssuer is the OpenID4VCI credential_issuer the credential was
	// obtained from.
	CredentialIssuer string
	IssuerVerified   bool

	// ProcessedPayload is the SD-JWT payload with every disclosure resolved.
	ProcessedPayload datatypes.JSON

	IssuedAt  datatypes.NullTime
	ExpiresAt datatypes.NullTime
	NotBefore datatypes.NullTime

	BatchSize      uint
	RemainingCount uint

	IssuerDisplay      []models.IssuerMetadataDisplay
	CredentialMetadata *models.CredentialMetadata
}

// Instance is the engine's view of one stored copy within a Batch.
type Instance struct {
	ID            datatypes.UUID
	RawCredential []byte

	// Revoked and RevocationSupported are resolved by the store adapter, since
	// the status mechanism differs per data model.
	Revoked             bool
	RevocationSupported bool
}

// BatchStore is the storage the engine needs: read batches, take an unused
// copy, spend it.
type BatchStore interface {
	ListBatches() ([]*Batch, error)
	GetUnusedInstance(batchID datatypes.UUID) (*Instance, error)
	MarkInstanceUsed(instanceID datatypes.UUID) error
}

// RevocationChecker applies the revocation policy to an instance's stored
// status, which the revocation sweep keeps up to date for every format. The
// disclosure planner depends only on this narrow verb, keeping the status list
// mechanics out of this package (see services.RevocationService).
type RevocationChecker interface {
	IsStoredStatusRevoked(status uint8) bool
}

// NewSdJwtVcBatchStore adapts the SD-JWT VC store. revocation determines an
// instance's Revoked flag; nil disables the check (instances are then never
// flagged revoked).
func NewSdJwtVcBatchStore(store db.SdJwtVcStore, revocation RevocationChecker) BatchStore {
	return &sdJwtVcBatchStore{store: store, revocation: revocation}
}

type sdJwtVcBatchStore struct {
	store      db.SdJwtVcStore
	revocation RevocationChecker
}

func (s *sdJwtVcBatchStore) ListBatches() ([]*Batch, error) {
	batches, err := s.store.GetCredentialBatchList()
	if err != nil {
		return nil, err
	}
	result := make([]*Batch, len(batches))
	for i, b := range batches {
		result[i] = &Batch{
			ID:                 b.ID,
			Format:             b.Format,
			CredentialType:     b.VerifiableCredentialType,
			Hash:               b.Hash,
			CredentialIssuer:   b.CredentialIssuerIdentifier,
			IssuerVerified:     b.IssuerVerified,
			ProcessedPayload:   b.ProcessedSdJwtPayload,
			IssuedAt:           b.IssuedAt,
			ExpiresAt:          b.ExpiresAt,
			NotBefore:          b.NotBefore,
			BatchSize:          b.BatchSize,
			RemainingCount:     b.RemainingCount,
			IssuerDisplay:      b.IssuerDisplay,
			CredentialMetadata: b.CredentialMetadata,
		}
	}
	return result, nil
}

func (s *sdJwtVcBatchStore) GetUnusedInstance(batchID datatypes.UUID) (*Instance, error) {
	instance, err := s.store.GetUnusedInstance(batchID)
	if err != nil {
		return nil, err
	}
	return &Instance{
		ID:                  instance.ID,
		RawCredential:       instance.RawCredential,
		Revoked:             s.revocation != nil && s.revocation.IsStoredStatusRevoked(instance.LastKnownStatus),
		RevocationSupported: instance.StatusListURI != nil,
	}, nil
}

func (s *sdJwtVcBatchStore) MarkInstanceUsed(instanceID datatypes.UUID) error {
	return s.store.MarkInstanceUsed(instanceID)
}

// NewVcdmBatchStore adapts the SD-JWT-secured VCDM store. revocation determines
// an instance's Revoked flag; nil disables the check.
func NewVcdmBatchStore(store db.VcdmStore, revocation RevocationChecker) BatchStore {
	return &vcdmBatchStore{store: store, revocation: revocation}
}

type vcdmBatchStore struct {
	store      db.VcdmStore
	revocation RevocationChecker
}

func (s *vcdmBatchStore) ListBatches() ([]*Batch, error) {
	batches, err := s.store.ListBatches()
	if err != nil {
		return nil, err
	}
	result := make([]*Batch, len(batches))
	for i, b := range batches {
		result[i] = &Batch{
			ID:                 b.ID,
			Format:             b.Format,
			CredentialType:     b.TypeIdentity,
			Hash:               b.Hash,
			CredentialIssuer:   b.CredentialIssuer,
			IssuerVerified:     b.IssuerVerified,
			ProcessedPayload:   b.ProcessedPayload,
			IssuedAt:           datatypes.NullTime{V: b.IssuedAt, Valid: !b.IssuedAt.IsZero()},
			ExpiresAt:          b.ExpiresAt,
			NotBefore:          b.NotBefore,
			BatchSize:          b.BatchSize,
			RemainingCount:     b.RemainingCount,
			IssuerDisplay:      services.VcdmIssuerDisplays(b),
			CredentialMetadata: services.VcdmCredentialMetadata(b),
		}
	}
	return result, nil
}

func (s *vcdmBatchStore) GetUnusedInstance(batchID datatypes.UUID) (*Instance, error) {
	instance, err := s.store.GetUnusedInstance(batchID)
	if err != nil {
		return nil, err
	}
	return &Instance{
		ID:                  instance.ID,
		RawCredential:       instance.RawCredential,
		Revoked:             s.revocation != nil && s.revocation.IsStoredStatusRevoked(instance.LastKnownStatus),
		RevocationSupported: instance.HasStatusReference(),
	}, nil
}

func (s *vcdmBatchStore) MarkInstanceUsed(instanceID datatypes.UUID) error {
	return s.store.MarkInstanceUsed(instanceID)
}

// isBatchValid returns false if the credential batch is expired or not yet
// valid. Unix epoch (time.Unix(0,0)) is treated as "not set" because the
// storage layer has marked ExpiresAt/NotBefore as Valid even when the
// credential states no expiry or not-before of its own, storing 0 as the
// timestamp.
func isBatchValid(batch *Batch, now time.Time) bool {
	epoch := time.Unix(0, 0)
	if batch.ExpiresAt.Valid && !batch.ExpiresAt.V.Equal(epoch) && now.After(batch.ExpiresAt.V) {
		return false
	}
	if batch.NotBefore.Valid && !batch.NotBefore.V.Equal(epoch) && now.Before(batch.NotBefore.V) {
		return false
	}
	return true
}

// expiryUnix returns the batch's expiry as a unix timestamp, or nil if the
// batch does not expire.
func expiryUnix(batch *Batch) *int64 {
	if batch.ExpiresAt.Valid {
		x := batch.ExpiresAt.V.Unix()
		return &x
	}
	return nil
}

// batchInstanceCountRemaining returns nil for batch-of-1 credentials
// (infinitely reusable) and a pointer to the remaining count for larger
// batches.
func batchInstanceCountRemaining(batch *Batch) *uint {
	if batch.BatchSize <= 1 {
		return nil
	}
	return &batch.RemainingCount
}
