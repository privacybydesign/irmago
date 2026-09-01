package models

import (
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// The cross-format storage model (#679/#686) is realized below as LogicalCredential
// + FormatBinding, superseding the single-table "Format field distinguishes formats"
// approach. CredentialBatch is the legacy flat model: as of #685 it is no longer
// written — the store persists FormatBindings and the read methods project them back
// to this shape — and it is retained only as that read-projection DTO and as the type
// the one-time flat->three-layer migration reads. It (and the credential_batch_id
// foreign keys on the child tables) can be dropped in a future release, once every
// install has run the migration.

// CredentialFormat represents the credential format identifier as defined in the OID4VCI spec.
type CredentialFormat string

const (
	CredentialFormatSdJwtVc CredentialFormat = "dc+sd-jwt"
	// CredentialFormatSdJwtVcdm is an SD-JWT-secured W3C VCDM 2.0 credential
	// (VC-JOSE-COSE §3.2). Stored in the same tables as SD-JWT VC batches
	// per the storage decision (#679): raw secured blob per instance plus
	// the extracted document as batch metadata, distinguished by this format.
	CredentialFormatSdJwtVcdm CredentialFormat = "vc+sd-jwt"
)

// CredentialBatch groups all credential instances issued from a single credential_configuration_id
// request within one OID4VCI issuance session. When the issuer supports batch issuance,
// BatchSize > 1 and multiple IssuedCredentialInstance rows belong to this batch. Single-use
// wallets decrement RemainingCount on each presentation; the batch is exhausted when it reaches 0.
//
// LEGACY (#685): no longer written. The store persists FormatBinding rows; the read
// methods build CredentialBatch values in memory as a projection of a FormatBinding
// (see db.projectBinding). This struct is kept only as that projection DTO and as the
// model the flat->three-layer migration reads.
type CredentialBatch struct {
	ID datatypes.UUID

	// IssuerIdentifier is the credential's issuer identity as resolved during
	// verification: the `iss` claim, or the subject of the x5c end-entity
	// certificate when `iss` is absent (SD-JWT VC §2.2.2.3).
	// This is the value used for DCQL TrustedAuthority resolution in OID4VP.
	// The column has been renamed from a previously called `IssuerURL` column and is now more in line with the specification naming conventions.
	IssuerIdentifier string `gorm:"column:issuer_url;not null"`

	// CredentialIssuerIdentifier is the credential's issuer identity as resolved
	// from the Credential Offer (OID4VCI §12.2.1).
	// The column has been renamed from a previously called `CredentialIssuer` column and is now more in line with the specification naming conventions.
	CredentialIssuerIdentifier string `gorm:"column:credential_issuer;not null"`

	// VerifiableCredentialType is the vct claim from the issued SD-JWT VC.
	VerifiableCredentialType string

	// Format is the credential format identifier (e.g. "dc+sd-jwt").
	Format CredentialFormat

	// Hash is a deterministic hash over the credential type and its sorted disclosed attributes.
	// Computed with the same algorithm as irmaclient.CreateHashForSdJwtVc so that the EUDI
	// storage remains compatible with the IRMA client's deduplication logic.
	Hash string `gorm:"uniqueIndex"`

	// ProcessedSdJwtPayload is the JSON-encoded payload of the SD-JWT after processing/verifying the issuer-signed JWT.
	ProcessedSdJwtPayload datatypes.JSON `gorm:"type:JSON;not null"`

	// IssuedAt is taken from the iat claim of the issuer-signed JWT.
	IssuedAt datatypes.NullTime

	// ExpiresAt is taken from the exp claim of the issuer-signed JWT. Nil if the credential does not expire.
	ExpiresAt datatypes.NullTime

	// NotBefore is taken from the nbf claim of the issuer-signed JWT. Nil if the credential has no nbf restriction.
	// OID4VP wallets must not present a credential before this time.
	NotBefore datatypes.NullTime

	// BatchSize is the number of instances that were issued in this batch.
	BatchSize uint

	// RemainingCount tracks how many instances have not yet been used for a presentation.
	// Decremented on each use; the batch is exhausted when it reaches 0.
	RemainingCount uint

	CredentialMetadata *CredentialMetadata        `gorm:"constraint:OnDelete:CASCADE"`
	Instances          []IssuedCredentialInstance `gorm:"constraint:OnDelete:CASCADE"`
	IssuerDisplay      []IssuerMetadataDisplay    `gorm:"constraint:OnDelete:CASCADE"`
}

func (b *CredentialBatch) BeforeCreate(tx *gorm.DB) error {
	if b.ID.IsNil() {
		b.ID = datatypes.NewUUIDv4()
	}
	b.normalizeChildren()
	return b.validate()
}

func (b *CredentialBatch) normalizeChildren() {
	id := b.ID
	if b.CredentialMetadata != nil {
		b.CredentialMetadata.CredentialBatchID = &id
	}
	for i := range b.Instances {
		b.Instances[i].CredentialBatchID = &id
	}
	for i := range b.IssuerDisplay {
		b.IssuerDisplay[i].CredentialBatchID = &id
	}
}

func (b *CredentialBatch) validate() error {
	if b.VerifiableCredentialType == "" {
		return fmt.Errorf("verifiable_credential_type is required")
	}
	if b.IssuerIdentifier == "" {
		return fmt.Errorf("issuer_identifier is required")
	}
	if b.CredentialIssuerIdentifier == "" {
		return fmt.Errorf("credential_issuer_identifier is required")
	}
	if b.Format == "" {
		return fmt.Errorf("format is required")
	}
	if b.Hash == "" {
		return fmt.Errorf("hash is required")
	}
	if !b.IssuedAt.Valid {
		return fmt.Errorf("issued_at is required")
	}
	if b.BatchSize == 0 {
		return fmt.Errorf("batch_size must be at least 1")
	}
	if b.RemainingCount > b.BatchSize {
		return fmt.Errorf("remaining_count cannot exceed batch_size")
	}
	return nil
}

// IssuedCredentialInstance is a single raw SD-JWT VC token within a CredentialBatch.
// Each instance carries its own holder binding key, because the OID4VCI session creates
// one key pair per proof JWT in the batch credential request.
type IssuedCredentialInstance struct {
	ID datatypes.UUID

	// Foreign keys — exactly one is set: CredentialBatchID for the legacy flat
	// batch, FormatBindingID for the three-layer model (#685). Both are nullable
	// so the unused parent's FK column is NULL, which PRAGMA foreign_keys exempts.
	CredentialBatchID *datatypes.UUID
	FormatBindingID   *datatypes.UUID

	// HolderBindingKey is the key pair bound to this credential instance during issuance.
	// Nil if the credential configuration did not require cryptographic key binding.
	HolderBindingKey *HolderBindingKey `gorm:"constraint:OnDelete:CASCADE"`

	// RawCredential is the raw SD-JWT VC token (without key binding JWT).
	// The surrounding SQLCipher layer encrypts this at rest.
	RawCredential []byte `gorm:"type:bytea;not null"`

	// Used marks this instance as consumed after it has been presented.
	// Single-use batch wallets must not reuse an instance once Used is true.
	Used bool `gorm:"default:false"`

	// StatusListURI is the canonical URI from the credential's
	// `status.status_list.uri` claim, when present. Nil for credentials
	// that don't carry a Token Status List reference.
	StatusListURI *string

	// StatusListIdx is the bit-position into the referenced status
	// list. Nil iff StatusListURI is nil.
	StatusListIdx *uint64

	// LastKnownStatus is the most recently observed
	// statuslist.Status for this instance. 0 (StatusUnknown) is the
	// default for credentials that have not yet been checked, and
	// for credentials without a status_list reference.
	LastKnownStatus uint8 `gorm:"default:0"`

	// LastStatusCheckAt records the wall-clock time of the most
	// recent successful status check. Nil iff the instance has
	// never been checked.
	LastStatusCheckAt *time.Time
}

func (i *IssuedCredentialInstance) BeforeCreate(tx *gorm.DB) error {
	if i.ID.IsNil() {
		i.ID = datatypes.NewUUIDv4()
	}
	if i.HolderBindingKey != nil {
		if i.HolderBindingKey.IssuedCredentialInstanceID != nil && !i.HolderBindingKey.IssuedCredentialInstanceID.IsNil() {
			return fmt.Errorf("holder binding key %s is already bound to credential instance %s",
				i.HolderBindingKey.ID, *i.HolderBindingKey.IssuedCredentialInstanceID)
		}
		i.HolderBindingKey.IssuedCredentialInstanceID = &i.ID
	}
	return i.validate()
}

func (i *IssuedCredentialInstance) validate() error {
	batchUnset := i.CredentialBatchID == nil || i.CredentialBatchID.IsNil()
	bindingUnset := i.FormatBindingID == nil || i.FormatBindingID.IsNil()
	if batchUnset && bindingUnset {
		return fmt.Errorf("either batch_id or format_binding_id is required")
	}
	if len(i.RawCredential) == 0 {
		return fmt.Errorf("raw_credential is required")
	}
	return nil
}

// IssuerMetadataDisplay holds a single locale's display entry for an issuer,
// corresponding to one element of the top-level display[] array in issuer metadata.
type IssuerMetadataDisplay struct {
	ID datatypes.UUID

	// Foreign keys — exactly one is set: CredentialBatchID for the legacy flat
	// batch, FormatBindingID for the three-layer model (#685). Both nullable so
	// the unused FK column is NULL, which PRAGMA foreign_keys exempts.
	CredentialBatchID *datatypes.UUID
	FormatBindingID   *datatypes.UUID

	Name   string
	Locale datatypes.NullString

	// Logo fields are flattened from the logo sub-object.
	LogoURI     datatypes.NullString
	LogoAltText datatypes.NullString
}

func (d *IssuerMetadataDisplay) BeforeCreate(tx *gorm.DB) error {
	if d.ID.IsNil() {
		d.ID = datatypes.NewUUIDv4()
	}
	return nil
}

// CredentialMetadata represents one entry in the credential_configurations_supported map
// of the issuer metadata, keyed by credential_configuration_id.
type CredentialMetadata struct {
	ID datatypes.UUID

	// Exactly one FK is set: CredentialBatchID (legacy flat batch) or
	// FormatBindingID (three-layer model, #685). Both nullable so the unused FK
	// column is NULL, which PRAGMA foreign_keys exempts.
	CredentialBatchID *datatypes.UUID
	FormatBindingID   *datatypes.UUID

	Display []CredentialDisplay `gorm:"constraint:OnDelete:CASCADE"`
	Claims  []CredentialClaim   `gorm:"constraint:OnDelete:CASCADE"`
}

func (m *CredentialMetadata) BeforeCreate(tx *gorm.DB) error {
	if m.ID.IsNil() {
		m.ID = datatypes.NewUUIDv4()
	}
	return m.normalizeChildren()
}

func (m *CredentialMetadata) normalizeChildren() error {
	for i := range m.Display {
		m.Display[i].CredentialMetadataID = m.ID
	}
	for i := range m.Claims {
		m.Claims[i].CredentialMetadataID = m.ID
		if err := m.Claims[i].normalizeChildren(); err != nil {
			return fmt.Errorf("failed to normalize claim display children: %w", err)
		}
	}
	return nil
}

// CredentialDisplay holds a single locale's display entry for a credential type,
// corresponding to one element of the credential_metadata.display[] array.
type CredentialDisplay struct {
	ID datatypes.UUID

	// Foreign key
	CredentialMetadataID datatypes.UUID

	Name   string
	Locale datatypes.NullString

	// Logo fields are flattened from the logo sub-object.
	// TODO: should be nullable fields
	LogoURI     string
	LogoAltText string

	Description     string
	BackgroundColor string

	// BackgroundImageURI is flattened from the background_image sub-object.
	BackgroundImageURI     string
	BackgroundImageAltText string

	TextColor string
}

func (d *CredentialDisplay) BeforeCreate(tx *gorm.DB) error {
	if d.ID.IsNil() {
		d.ID = datatypes.NewUUIDv4()
	}
	return nil
}

// CredentialClaim represents one entry in the credential_metadata.claims[] array,
// describing a single claim path within the credential.
type CredentialClaim struct {
	ID datatypes.UUID

	// Foreign key
	CredentialMetadataID datatypes.UUID

	// Path is the dot-separated or JSON Pointer path to the claim within the credential.
	Path      datatypes.JSON `gorm:"type:JSON;not null"`
	Mandatory bool           `gorm:"default:false"`

	Display []ClaimDisplay `gorm:"constraint:OnDelete:CASCADE"`
}

func (c *CredentialClaim) BeforeCreate(tx *gorm.DB) error {
	if c.ID.IsNil() {
		c.ID = datatypes.NewUUIDv4()
	}
	if len(c.Path) == 0 {
		return fmt.Errorf("path is required")
	}
	return c.normalizeChildren()
}

func (c *CredentialClaim) normalizeChildren() error {
	for i := range c.Display {
		c.Display[i].CredentialClaimID = c.ID
	}
	return nil
}

// ClaimDisplay holds a single locale's display label for a credential claim.
type ClaimDisplay struct {
	ID datatypes.UUID

	// Foreign key
	CredentialClaimID datatypes.UUID

	Name   string
	Locale datatypes.NullString
}

func (d *ClaimDisplay) BeforeCreate(tx *gorm.DB) error {
	if d.ID.IsNil() {
		d.ID = datatypes.NewUUIDv4()
	}
	return nil
}

// ── Three-layer storage model (map #685, realizing #679) ─────────────────────
//
// The flat CredentialBatch above stores one securing format per row. The models
// below introduce the cross-format grouping decided in #679/#686: a
// LogicalCredential owner — keyed by the #686 content-hash identity — with a
// FormatBinding per securing format. They are added ADDITIVELY as the first step
// of the restructure: the store/read rewiring, the reparenting of
// IssuedCredentialInstance and the display children onto FormatBinding, the data
// migration off CredentialBatch, and CredentialBatch's eventual removal are
// later steps (see #685).

// LogicalCredential is the cross-format owner: one row per logical credential,
// grouping the FormatBindings that carry the same credential (same issuer, same
// content) in different securing formats (dc+sd-jwt / vc+sd-jwt / ldp_vc).
type LogicalCredential struct {
	ID datatypes.UUID

	// Identity is the data-model-agnostic grouping key from #686
	// (services.LogicalCredentialID): a hash over the issuer and the credential's
	// normalized content claims, deliberately excluding type/vct so copies in
	// different formats share it.
	Identity string `gorm:"uniqueIndex;not null"`

	// IssuerURL is shared across every format of the credential (the iss /
	// credential_issuer), so it lives on the owner rather than per format.
	IssuerURL string

	FormatBindings []FormatBinding `gorm:"constraint:OnDelete:CASCADE"`
}

func (c *LogicalCredential) BeforeCreate(tx *gorm.DB) error {
	if c.ID.IsNil() {
		c.ID = datatypes.NewUUIDv4()
	}
	c.normalizeChildren()
	return c.validate()
}

func (c *LogicalCredential) normalizeChildren() {
	for i := range c.FormatBindings {
		c.FormatBindings[i].LogicalCredentialID = c.ID
	}
}

func (c *LogicalCredential) validate() error {
	if c.Identity == "" {
		return fmt.Errorf("identity is required")
	}
	if c.IssuerURL == "" {
		return fmt.Errorf("issuer_url is required")
	}
	return nil
}

// FormatBinding is one securing format of a LogicalCredential: the decoded
// document/payload for that format plus its per-issuance metadata. It is unique
// per (LogicalCredential, Format). Display children and IssuedCredentialInstances
// attach here via nullable FormatBindingID FKs; the flat CredentialBatch keeps
// its own copies until the data migration (#685 step 2) retires it.
type FormatBinding struct {
	ID datatypes.UUID

	// LogicalCredentialID is the owning LogicalCredential; unique together with
	// Format — one binding per (logical credential, securing format).
	LogicalCredentialID datatypes.UUID `gorm:"uniqueIndex:idx_format_binding_logical_format"`

	// LogicalCredential is the owning row, loaded (Preload) when projecting a
	// binding back to the flat read model (CredentialBatch) for the credential
	// list; its IssuerURL is the credential's issuer identity.
	LogicalCredential *LogicalCredential

	// Format is the credential format identifier (dc+sd-jwt / vc+sd-jwt / ldp_vc).
	Format CredentialFormat `gorm:"uniqueIndex:idx_format_binding_logical_format"`

	// Hash is the per-format deterministic dedup/correlation key (type + sorted
	// disclosed content) — the same value the flat CredentialBatch stored. It
	// stays the wallet-facing credential id and the Token Status List correlation
	// key, so the read projection keeps exposing it unchanged.
	Hash string `gorm:"index"`

	// CredentialIssuerIdentifier is the OID4VCI credential_issuer (the offer's
	// issuer), distinct from LogicalCredential.IssuerURL (the credential's iss).
	CredentialIssuerIdentifier string

	// TypeLabel is the per-format type identifier: the `vct` for an IETF SD-JWT
	// VC, or the @context+type composite for a VCDM credential.
	TypeLabel string

	// ProcessedPayload is the decoded/disclosed document for this format.
	ProcessedPayload datatypes.JSON `gorm:"type:JSON;not null"`

	// IssuedAt/ExpiresAt/NotBefore and the batch counts are per format, since
	// each format is issued in its own OpenID4VCI exchange.
	IssuedAt  datatypes.NullTime
	ExpiresAt datatypes.NullTime
	NotBefore datatypes.NullTime

	BatchSize      uint
	RemainingCount uint

	// Children reparented from CredentialBatch (#685 step 2). They carry a
	// nullable FormatBindingID; the flat CredentialBatch keeps its own copies
	// until the data migration retires it.
	Instances          []IssuedCredentialInstance `gorm:"constraint:OnDelete:CASCADE"`
	IssuerDisplay      []IssuerMetadataDisplay    `gorm:"constraint:OnDelete:CASCADE"`
	CredentialMetadata *CredentialMetadata        `gorm:"constraint:OnDelete:CASCADE"`
}

func (f *FormatBinding) BeforeCreate(tx *gorm.DB) error {
	if f.ID.IsNil() {
		f.ID = datatypes.NewUUIDv4()
	}
	f.normalizeChildren()
	return f.validate()
}

// normalizeChildren stamps this binding's ID onto the FormatBindingID FK of its
// reparented children, mirroring CredentialBatch.normalizeChildren for the
// three-layer model.
func (f *FormatBinding) normalizeChildren() {
	id := f.ID
	for i := range f.Instances {
		f.Instances[i].FormatBindingID = &id
	}
	for i := range f.IssuerDisplay {
		f.IssuerDisplay[i].FormatBindingID = &id
	}
	if f.CredentialMetadata != nil {
		f.CredentialMetadata.FormatBindingID = &id
	}
}

func (f *FormatBinding) validate() error {
	if f.Format == "" {
		return fmt.Errorf("format is required")
	}
	if len(f.ProcessedPayload) == 0 {
		return fmt.Errorf("processed_payload is required")
	}
	if f.BatchSize == 0 {
		return fmt.Errorf("batch_size must be at least 1")
	}
	if f.RemainingCount > f.BatchSize {
		return fmt.Errorf("remaining_count cannot exceed batch_size")
	}
	return nil
}
