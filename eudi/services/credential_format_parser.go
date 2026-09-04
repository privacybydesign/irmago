package services

import (
	"crypto/ecdsa"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// ParsedCredential is the generic, format-agnostic result of parsing and
// cryptographically verifying one freshly issued credential's raw wire
// representation (the OID4VCI CredentialResponse's "credential" string),
// before it is shown to the user or persisted.
//
// The generic fields are what the OpenID4VCI session needs regardless of
// format: to name the credential, to bind it to its configuration, and to show
// it on the offer screen. Everything a format's own store needs to persist it
// lives behind one typed escape hatch per format — SdJwtVc or Mdoc, exactly
// one of which is set — so no format's data has to be flattened into bytes to
// cross this seam and re-parsed on the other side.
type ParsedCredential struct {
	Format models.CredentialFormat

	// VerifiableCredentialType is the vct claim (dc+sd-jwt) or the ISO
	// 18013-5 docType (mso_mdoc).
	VerifiableCredentialType string

	// IssuerIdentifier is the issuer identity the credential itself asserts and
	// was verified against: the `iss` claim, or the subject of the x5c end-entity
	// certificate when `iss` is absent (dc+sd-jwt, SD-JWT VC §2.2.2.3); the
	// credential_issuer used at issuance for mso_mdoc, which has no iss claim of
	// its own.
	IssuerIdentifier string

	// RawCredentialBytes is the credential as issued, minus what the holder
	// re-creates per presentation: the SD-JWT VC without its key binding JWT, or
	// the CBOR of docType plus IssuerSigned without DeviceSigned. Persisted
	// verbatim by the format's store.
	RawCredentialBytes []byte

	// IssuedAt, ExpiresAt, and NotBefore are unix-second timestamps, nil
	// when the format/credential does not carry that claim. For mso_mdoc all
	// three are set, from the MSO's mandatory validityInfo.
	IssuedAt  *int64
	ExpiresAt *int64
	NotBefore *int64

	// SdJwtVc is set only when Format == models.CredentialFormatSdJwtVc.
	SdJwtVc *sdjwtvc.VerifiedSdJwtVc

	// Mdoc is set only when Format == models.CredentialFormatMsoMdoc.
	Mdoc *ParsedMdoc
}

// ParsedMdoc is what verifying an mso_mdoc yields beyond the generic fields:
// the typed inputs the mdoc store persists and the session displays.
type ParsedMdoc struct {
	// DocType is the document type from the signed MSO.
	DocType string

	// Namespaces holds the element values, namespace → elementIdentifier →
	// value, after NormalizeMdocClaimValues has made them JSON-safe and
	// JSONShapedMdocNamespaces has given them the types they will have when read
	// back from storage.
	Namespaces models.MdocNamespaces

	// ValidityInfo is the MSO's validity window: signed, validFrom, validUntil.
	ValidityInfo mdoc.ValidityInfo

	// DeviceKey is the device public key the issuer bound into the MSO's
	// deviceKeyInfo, nil when the document carries none. DeviceKeyThumbprint is
	// its hex SHA-256 JWK thumbprint, the identity mdoc device keys are stored
	// and looked up under; "" when DeviceKey is nil.
	DeviceKey           *ecdsa.PublicKey
	DeviceKeyThumbprint string
}

// CredentialFormatParser parses and cryptographically verifies one raw
// issued credential string for a single credential format.
type CredentialFormatParser interface {
	// ParseAndVerify verifies raw (the wire "credential" string from the
	// OID4VCI CredentialResponse) and extracts its claims/metadata.
	// credentialIssuer is the credential_issuer from the issuer metadata,
	// needed by formats (mso_mdoc) that have no iss claim of their own.
	// holderBindingKeyRequired lets an implementation validate that its
	// format's own binding mechanism (cnf claim / embedded deviceKey) is
	// present when the credential configuration required cryptographic
	// key binding.
	ParseAndVerify(raw, credentialIssuer string, holderBindingKeyRequired bool) (*ParsedCredential, error)

	// CheckBatchUniqueness validates cross-instance invariants across one
	// full batch of credentials issued from a single credential request
	// (e.g. rejecting a repeated holder-binding key within the batch).
	CheckBatchUniqueness(batch []*ParsedCredential) error
}

// CredentialFormatParsers is a format -> parser registry.
type CredentialFormatParsers map[models.CredentialFormat]CredentialFormatParser
