package services

import (
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// ParsedCredential is the generic, format-agnostic result of parsing and
// cryptographically verifying one freshly issued credential's raw wire
// representation (the OID4VCI CredentialResponse's "credential" string),
// before it is shown to the user or persisted. It carries exactly the
// information buildOfferedCredentials (display) and
// VerifyAndStoreIssuedCredentials (storage) need, without either of them
// depending on a specific credential format.
type ParsedCredential struct {
	Format models.CredentialFormat

	// VerifiableCredentialType is the vct claim (dc+sd-jwt) or the ISO
	// 18013-5 docType (mso_mdoc).
	VerifiableCredentialType string

	// IssuerURL is the iss claim (dc+sd-jwt) or the credential_issuer used
	// at issuance (mso_mdoc, which has no iss claim of its own).
	IssuerURL string

	// ResolvedClaims is the JSON-encoded claims to cache into
	// models.CredentialBatch.ProcessedSdJwtPayload — misleadingly named on the
	// model for a schema reason documented there, and format-dependent in the
	// same way this field is: the processed SD-JWT payload for dc+sd-jwt, or a
	// namespace -> elementIdentifier -> value map for mso_mdoc (the shape
	// eudi/openid4vp/mdoc_dcql already expects to read).
	ResolvedClaims []byte

	// RawCredentialBytes is persisted verbatim into
	// models.IssuedCredentialInstance.RawCredential.
	RawCredentialBytes []byte

	// IssuedAt, ExpiresAt, and NotBefore are unix-second timestamps, nil
	// when the format/credential does not carry that claim.
	IssuedAt  *int64
	ExpiresAt *int64
	NotBefore *int64

	// HolderBindingKeyThumbprint is the hex SHA-256 JWK thumbprint of the
	// holder-binding public key this credential embeds/confirms, used by
	// matchAllHolderBindingKeys for formats with no cnf claim (mso_mdoc).
	// Left nil for dc+sd-jwt, which matches via SdJwtVc.IssuerSignedJwtPayload.Confirm
	// instead.
	HolderBindingKeyThumbprint *string

	// HolderBindingKeyDidUrl mirrors HolderBindingKeyThumbprint for
	// DID-based holder bindings. mso_mdoc never sets this today (no DID
	// concept), but the field exists so matchHolderBindingKeyByIdentifiers
	// can support it symmetrically with the SD-JWT path.
	HolderBindingKeyDidUrl *string

	// SdJwtVc is set only when Format == models.CredentialFormatSdJwtVc.
	// It is the escape hatch that lets every existing SD-JWT-specific code
	// path (VCT integrity checking, cnf-based key matching, attribute
	// flattening) keep operating on the exact type it always has, reached
	// through this field instead of a bare slice element. nil for every
	// other format.
	SdJwtVc *sdjwtvc.VerifiedSdJwtVc
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

// CredentialFormatParsers is a format -> parser registry, built once at
// client-construction time and threaded into each openid4vci session.
type CredentialFormatParsers map[models.CredentialFormat]CredentialFormatParser
