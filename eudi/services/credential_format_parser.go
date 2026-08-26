package services

import (
	"crypto/ecdsa"

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

	// IssuerIdentifier is the issuer identity the credential itself asserts and
	// was verified against: the `iss` claim, or the subject of the x5c end-entity
	// certificate when `iss` is absent (dc+sd-jwt, SD-JWT VC §2.2.2.3); the
	// credential_issuer used at issuance for mso_mdoc, which has no iss claim of
	// its own. Distinct from CredentialBatch.CredentialIssuerIdentifier, which is
	// the issuer the wallet went to according to the Credential Offer.
	IssuerIdentifier string

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

	// HolderBindingKeyPublicKey is the holder-binding public key itself, for
	// formats that embed a bare key rather than a cnf claim (mso_mdoc embeds a
	// COSE_Key in the MSO's deviceKeyInfo).
	//
	// It exists because a thumbprint alone cannot always find the stored key.
	// models.HolderBindingKey identifies a key by PublicKeyThumbprint *or*
	// DidUrl, never both, and which one it gets is decided by the proof:
	// keybinder_service records the DID from the proof JWT's kid when the
	// credential configuration's binding method is did:key or did:jwk, and only
	// falls back to a thumbprint otherwise. A format that reports just a
	// thumbprint therefore cannot be matched at all against a DID-bound key, and
	// issuance failed outright with "no matching holder binding key found".
	//
	// Both DID forms are derivable from the public key — see
	// holderBindingKeyIdentifiers — so carrying the key lets the matcher try
	// every identifier the wallet could have stored, without the parser having to
	// know which binding method was negotiated.
	HolderBindingKeyPublicKey *ecdsa.PublicKey

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
