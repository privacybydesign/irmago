package services

import (
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"gorm.io/gorm"
)

// Each credential format owns its storage end to end: its tables,
// its models, its key table and its persistence path. This file is where the
// formats meet. A CredentialFormatSupport bundles everything the OpenID4VCI
// session and the wallet client need from one format, and CredentialFormats is
// the registry they dispatch on. Nothing here knows how either format stores
// anything; it only knows which one to ask.

// CredentialFormatStore is one format's persistence and read side.
type CredentialFormatStore interface {
	// Store verifies the holder key bindings of freshly issued credentials of
	// this format and persists them as one batch, replacing a stored batch with
	// the same content identity when that batch is no longer presentable.
	Store(
		parsedCredentials []*ParsedCredential,
		credentialConfigurationId string,
		issuerMetadata metadata.CredentialIssuerMetadata,
		requireCryptographicKeyBinding bool,
		publicKeyIdentifiers []models.PublicHolderBindingKey,
	) error

	// List renders every stored credential of this format for the app.
	List() ([]*clientmodels.Credential, error)

	// DeleteByHash deletes the stored batch with the given content hash.
	// Returns db.ErrNotFound if none matches.
	DeleteByHash(hash string) error

	CredentialDisplaySource
}

// CredentialDisplaySource is the part of a format's read side that needs only
// the database: what the activity log and the logo backfill consult across all
// stored credentials of the format.
type CredentialDisplaySource interface {
	// LiveDisplaysByType resolves, per stored credential type (vct or docType),
	// the display text the locale gives it, preferring a batch that carries
	// credential metadata when several share a type.
	LiveDisplaysByType(locale string) map[string]ResolvedBatchDisplay

	// LogoURIs returns, per stored batch, the issuer and credential logo URIs
	// that resolve for the locale; "" where a batch has none.
	LogoURIs(locale string) (issuer []string, credential []string)
}

// CredentialFormatSupport is everything one format contributes: how to verify
// its credentials, how to mint the keys they are bound to, and where to keep
// them.
type CredentialFormatSupport struct {
	Parser CredentialFormatParser
	Keys   HolderKeyBinder
	Store  CredentialFormatStore
}

// CredentialFormats is the format → support registry the OpenID4VCI session
// and the wallet client dispatch on. Built once, by NewCredentialFormats.
type CredentialFormats map[models.CredentialFormat]CredentialFormatSupport

// NewCredentialFormats builds the registry for every format this wallet
// supports, from the ingredients the formats share: the database the stores
// live in, the file storage that holds logos, the issuer trust configuration,
// the SD-JWT holder verifier, the revocation service, and the current locale.
//
// Derived in one place on purpose. A registry assembled at the call site can
// be wired inconsistently or lose an entry in a merge with no compile error,
// which has happened; a session then fails at runtime with "no credential
// format registered". TestNewCredentialFormatsRegistersEveryFormat pins the set.
//
// mso_mdoc's IACA trust anchors are taken from the same issuer trust model that
// backs SD-JWT x5c validation. That assumes one shared PKI, which holds for the
// current setup but is a deliberate simplification, not a general truth. The
// model is passed as a live lookup, not as the pool it currently holds: the
// trust models are rebuilt whenever developer mode is toggled, and the registry
// outlives that.
func NewCredentialFormats(
	config *eudi.Configuration,
	holderVerifier *sdjwtvc.HolderVerificationProcessor,
	d *gorm.DB,
	fs filesystem.FileSystemStorage,
	revocation *RevocationService,
	currentLocale *clientmodels.CurrentLocale,
) CredentialFormats {
	sdJwtVcStore := db.NewSdJwtVcStore(d)
	mdocStore := db.NewMdocStore(d)
	mdocKeys := db.NewMdocDeviceKeyStore(d)

	return CredentialFormats{
		models.CredentialFormatSdJwtVc: {
			Parser: NewSdJwtVcCredentialFormatParser(holderVerifier),
			Keys:   NewHolderBindingKeyService(d),
			Store:  NewSdJwtVcCredentialService(sdJwtVcStore, db.NewHolderBindingKeyStore(d), fs, revocation, currentLocale),
		},
		models.CredentialFormatMsoMdoc: {
			Parser: NewMdocCredentialFormatParser(mdoc.NewVerifierFromTrustSource(&config.Issuers)),
			Keys:   NewMdocKeyService(mdocKeys),
			Store:  NewMdocCredentialService(mdocStore, mdocKeys, fs, currentLocale),
		},
	}
}

// NewCredentialDisplaySources returns the read side of every format over the
// given database, for callers that only render stored credentials (the
// activity log, the logo backfill) and need none of the rest of the registry.
// Kept next to NewCredentialFormats so the two format lists cannot drift
// apart; TestNewCredentialFormatsRegistersEveryFormat compares them.
func NewCredentialDisplaySources(d *gorm.DB) []CredentialDisplaySource {
	return []CredentialDisplaySource{
		newSdJwtVcDisplaySource(db.NewSdJwtVcStore(d)),
		newMdocDisplaySource(db.NewMdocStore(d)),
	}
}

// --- helpers every format's store uses ---

// batchInstanceCounts is the per-format remaining-instance map the app reads.
// A batch of one is a reusable credential with no count to spend down, so it
// reports nil rather than 1; remaining points into the batch so the value is
// the stored one.
func batchInstanceCounts(format models.CredentialFormat, batchSize uint, remaining *uint) map[clientmodels.CredentialFormat]*uint {
	f := clientmodels.CredentialFormat(format)
	if batchSize <= 1 {
		return map[clientmodels.CredentialFormat]*uint{f: nil}
	}
	return map[clientmodels.CredentialFormat]*uint{f: remaining}
}

// missingDisplayMetadataReason explains why a credential stored against this
// configuration will have no display text, or returns "" when the configuration
// carries display metadata.
//
// The reasons are distinct problems with distinct fixes, which is why they are
// worth telling apart rather than reporting as one "no display" case:
//   - the configuration is absent, so the offer's credential_configuration_id does
//     not match any key the issuer advertises;
//   - the configuration carries no display metadata in either placement — neither
//     the nested credential_metadata of OID4VCI v1.0 nor the older drafts' display
//     and claims on the configuration itself, both of which
//     metadata.CredentialConfiguration.UnmarshalJSON now normalises into the
//     nested shape;
//   - the metadata is present but empty, so the issuer genuinely advertises no
//     display text (or no per-claim text, which costs the attribute labels rather
//     than the credential name).
func missingDisplayMetadataReason(configID string, config metadata.CredentialConfiguration, configFound bool) string {
	switch {
	case !configFound:
		return fmt.Sprintf("the issuer advertises no credential configuration %q", configID)
	case config.CredentialMetadata == nil:
		return fmt.Sprintf("configuration %q carries no display metadata, in neither credential_metadata nor the older drafts' display/claims on the configuration itself", configID)
	case len(config.CredentialMetadata.Display) == 0:
		return fmt.Sprintf("configuration %q carries credential_metadata with no display entries", configID)
	case len(config.CredentialMetadata.Claims) == 0:
		return fmt.Sprintf("configuration %q carries no claims, so its attributes will render without labels", configID)
	default:
		return ""
	}
}
