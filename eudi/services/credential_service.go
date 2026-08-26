package services

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/privacybydesign/irmago/eudi/didkey"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"gorm.io/datatypes"
)

// CredentialService stores verified credentials and their associated holder binding keys
// in a single atomic transaction.
type CredentialService interface {
	GetCredentialMetadataList() ([]*clientmodels.Credential, error)
	VerifyAndStoreIssuedCredentials(
		parsedCredentials []*ParsedCredential,
		credentialConfigurationId string,
		metadata metadata.CredentialIssuerMetadata,
		requireCryptographicKeyBinding bool,
		publicKeyIdentifiers []models.PublicHolderBindingKey,
	) error

	// DeleteByHash deletes a stored CredentialBatch by its deterministic hash.
	// Returns ErrNotFound if no batch exists with that hash.
	DeleteByHash(hash string) error
}

type credentialService struct {
	credentialStore       db.CredentialStore
	holderBindingKeyStore db.HolderBindingKeyStore
	fileStorage           filesystem.FileSystemStorage
	// revocation supplies the per-batch revocation flags for the credential
	// list view (see GetCredentialMetadataList).
	revocation *RevocationService
	// currentLocale is read on every call, not snapshotted, so a SetLocale in
	// between two list calls is reflected without rebuilding the service.
	currentLocale *clientmodels.CurrentLocale
}

func NewCredentialService(
	credentialStore db.CredentialStore,
	holderBindingKeyStore db.HolderBindingKeyStore,
	fileStorage filesystem.FileSystemStorage,
	revocation *RevocationService,
	currentLocale *clientmodels.CurrentLocale,
) CredentialService {
	return &credentialService{
		credentialStore:       credentialStore,
		holderBindingKeyStore: holderBindingKeyStore,
		fileStorage:           fileStorage,
		revocation:            revocation,
		currentLocale:         currentLocale,
	}
}

func (s *credentialService) DeleteByHash(hash string) error {
	return s.credentialStore.DeleteBatchByHash(hash)
}

func (s *credentialService) GetCredentialMetadataList() ([]*clientmodels.Credential, error) {
	m, err := s.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, err
	}

	// Per-credential revocation flags are derived from stored Token Status List
	// statuses (maintained by RevocationService.RefreshStatuses).
	revoked, revocable, err := s.revocation.BatchRevocation()
	if err != nil {
		return nil, err
	}

	locale := s.currentLocale.Get()

	// Convert storage models to client models
	clientModels := make([]*clientmodels.Credential, 0, len(m))
	for _, batch := range m {
		var processedSdJwtPayload *sdjwt.ProcessedPayload
		if err := json.Unmarshal(batch.ProcessedSdJwtPayload, &processedSdJwtPayload); err != nil {
			processedSdJwtPayload = nil // fallback to nil if unmarshalling fails
		}

		display := ResolveBatchDisplay(batch, locale)
		issuerName := display.IssuerName
		// Fall back to the credential type identifier — the vct for SD-JWT VC, the
		// docType for mdoc, both held in this one column — when the issuer published
		// no display text this locale can resolve. Both DCQL handlers already do
		// exactly this (mdoc_dcql and eudi_sdjwt_dcql credentialDisplayName), so
		// without it the same credential shows as a blank row in this list while the
		// consent screen names it.
		//
		// Applied here rather than inside ResolveBatchDisplay on purpose: the log
		// service reads the same resolver and treats an empty CredentialName as "the
		// live credential has no name to re-resolve", keeping the text it snapshotted
		// at disclosure. A fallback in there would let a type identifier overwrite a
		// snapshotted display name.
		credentialName := display.CredentialName
		if credentialName == "" {
			credentialName = batch.VerifiableCredentialType
		}

		attrs := BuildAttributesFromPayload(processedSdJwtPayload, display.ClaimNames, display.ClaimOrder)

		var iat, exp *int64
		if batch.ExpiresAt.Valid {
			x := batch.ExpiresAt.V.Unix()
			exp = &x
		}
		if batch.IssuedAt.Valid {
			x := batch.IssuedAt.V.Unix()
			iat = &x
		}

		// Load the logo that resolves for the current locale from filesystem
		// storage. The logo falls back across languages independently of the
		// text, so a logo shows whenever any display carries one.
		credentialLogoManager := s.fileStorage.Credentials().LogoManager()
		issuerLogoManager := s.fileStorage.Issuers().LogoManager()

		issuerImage := LoadResolvedLogo(issuerLogoManager, IssuerLogoURIsByLanguage(batch.IssuerDisplay), locale)

		var credentialImage *clientmodels.Image
		if batch.CredentialMetadata != nil {
			credentialImage = LoadResolvedLogo(credentialLogoManager, CredentialLogoURIsByLanguage(batch.CredentialMetadata.Display), locale)
		}

		clientModels = append(clientModels, &clientmodels.Credential{
			CredentialId:      batch.VerifiableCredentialType,
			Hash:              batch.Hash,
			Image:             credentialImage,
			Name:              credentialName,
			DisplayIsFallback: display.DisplayIsFallback,
			Issuer: clientmodels.TrustedParty{
				Id:     batch.CredentialIssuerIdentifier,
				Name:   issuerName,
				Image:  issuerImage,
				Url:    nil,
				Parent: nil,
				// Was false for every credential, unconditionally, which said the
				// opposite of what is true of all of them: the wallet refuses to
				// store a credential whose issuer it cannot authenticate, so a
				// stored batch is by construction one whose chain verified.
				Verified: batch.IssuerVerified,
			},
			CredentialInstanceIds: map[clientmodels.CredentialFormat]string{
				clientmodels.CredentialFormat(batch.Format): batch.Hash,
			},
			BatchInstanceCountsRemaining: batchInstanceCountsRemaining(batch),
			Attributes:                   attrs,
			ExpiryDate:                   exp,
			IssuanceDate:                 iat,
			Revoked:                      revoked[batch.Hash],
			RevocationSupported:          revocable[batch.Hash],
			IssueURL:                     nil, // TODO: add issue URL to storage model so this can be filled in here
		})
	}

	return clientModels, nil
}

// batchInstanceCountsRemaining returns the remaining instance count map for a credential batch.
// For batch size 1, the single instance is infinitely reusable, so the count is nil (unlimited).
func batchInstanceCountsRemaining(batch *models.CredentialBatch) map[clientmodels.CredentialFormat]*uint {
	format := clientmodels.CredentialFormat(batch.Format)
	if batch.BatchSize <= 1 {
		return map[clientmodels.CredentialFormat]*uint{format: nil}
	}
	return map[clientmodels.CredentialFormat]*uint{format: &batch.RemainingCount}
}

// StoreIssuedCredentials builds a CredentialBatch from the supplied parsed credentials and
// metadata, then persists the batch and all its instances in one transaction.
//
// keyModels must either be empty (no cryptographic key binding required) or have exactly the same length as
// parsedCredentials (one key per instance). All credentials in the slice are assumed to have been
// issued from the same credential_configuration_id and therefore share their type, issuer, and timing claims.
func (s *credentialService) VerifyAndStoreIssuedCredentials(
	parsedCredentials []*ParsedCredential,
	credentialConfigurationId string,
	issuerMetadata metadata.CredentialIssuerMetadata,
	requireCryptographicKeyBinding bool,
	publicKeyIdentifiers []models.PublicHolderBindingKey,
) error {
	if len(parsedCredentials) == 0 {
		return nil // nothing to store
	}

	// A batch's instances are the same logical credential and are revoked
	// together. Per draft-ietf-oauth-status-list §13.2 each one-time-use copy
	// MUST carry its OWN dedicated, distinct status entry (for unlinkability):
	// require all-or-none presence and reject duplicate references. Reject here,
	// before any side effects, so a malformed issuance can't delete the user's
	// existing credential (computeHashAndDeleteExisting below is destructive).
	if err := validateStatusReferences(parsedCredentials); err != nil {
		if requireCryptographicKeyBinding {
			s.deleteOrphanedKeys(publicKeyIdentifiers)
		}
		return err
	}

	if requireCryptographicKeyBinding && len(publicKeyIdentifiers) != len(parsedCredentials) {
		return fmt.Errorf(
			"publicKeyIdentifiers length (%d) must equal parsedCredentials length (%d) when cryptographic key binding is used",
			len(publicKeyIdentifiers), len(parsedCredentials),
		)
	}

	// Match all holder binding keys upfront before any side effects, so that a
	// mismatch aborts the issuance without deleting the user's existing batch.
	var matchedKeyIDs []datatypes.UUID
	if requireCryptographicKeyBinding {
		var err error
		matchedKeyIDs, err = matchAllHolderBindingKeys(parsedCredentials, publicKeyIdentifiers)
		if err != nil {
			s.deleteOrphanedKeys(publicKeyIdentifiers)
			return err
		}
	}

	// All instances in a batch share the same type, issuer, and timing claims.
	// Use the first credential as the source of truth for batch-level metadata.
	first := parsedCredentials[0]

	hash, err := s.computeHashAndDeleteExisting(first)
	if err != nil {
		return err
	}

	// Absent configuration is tolerated: everything read from it below is display
	// metadata, which degrades to empty rather than making a verified credential
	// unstorable. The batch's Format deliberately does not come from here — see
	// below.
	credentialConfiguration, credentialConfigurationFound := issuerMetadata.CredentialConfigurationsSupported[credentialConfigurationId]

	// Say so when the credential is going to have no display text. Without this the
	// degradation above is entirely silent: the wallet renders the raw vct/docType
	// in its place, and nothing records whether the issuer's metadata lacked the
	// configuration, lacked credential_metadata within it, or carried no display
	// entries — three issuer-side causes that look identical from the app.
	if reason := missingDisplayMetadataReason(credentialConfigurationId, credentialConfiguration, credentialConfigurationFound); reason != "" {
		eudi.Logger.Warnf("credential from issuer %q will render as its raw type %q: %s", first.IssuerIdentifier, first.VerifiableCredentialType, reason)
	}

	batch := &models.CredentialBatch{
		IssuerIdentifier:         first.IssuerIdentifier,
		VerifiableCredentialType: first.VerifiableCredentialType,
		// The format of the credential that was actually parsed and verified, not
		// the one the issuer's metadata advertises. The two normally agree — the
		// advertised format is what selected this parser — but the metadata is an
		// unverified claim, and the map index above yields a zero-valued
		// configuration when credentialConfigurationId is absent from it. That
		// silently stored the batch with an empty Format, which every later
		// format-keyed read then misses: GetBatchesByDocType finds nothing, and the
		// DCQL handlers dispatch on format to decide who owns a credential.
		Format:                first.Format,
		Hash:                  hash,
		ProcessedSdJwtPayload: datatypes.JSON(first.ResolvedClaims),
		// Reaching this point means the issuer was authenticated. Every credential
		// here came from CredentialFormatParser.ParseAndVerify, which returns an
		// error rather than a ParsedCredential when the signature or the chain to a
		// trust anchor does not hold, so an unauthenticated issuer never gets as far
		// as a batch. Recording it here, at the one place where that is guaranteed,
		// avoids a per-parser flag that a new format could silently forget to set.
		IssuerVerified: true,
		// From the Credential Offer rather than from the credential, which is the
		// distinction master drew when it split these two fields: IssuerIdentifier
		// is the identity the credential itself asserts and was verified against,
		// CredentialIssuerIdentifier is the issuer the wallet went to.
		CredentialIssuerIdentifier: issuerMetadata.CredentialIssuer,
		IssuerDisplay:              slices.Collect(issuerMetadata.Display.ToStorageModelIterator()),
		CredentialMetadata:         convertCredentialMetadata(credentialConfiguration),
		BatchSize:                  uint(len(parsedCredentials)),
		RemainingCount:             uint(len(parsedCredentials)),
		Instances:                  buildInstances(parsedCredentials),
	}

	if first.IssuedAt != nil {
		batch.IssuedAt = datatypes.NullTime{V: time.Unix(*first.IssuedAt, 0), Valid: true}
	}
	if first.ExpiresAt != nil {
		batch.ExpiresAt = datatypes.NullTime{V: time.Unix(*first.ExpiresAt, 0), Valid: true}
	}
	if first.NotBefore != nil {
		batch.NotBefore = datatypes.NullTime{V: time.Unix(*first.NotBefore, 0), Valid: true}
	}

	if err := s.credentialStore.StoreBatch(batch); err != nil {
		return err
	}

	if requireCryptographicKeyBinding {
		s.linkHolderBindingKeys(matchedKeyIDs, batch.Instances)
	}

	return nil
}

func (s *credentialService) computeHashAndDeleteExisting(p *ParsedCredential) (string, error) {
	var hash string
	var err error
	if p.SdJwtVc != nil {
		hash, err = hashForSdJwtVc(p.VerifiableCredentialType, p.IssuerIdentifier, p.ResolvedClaims)
	} else {
		hash, err = hashGeneric(p.VerifiableCredentialType, p.IssuerIdentifier, p.ResolvedClaims)
	}
	if err != nil {
		return "", fmt.Errorf("failed to compute credential hash: %w", err)
	}

	// A matching hash means the wallet already holds this credential: the hash
	// covers the credential type and its sorted claims, so re-issuing identical
	// attributes lands here.
	//
	// Note what the hash does *not* cover: the issuer. hashGeneric and
	// hashForSdJwtVc take the credential type and the resolved claims and nothing
	// else, so two different issuers minting the same type with the same claims
	// collide here and the second is refused as a duplicate of the first. That is
	// a property of the hash rather than of this check, and it predates it --
	// Hash is a unique index, so the storage layer could not hold both regardless.
	// Changing it means putting the issuer in the hash, which rewrites every
	// existing hash and breaks the deliberate compatibility with
	// irmaclient.CreateHashForSdJwtVc. The message below therefore names the
	// stored copy's issuer as information, and does not claim the issuers were
	// compared.
	//
	// Whether that is a duplicate worth refusing or a renewal worth accepting
	// depends on the batch already stored, which is why this is not a flat
	// rejection. Replacing a batch is destructive -- DeleteBatch cascades to the
	// instances and through them to the holder binding keys -- so replacing one
	// the wallet can still present throws away usable single-use attestations to
	// gain nothing but fresher timestamps.
	//
	// Refusing unconditionally would be worse, because attributes are exactly
	// what does not change on renewal. An age-verification credential asserts
	// age_over_18=true for as long as it exists, so every legitimate renewal --
	// batch spent, expiry approaching, new device keys wanted -- carries the same
	// claims and arrives with this same hash. A wallet that refused them all
	// could never top up a spent batch and would go permanently unpresentable.
	//
	// So: refuse while the stored batch is still usable, replace once it is not.
	if existing, err := s.credentialStore.GetBatchByHash(hash); err == nil {
		if reason := batchStillUsable(existing, time.Now()); reason != "" {
			return "", fmt.Errorf(
				"credential %q is already held (stored copy issued by %q) and %s; re-issuing identical claims would replace it and discard its unused instances",
				existing.VerifiableCredentialType, existing.CredentialIssuerIdentifier, reason)
		}
		if err := s.credentialStore.DeleteBatch(existing.ID); err != nil {
			return "", fmt.Errorf("failed to delete existing batch before re-issuance: %w", err)
		}
	}

	return hash, nil
}

// batchStillUsable reports why a stored batch has unspent instances worth
// keeping, or "" when the batch may be replaced by a new issuance.
//
// Only batched credentials are protected. What re-issuance destroys, and the
// whole reason to refuse it, is unspent single-use attestations: a batch of
// thirty that the holder has used twice still has twenty-eight presentations in
// it, and replacing it to gain fresher timestamps throws those away.
//
// A batch of one has nothing to throw away. It is a reusable credential, so
// re-issuing it is simply how it gets refreshed -- a new expiry, a new holder
// binding key -- and replacing it costs the holder nothing. Refusing there would
// block refresh for the credential's entire validity period, since "still
// usable" is true of a reusable credential from issuance until expiry; the holder
// would have to delete it first to obtain a new one. That is why BatchSize <= 1
// is replaceable rather than protected, and it is what keeps ordinary SD-JWT
// re-issuance working as it did.
//
// The remaining conditions mirror what dcql.FindCandidates applies when deciding
// whether a batch may answer a query, and they are taken from there on purpose:
// if this drifted, the wallet would either refuse a re-issuance it needs (having
// judged usable a batch no query will accept) or discard one it could still
// present. dcql.IsBatchValid is called rather than re-derived for the same
// reason. Note dcql treats a batch of one as never exhausted, the same rule
// BatchInstanceCountRemaining encodes by returning nil there -- so consulting
// RemainingCount for it would be meaningless as well as harmful.
func batchStillUsable(batch *models.CredentialBatch, now time.Time) string {
	if batch.BatchSize <= 1 {
		return ""
	}
	if !dcql.IsBatchValid(batch, now) {
		return ""
	}
	if batch.RemainingCount == 0 {
		return ""
	}
	return fmt.Sprintf("still has %d of %d instances unused", batch.RemainingCount, batch.BatchSize)
}

// statusReferenceOf returns the credential's Token Status List reference, or
// the zero Reference when it carries none. The zero value (empty URI) is a
// safe "absent" sentinel because a real reference always has a non-empty URI.
// Token Status List is an SD-JWT-specific concept (the status claim lives in
// IssuerSignedJwtPayload); other formats (mso_mdoc) never carry one.
func statusReferenceOf(p *ParsedCredential) statuslist.Reference {
	if p.SdJwtVc == nil || p.SdJwtVc.IssuerSignedJwtPayload.Status == nil || p.SdJwtVc.IssuerSignedJwtPayload.Status.StatusList == nil {
		return statuslist.Reference{}
	}
	return *p.SdJwtVc.IssuerSignedJwtPayload.Status.StatusList
}

// validateStatusReferences enforces the batch's Token Status List invariants from
// draft-ietf-oauth-status-list §13.2/§13.3:
//   - all-or-none: either every instance carries a status_list reference or none
//     does (a partially-referenced batch would leave some instances
//     status-checkable and others not);
//   - uniqueness: each reference MUST be distinct across the batch. Every
//     one-time-use copy needs its own dedicated (uri, idx) entry so presentations
//     can't be correlated and to avoid double allocation (§13.3). Copies may
//     differ by idx on one list or be spread across multiple Status List Tokens.
func validateStatusReferences(parsedCredentials []*ParsedCredential) error {
	firstHasRef := statusReferenceOf(parsedCredentials[0]) != (statuslist.Reference{})
	seen := make(map[statuslist.Reference]int, len(parsedCredentials))
	for i, p := range parsedCredentials {
		ref := statusReferenceOf(p)
		hasRef := ref != (statuslist.Reference{})
		if hasRef != firstHasRef {
			return fmt.Errorf(
				"partial status_list reference in batch: instance 0 hasRef=%t but instance %d hasRef=%t; either all instances carry a status_list reference or none do",
				firstHasRef, i, hasRef,
			)
		}
		if !hasRef {
			continue
		}
		if prev, dup := seen[ref]; dup {
			return fmt.Errorf(
				"duplicate status_list reference in batch: instances %d and %d both use %+v; each one-time-use copy MUST have a dedicated entry (draft-ietf-oauth-status-list §13.2)",
				prev, i, ref,
			)
		}
		seen[ref] = i
	}
	return nil
}

func buildInstances(parsedCredentials []*ParsedCredential) []models.IssuedCredentialInstance {
	instances := make([]models.IssuedCredentialInstance, len(parsedCredentials))
	now := time.Now()
	for i, p := range parsedCredentials {
		inst := models.IssuedCredentialInstance{
			RawCredential: p.RawCredentialBytes,
		}
		// Persist the status_list reference so the disclosure path and
		// the refresh sweep can run without re-parsing the SD-JWT VC.
		// At issuance time the holder verifier has just confirmed the
		// bit reads StatusValid (or the credential has no status
		// reference), so seed LastKnownStatus accordingly. Formats with
		// no status_list concept (mso_mdoc) simply carry none of this.
		if ref := statusReferenceOf(p); ref != (statuslist.Reference{}) {
			uri := ref.URI
			idx := ref.Index
			t := now
			inst.StatusListURI = &uri
			inst.StatusListIdx = &idx
			inst.LastKnownStatus = uint8(statuslist.StatusValid)
			inst.LastStatusCheckAt = &t
		}
		instances[i] = inst
	}
	return instances
}

// hashGeneric hashes the claims directly, with no standard-claim stripping —
// used for formats (mso_mdoc) whose ResolvedClaims is already a bare
// namespace->element->value map with nothing resembling sdjwtvc.StandardClaims
// mixed in, unlike hashForSdJwtVc.
func hashGeneric(credType, issuerIdentifier string, resolvedClaimsBytes []byte) (string, error) {
	return credentialHash(credType, issuerIdentifier, resolvedClaimsBytes), nil
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
	}
	return ""
}

func convertCredentialMetadata(config metadata.CredentialConfiguration) *models.CredentialMetadata {
	result := &models.CredentialMetadata{}
	if config.CredentialMetadata == nil {
		return result
	}

	claimModels := make([]models.CredentialClaim, len(config.CredentialMetadata.Claims))
	for i, claim := range config.CredentialMetadata.Claims {
		claimPath, err := json.Marshal(claim.Path)
		if err != nil {
			eudi.Logger.Warnf("failed to marshal claim path: %v", err)
			continue
		}

		displays := make([]models.ClaimDisplay, len(claim.Display))
		for j, display := range claim.Display {
			locale := datatypes.NullString{}
			if display.Locale != nil {
				locale.V = *display.Locale
				locale.Valid = true
			}
			displays[j] = models.ClaimDisplay{
				Name:   display.Name,
				Locale: locale,
			}
		}

		mandatory := false
		if claim.Mandatory != nil {
			mandatory = *claim.Mandatory
		}

		claimModels[i] = models.CredentialClaim{
			Path:      datatypes.JSON(claimPath),
			Mandatory: mandatory,
			Display:   displays,
		}
	}

	result.Claims = claimModels
	result.Display = slices.Collect(config.CredentialMetadata.Display.ToStorageModelIterator())
	return result
}

// matchAllHolderBindingKeys matches every credential to a stored holder
// binding key: via its cnf claim for dc+sd-jwt, or via its embedded device
// key's thumbprint/DID for every other format. Returns an error if any
// credential cannot be matched, ensuring the caller can abort before any
// side effects.
func matchAllHolderBindingKeys(
	parsedCredentials []*ParsedCredential,
	publicKeyIdentifiers []models.PublicHolderBindingKey,
) ([]datatypes.UUID, error) {
	keyByThumbprint := map[string]datatypes.UUID{}
	keyByDidUrl := map[string]datatypes.UUID{}
	for _, pk := range publicKeyIdentifiers {
		if pk.PublicKeyThumbprint != nil {
			keyByThumbprint[*pk.PublicKeyThumbprint] = pk.ID
		}
		if pk.DidUrl != nil {
			keyByDidUrl[*pk.DidUrl] = pk.ID
		}
	}

	// An issuer may echo the kid with the verification method fragment the DID method
	// uses to reference the key (`did:key:z…#z…`) where the proof sent it without, so
	// register the fragmentless form too. Second pass, so an exact DID URL always wins
	// over a fragmentless alias.
	//
	// Format-independent: this fixes up the key map, which both the cnf path and the
	// identifier path below look keys up in.
	for _, pk := range publicKeyIdentifiers {
		if pk.DidUrl == nil {
			continue
		}
		if base := stripFragment(*pk.DidUrl); base != *pk.DidUrl {
			if _, taken := keyByDidUrl[base]; !taken {
				keyByDidUrl[base] = pk.ID
			}
		}
	}

	result := make([]datatypes.UUID, len(parsedCredentials))
	for i, p := range parsedCredentials {
		var keyID datatypes.UUID
		var err error
		if p.SdJwtVc != nil {
			cnf := p.SdJwtVc.IssuerSignedJwtPayload.Confirm
			if cnf == nil {
				return nil, fmt.Errorf("credential %d requires holder binding but has no cnf claim", i)
			}
			keyID, err = matchHolderBindingKey(cnf, keyByThumbprint, keyByDidUrl)
		} else {
			if p.HolderBindingKeyThumbprint == nil && p.HolderBindingKeyPublicKey == nil {
				return nil, fmt.Errorf("credential %d requires holder binding but carries no key-binding data", i)
			}
			keyID, err = matchHolderBindingKeyByIdentifiers(p, keyByDidUrl, keyByThumbprint)
		}
		if err != nil {
			return nil, fmt.Errorf("credential %d: %w", i, err)
		}
		result[i] = keyID
	}
	return result, nil
}

// matchHolderBindingKeyByIdentifiers is matchHolderBindingKey's generic
// counterpart for formats with no cnf claim (mso_mdoc), taking already-
// extracted identifiers instead of an sdjwt.CnfField.
func matchHolderBindingKeyByIdentifiers(p *ParsedCredential, keyByDidUrl, keyByThumbprint map[string]datatypes.UUID) (datatypes.UUID, error) {
	thumbprint, didUrls := holderBindingKeyIdentifiers(p)

	if thumbprint != nil {
		if keyID, ok := keyByThumbprint[*thumbprint]; ok {
			return keyID, nil
		}
	}
	for _, didUrl := range didUrls {
		if keyID, ok := keyByDidUrl[didUrl]; ok {
			return keyID, nil
		}
	}
	return datatypes.UUID{}, fmt.Errorf("no matching holder binding key found")
}

// holderBindingKeyIdentifiers lists every identifier under which the stored
// holder binding key for this credential could have been recorded.
//
// A stored key carries a thumbprint or a DID URL and never both, chosen by the
// binding method the credential configuration asked for (see
// holderBindingKeyService.storePrivateKeys). A format like mso_mdoc reads a bare
// public key out of the credential and cannot tell which was used, so rather
// than guess, derive all of them the same way the proof builder did and let the
// caller try each. Deriving from the public key is exactly reproducible:
// did:key is a multibase encoding of the key, and did:jwk is base64url of the
// serialized JWK — which is why the JWK is marked for signature use here, as
// JwtProofBuilder does, since that field is part of the encoded document.
//
// A derivation that fails is skipped rather than fatal: it only means one
// candidate cannot be formed, and the remaining ones may still match.
func holderBindingKeyIdentifiers(p *ParsedCredential) (thumbprint *string, didUrls []string) {
	thumbprint = p.HolderBindingKeyThumbprint
	if p.HolderBindingKeyPublicKey == nil {
		return thumbprint, nil
	}

	// Both did:key forms, because which one the kid carries depends on which proof
	// builder ran: JwtProofBuilder uses
	// didkey.CreateWithVerificationMethodIdentifier and emits the verification
	// method fragment (`did:key:z…#z…`), while the other builder emits the bare
	// DID. Deriving only one silently fails to match half the time, which is what
	// TestDerivedDidUrlsMatchProofBuilder exists to catch.
	if didKey, err := didkey.Create(*p.HolderBindingKeyPublicKey); err == nil {
		didUrls = append(didUrls, didKey)
	}
	if didKeyWithFragment, err := didkey.CreateWithVerificationMethodIdentifier(*p.HolderBindingKeyPublicKey); err == nil {
		didUrls = append(didUrls, didKeyWithFragment)
	}

	pubJwk, err := jwk.Import[jwk.Key](p.HolderBindingKeyPublicKey)
	if err != nil {
		return thumbprint, didUrls
	}
	if err := pubJwk.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return thumbprint, didUrls
	}
	builder := didjwk.DocumentBuilder{}
	doc, err := builder.FromJwk(pubJwk)
	if err != nil || len(doc.AssertionMethod) == 0 {
		return thumbprint, didUrls
	}
	// VerificationRef is `any`; didjwk fills it with the "<did>#0" string, which
	// is what JwtProofBuilder puts in the proof's kid and therefore what
	// keybinder_service stored.
	didJwkUrl, ok := doc.AssertionMethod[0].(string)
	if !ok {
		return thumbprint, didUrls
	}
	return thumbprint, append(didUrls, didJwkUrl)
}

func (s *credentialService) deleteOrphanedKeys(publicKeyIdentifiers []models.PublicHolderBindingKey) {
	ids := make([]datatypes.UUID, len(publicKeyIdentifiers))
	for i, pk := range publicKeyIdentifiers {
		ids[i] = pk.ID
	}
	if err := s.holderBindingKeyStore.DeleteKeys(ids); err != nil {
		eudi.Logger.Warnf("failed to clean up orphaned holder binding keys: %v", err)
	}
}

func (s *credentialService) linkHolderBindingKeys(keyIDs []datatypes.UUID, instances []models.IssuedCredentialInstance) {
	for i, keyID := range keyIDs {
		if err := s.holderBindingKeyStore.LinkToInstance(keyID, instances[i].ID); err != nil {
			eudi.Logger.Warnf("failed to link holder binding key %s to instance %s: %v", keyID, instances[i].ID, err)
		}
	}
}

// matchHolderBindingKey resolves the holder binding key ID from the credential's cnf claim
// by matching against the known thumbprints and DID URLs.
func matchHolderBindingKey(cnf *sdjwt.CnfField, keyByThumbprint map[string]datatypes.UUID, keyByDidUrl map[string]datatypes.UUID) (datatypes.UUID, error) {
	// Try DID URL (kid) first.
	if cnf.Kid != nil {
		if keyID, ok := keyByDidUrl[*cnf.Kid]; ok {
			return keyID, nil
		}
		// Then the base DID, for a kid that carries a verification method fragment the
		// stored DID URL does not (mirrors GetAndRemovePrivateKey).
		if base := stripFragment(*cnf.Kid); base != *cnf.Kid {
			if keyID, ok := keyByDidUrl[base]; ok {
				return keyID, nil
			}
		}
	}

	// Try JWK thumbprint.
	if cnf.Jwk != nil {
		thumbprintBytes, err := (*cnf.Jwk).Thumbprint(crypto.SHA256)
		if err != nil {
			return datatypes.UUID{}, fmt.Errorf("failed to compute thumbprint from cnf.jwk: %w", err)
		}
		thumbprint := hex.EncodeToString(thumbprintBytes)
		if keyID, ok := keyByThumbprint[thumbprint]; ok {
			return keyID, nil
		}
	}

	return datatypes.UUID{}, fmt.Errorf("no matching holder binding key found for cnf claim")
}

// BuildMdocAttributesFromResolvedClaims builds an attribute list directly
// from a resolved mso_mdoc claims map (namespace -> elementIdentifier ->
// value), for the permission-dialog display at issuance time. mso_mdoc's
// resolved claims are just a two-level nested map -- a degenerate case of
// the same arbitrary-depth structure FlattenClaimValue/sortObjectKeys
// already walk for dc+sd-jwt -- so this reuses them directly rather than
// re-implementing sort/flatten from scratch.
func BuildMdocAttributesFromResolvedClaims(claims []metadata.ClaimsDescription, resolved map[string]map[string]any, locale string) []clientmodels.Attribute {
	displayLookup := map[string]string{}
	metadataOrder := map[string]int{}
	for i, c := range claims {
		key := clientmodels.ClaimPathKey(c.Path)
		metadataOrder[key] = i
		if len(c.Display) == 0 {
			continue
		}
		// Falls back to clientmodels.DefaultFallbackLanguage when a display
		// entry carries no locale -- the same convention every other
		// display-name conversion in this package uses. Resolved to a single
		// string for the caller's locale, matching FlattenClaimValue's lookup.
		display := clientmodels.TranslatedString{}
		for _, d := range c.Display {
			entryLocale := clientmodels.DefaultFallbackLanguage
			if d.Locale != nil {
				if base, ok := metadata.TryGetBaseLanguageFromLocale(*d.Locale); ok {
					entryLocale = base
				}
			}
			display[entryLocale] = d.Name
		}
		displayLookup[key] = clientmodels.Resolve(display, locale)
	}

	topLevel := make(map[string]any, len(resolved))
	for namespace, elements := range resolved {
		topLevel[namespace] = elements
	}

	attrs := []clientmodels.Attribute{}
	for _, namespace := range sortObjectKeys(topLevel, []any{}, metadataOrder) {
		attrs = FlattenClaimValue(attrs, []any{namespace}, topLevel[namespace], displayLookup, metadataOrder)
	}
	return attrs
}

// BuildAttributesFromPayload walks the credential payload top-down and emits an
// Attribute for every claim it finds. Standard JWT/SD-JWT claims are filtered
// out at the top level. The lookup map (built from issuer metadata, resolved
// to the current locale) supplies display names; claims without a metadata
// entry produce attributes with DisplayName: nil. Top-level keys are ordered
// by metadata position, then alphabetically for keys absent from the metadata.
func BuildAttributesFromPayload(
	payload *sdjwt.ProcessedPayload,
	lookup map[string]string,
	metadataOrder map[string]int,
) []clientmodels.Attribute {
	attrs := []clientmodels.Attribute{}
	if payload == nil {
		return attrs
	}
	topLevel := make(map[string]any, len(*payload))
	for k, v := range *payload {
		if _, isStd := sdjwtvc.StandardClaims[k]; isStd {
			continue
		}
		topLevel[k] = v
	}
	for _, key := range sortObjectKeys(topLevel, []any{}, metadataOrder) {
		attrs = FlattenClaimValue(attrs, []any{key}, topLevel[key], lookup, metadataOrder)
	}
	return attrs
}

// FlattenClaimValue recursively flattens arrays and objects into individual scalar
// attributes. Each leaf value gets its own Attribute with the full path from root.
// A section header (Value == nil) is emitted only when the path has an explicit
// display name in the metadata lookup. Object keys are ordered by their position
// in the metadata (via metadataOrder), falling back to alphabetical for keys not
// in the metadata.
func FlattenClaimValue(
	attrs []clientmodels.Attribute,
	path []any,
	value any,
	lookup map[string]string,
	metadataOrder map[string]int,
) []clientmodels.Attribute {
	switch v := value.(type) {
	case []any:
		if d, ok := lookupDisplayName(lookup, path); ok {
			dn := d
			attrs = append(attrs, clientmodels.Attribute{
				ClaimPath:   path,
				DisplayName: &dn,
			})
		}
		for i, elem := range v {
			childPath := append(append([]any{}, path...), i)
			attrs = FlattenClaimValue(attrs, childPath, elem, lookup, metadataOrder)
		}
	case map[string]any:
		if d, ok := lookupDisplayName(lookup, path); ok {
			dn := d
			attrs = append(attrs, clientmodels.Attribute{
				ClaimPath:   path,
				DisplayName: &dn,
			})
		}
		keys := sortObjectKeys(v, path, metadataOrder)
		for _, key := range keys {
			childPath := append(append([]any{}, path...), key)
			attrs = FlattenClaimValue(attrs, childPath, v[key], lookup, metadataOrder)
		}
	default:
		var dn *string
		if d, ok := lookupDisplayName(lookup, path); ok {
			dnCopy := d
			dn = &dnCopy
		}
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   path,
			DisplayName: dn,
			Value:       clientmodels.NewAttributeValue(value),
		})
	}
	return attrs
}

// sortObjectKeys returns the keys of an object sorted by their position in the
// issuer metadata. Keys not in the metadata are appended alphabetically.
func sortObjectKeys(obj map[string]any, parentPath []any, metadataOrder map[string]int) []string {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		pi := metadataOrderForKey(parentPath, keys[i], metadataOrder)
		pj := metadataOrderForKey(parentPath, keys[j], metadataOrder)
		if pi != pj {
			return pi < pj
		}
		return keys[i] < keys[j]
	})
	return keys
}

// metadataOrderForKey returns the metadata order index for a child key under parentPath.
// Tries both exact and wildcard (null) path matching. Returns maxInt if not found.
func metadataOrderForKey(parentPath []any, key string, metadataOrder map[string]int) int {
	childPath := append(append([]any{}, parentPath...), key)
	// Exact match.
	if idx, ok := metadataOrder[clientmodels.ClaimPathKey(childPath)]; ok {
		return idx
	}
	// Wildcard match.
	wildcard := make([]any, len(childPath))
	hasIndex := false
	for i, c := range childPath {
		if isArrayIndex(c) {
			wildcard[i] = nil
			hasIndex = true
		} else {
			wildcard[i] = c
		}
	}
	if hasIndex {
		if idx, ok := metadataOrder[clientmodels.ClaimPathKey(wildcard)]; ok {
			return idx
		}
	}
	return 1<<31 - 1
}

// isArrayIndex returns true if the path component is a numeric array index.
func isArrayIndex(component any) bool {
	switch component.(type) {
	case int, float64:
		return true
	}
	return false
}

// lookupDisplayName checks the lookup map for the given path, first by exact match,
// then by replacing integer indices with nil (null wildcard) to match metadata paths
// like ["faculties", null, "faculty_name"].
func lookupDisplayName(lookup map[string]string, path []any) (string, bool) {
	// Exact match.
	if d, ok := lookup[clientmodels.ClaimPathKey(path)]; ok && d != "" {
		return d, true
	}
	// Wildcard match: replace integer indices with nil.
	wildcard := make([]any, len(path))
	hasIndex := false
	for i, c := range path {
		if isArrayIndex(c) {
			wildcard[i] = nil
			hasIndex = true
		} else {
			wildcard[i] = c
		}
	}
	if hasIndex {
		if d, ok := lookup[clientmodels.ClaimPathKey(wildcard)]; ok && d != "" {
			return d, true
		}
	}
	return "", false
}

// hashForSdJwtVc computes the deterministic hash used for batch deduplication.
// Standard claims (iat, exp, nbf, iss, sub, vct, cnf, status, etc.) are stripped
// before hashing so that two issuances of the same credential with identical claims
// produce the same hash. Note: this hash is intentionally different from
// irmaclient.CreateHashForSdJwtVc, which is used for IRMA-issued SD-JWTs.
//
// Stability: json.Marshal sorts map keys at every nesting level, so object key
// order in the input does not affect the hash. Array element order IS significant
// — ["A","B"] and ["B","A"] produce different hashes, which is the correct
// behaviour since array ordering is meaningful in SD-JWT claims.
func hashForSdJwtVc(credType, issuerIdentifier string, processedSdJwtPayloadBytes []byte) (string, error) {
	// Unmarshal into a map so we can strip standard claims before hashing.
	var payload map[string]any
	if err := json.Unmarshal(processedSdJwtPayloadBytes, &payload); err != nil {
		return "", fmt.Errorf("hashForSdJwtVc: failed to unmarshal payload: %w", err)
	}

	for key := range sdjwtvc.StandardClaims {
		delete(payload, key)
	}

	cleanedBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("hashForSdJwtVc: failed to marshal cleaned payload: %w", err)
	}

	return credentialHash(credType, issuerIdentifier, cleanedBytes), nil
}

// credentialHash is the one place a credential's deduplication hash is computed,
// for every format.
//
// The issuer is part of the identity on purpose. Two different issuers minting the
// same credential type with the same claims are two different credentials —
// "over 18, according to the Dutch state" and "over 18, according to a shop's own
// loyalty scheme" are not interchangeable, and a wallet that hashed them alike
// could hold only one of them, silently refusing or replacing the other. Because
// the hash is a unique index, that was not a display quirk: the storage layer
// could not represent both.
//
// Renewal still works, which is the property that constrains this: the issuer of
// a credential does not change when it is re-issued, so a renewal produces the
// same hash and is still recognised as the same credential.
//
// Length-prefixed rather than concatenated. Plain concatenation cannot tell field
// boundaries apart, so a type ending in the issuer's first characters would hash
// identically to a shorter type and a longer issuer — ("a.b", "cd") and ("a.bc",
// "d") were the same bytes. Nothing observed that, but a hash that decides
// credential identity should not have a preimage ambiguity in it at all.
func credentialHash(credType, issuerIdentifier string, claims []byte) string {
	digest := sha256.New()
	for _, field := range [][]byte{[]byte(credType), []byte(issuerIdentifier), claims} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		digest.Write(length[:])
		digest.Write(field)
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}
