package services

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"gorm.io/datatypes"
)

// sdJwtVcCredentialService is the SD-JWT VC CredentialFormatStore: it verifies
// the holder key bindings of freshly issued SD-JWT VCs, persists them as one
// SdJwtVcBatch with its holder binding keys, and renders stored batches for the
// app. It knows nothing about any other format.
type sdJwtVcCredentialService struct {
	sdJwtVcDisplaySource
	holderBindingKeyStore db.HolderBindingKeyStore
	fileStorage           filesystem.FileSystemStorage
	// revocation supplies the per-batch revocation flags for the credential
	// list view (see List).
	revocation *RevocationService
	// currentLocale is read on every call, not snapshotted, so a SetLocale in
	// between two list calls is reflected without rebuilding the service.
	currentLocale *clientmodels.CurrentLocale
}

// NewSdJwtVcCredentialService returns the SD-JWT VC store over the given
// stores and file storage.
func NewSdJwtVcCredentialService(
	store db.SdJwtVcStore,
	holderBindingKeyStore db.HolderBindingKeyStore,
	fileStorage filesystem.FileSystemStorage,
	revocation *RevocationService,
	currentLocale *clientmodels.CurrentLocale,
) *sdJwtVcCredentialService {
	return &sdJwtVcCredentialService{
		sdJwtVcDisplaySource:  newSdJwtVcDisplaySource(store),
		holderBindingKeyStore: holderBindingKeyStore,
		fileStorage:           fileStorage,
		revocation:            revocation,
		currentLocale:         currentLocale,
	}
}

var _ CredentialFormatStore = (*sdJwtVcCredentialService)(nil)

func (s *sdJwtVcCredentialService) DeleteByHash(hash string) error {
	return s.store.DeleteBatchByHash(hash)
}

// List renders every stored SD-JWT VC batch for the app.
func (s *sdJwtVcCredentialService) List() ([]*clientmodels.Credential, error) {
	batches, err := s.store.GetCredentialBatchList()
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
	credentialLogoManager := s.fileStorage.Credentials().LogoManager()
	issuerLogoManager := s.fileStorage.Issuers().LogoManager()

	result := make([]*clientmodels.Credential, 0, len(batches))
	for _, batch := range batches {
		var payload *sdjwt.ProcessedPayload
		if err := json.Unmarshal(batch.ProcessedSdJwtPayload, &payload); err != nil {
			payload = nil // fallback to nil if unmarshalling fails
		}

		display := ResolveBatchDisplay(batch, locale)
		// Fall back to the vct when the issuer published no display text this
		// locale can resolve. The DCQL handler does exactly this
		// (eudi_sdjwt_dcql.credentialDisplayName), so without it the same
		// credential shows as a blank row in this list while the consent screen
		// names it.
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

		var iat, exp *int64
		if batch.ExpiresAt.Valid {
			x := batch.ExpiresAt.V.Unix()
			exp = &x
		}
		if batch.IssuedAt.Valid {
			x := batch.IssuedAt.V.Unix()
			iat = &x
		}

		// The logo falls back across languages independently of the text, so a
		// logo shows whenever any display carries one.
		var credentialImage *clientmodels.Image
		if batch.CredentialMetadata != nil {
			credentialImage = LoadResolvedLogo(credentialLogoManager, CredentialLogoURIsByLanguage(batch.CredentialMetadata.Display), locale)
		}

		result = append(result, &clientmodels.Credential{
			CredentialId:      batch.VerifiableCredentialType,
			Hash:              batch.Hash,
			Image:             credentialImage,
			Name:              credentialName,
			DisplayIsFallback: display.DisplayIsFallback,
			Issuer: clientmodels.TrustedParty{
				Id:    batch.CredentialIssuerIdentifier,
				Name:  display.IssuerName,
				Image: LoadResolvedLogo(issuerLogoManager, IssuerLogoURIsByLanguage(batch.IssuerDisplay), locale),
				// The wallet refuses to store a credential whose issuer it cannot
				// authenticate, so a stored batch is by construction one whose chain
				// verified; the flag records that it did.
				Verified: batch.IssuerVerified,
			},
			CredentialInstanceIds: map[clientmodels.CredentialFormat]string{
				clientmodels.CredentialFormat(batch.Format): batch.Hash,
			},
			BatchInstanceCountsRemaining: batchInstanceCounts(batch.Format, batch.BatchSize, &batch.RemainingCount),
			Attributes:                   BuildAttributesFromPayload(payload, display.ClaimNames, display.ClaimOrder),
			ExpiryDate:                   exp,
			IssuanceDate:                 iat,
			Revoked:                      revoked[batch.Hash],
			RevocationSupported:          revocable[batch.Hash],
			IssueURL:                     nil, // TODO: add issue URL to storage model so this can be filled in here
		})
	}

	return result, nil
}

// Store builds an SdJwtVcBatch from the supplied parsed credentials and
// metadata, then persists the batch and all its instances in one transaction.
//
// publicKeyIdentifiers must either be empty (no cryptographic key binding
// required) or have exactly the same length as parsedCredentials (one key per
// instance). All credentials in the slice are assumed to have been issued from
// the same credential_configuration_id and therefore share their type, issuer,
// and timing claims.
func (s *sdJwtVcCredentialService) Store(
	parsedCredentials []*ParsedCredential,
	credentialConfigurationId string,
	issuerMetadata metadata.CredentialIssuerMetadata,
	requireCryptographicKeyBinding bool,
	publicKeyIdentifiers []models.PublicHolderBindingKey,
) error {
	if len(parsedCredentials) == 0 {
		return nil // nothing to store
	}
	for i, p := range parsedCredentials {
		if p.SdJwtVc == nil {
			return fmt.Errorf("credential %d is not an SD-JWT VC (format %q); the SD-JWT VC store cannot hold it", i, p.Format)
		}
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

	processedPayload, err := json.Marshal(first.SdJwtVc.ProcessedSdJwtPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal processed SD-JWT payload: %w", err)
	}

	hash, err := s.computeHashAndDeleteExisting(first, processedPayload)
	if err != nil {
		return err
	}

	// Absent configuration is tolerated: everything read from it below is display
	// metadata, which degrades to empty rather than making a verified credential
	// unstorable. The batch's Format deliberately does not come from here — see
	// below.
	credentialConfiguration, credentialConfigurationFound := issuerMetadata.CredentialConfigurationsSupported[credentialConfigurationId]

	// Say so when the credential is going to have no display text. Without this the
	// degradation above is entirely silent: the wallet renders the raw vct in its
	// place, and nothing records whether the issuer's metadata lacked the
	// configuration, lacked credential_metadata within it, or carried no display
	// entries — three issuer-side causes that look identical from the app.
	if reason := missingDisplayMetadataReason(credentialConfigurationId, credentialConfiguration, credentialConfigurationFound); reason != "" {
		eudi.Logger.Warnf("credential from issuer %q will render as its raw type %q: %s", first.IssuerIdentifier, first.VerifiableCredentialType, reason)
	}

	batch := &models.SdJwtVcBatch{
		IssuerIdentifier:         first.IssuerIdentifier,
		VerifiableCredentialType: first.VerifiableCredentialType,
		// The format of the credential that was actually parsed and verified, not
		// the one the issuer's metadata advertises. The two normally agree — the
		// advertised format is what selected this parser — but the metadata is an
		// unverified claim, and the map index above yields a zero-valued
		// configuration when credentialConfigurationId is absent from it.
		Format:                first.Format,
		Hash:                  hash,
		ProcessedSdJwtPayload: datatypes.JSON(processedPayload),
		// Reaching this point means the issuer was authenticated. Every credential
		// here came from CredentialFormatParser.ParseAndVerify, which returns an
		// error rather than a ParsedCredential when the signature or the chain to a
		// trust anchor does not hold, so an unauthenticated issuer never gets as far
		// as a batch.
		IssuerVerified: true,
		// From the Credential Offer rather than from the credential:
		// IssuerIdentifier is the identity the credential itself asserts and was
		// verified against, CredentialIssuerIdentifier is the issuer the wallet
		// went to.
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

	if err := s.store.StoreBatch(batch); err != nil {
		return err
	}

	if requireCryptographicKeyBinding {
		s.linkHolderBindingKeys(matchedKeyIDs, batch.Instances)
	}

	return nil
}

// computeHashAndDeleteExisting computes the credential's content hash and makes
// room for it: a stored batch with the same hash is deleted when it may be
// replaced, and refused when it may not.
//
// A matching hash means the wallet already holds this credential: the hash
// covers the credential type, the issuer identity and the resolved claims, so
// re-issuing identical attributes from the same issuer lands here. What it
// deliberately does not cover is anything that changes on every issuance of the
// same content: salts, digest ids, holder keys, and the validity timestamps.
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
// batch spent, expiry approaching, new holder keys wanted -- carries the same
// claims and arrives with this same hash. A wallet that refused them all
// could never top up a spent batch and would go permanently unpresentable.
//
// So: refuse while the stored batch is still usable, replace once it is not.
func (s *sdJwtVcCredentialService) computeHashAndDeleteExisting(p *ParsedCredential, processedPayload []byte) (string, error) {
	hash, err := hashForSdJwtVc(p.VerifiableCredentialType, p.IssuerIdentifier, processedPayload)
	if err != nil {
		return "", fmt.Errorf("failed to compute credential hash: %w", err)
	}

	if existing, err := s.store.GetBatchByHash(hash); err == nil {
		if reason := batchStillUsable(existing, time.Now()); reason != "" {
			return "", fmt.Errorf(
				"credential %q is already held (stored copy issued by %q) and %s; re-issuing identical claims would replace it and discard its unused instances",
				existing.VerifiableCredentialType, existing.CredentialIssuerIdentifier, reason)
		}
		if err := s.store.DeleteBatch(existing.ID); err != nil {
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
// The remaining conditions mirror what the DCQL handler applies when deciding
// whether a batch may answer a query, and they are taken from there on purpose:
// if this drifted, the wallet would either refuse a re-issuance it needs (having
// judged usable a batch no query will accept) or discard one it could still
// present. dcql.IsBatchValid is called rather than re-derived for the same
// reason. Note dcql treats a batch of one as never exhausted, the same rule
// batchInstanceCounts encodes by returning nil there -- so consulting
// RemainingCount for it would be meaningless as well as harmful.
func batchStillUsable(batch *models.SdJwtVcBatch, now time.Time) string {
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

func buildInstances(parsedCredentials []*ParsedCredential) []models.SdJwtVcBatchInstance {
	instances := make([]models.SdJwtVcBatchInstance, len(parsedCredentials))
	now := time.Now()
	for i, p := range parsedCredentials {
		inst := models.SdJwtVcBatchInstance{
			RawCredential: p.RawCredentialBytes,
		}
		// Persist the status_list reference so the disclosure path and
		// the refresh sweep can run without re-parsing the SD-JWT VC.
		// At issuance time the holder verifier has just confirmed the
		// bit reads StatusValid (or the credential has no status
		// reference), so seed LastKnownStatus accordingly.
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

// convertCredentialMetadata converts a credential configuration's
// credential_metadata into the normalized storage tree the SD-JWT batch
// carries. A configuration without one yields an empty tree, not nil: that is
// what every deployed wallet has stored for such credentials, and the display
// code reads an empty tree and a missing one the same way.
func convertCredentialMetadata(config metadata.CredentialConfiguration) *models.CredentialMetadata {
	credentialMetadata := &models.CredentialMetadata{}
	if config.CredentialMetadata == nil {
		return credentialMetadata
	}
	credentialMetadata.Display = slices.Collect(config.CredentialMetadata.Display.ToStorageModelIterator())

	for _, claim := range config.CredentialMetadata.Claims {
		pathBytes, err := json.Marshal(claim.Path)
		if err != nil {
			eudi.Logger.Warnf("failed to marshal claim path %v: %v", claim.Path, err)
			continue
		}

		credentialClaim := models.CredentialClaim{
			Path:      datatypes.JSON(pathBytes),
			Mandatory: claim.Mandatory != nil && *claim.Mandatory,
		}
		for _, display := range claim.Display {
			locale := datatypes.NullString{}
			if display.Locale != nil {
				locale = datatypes.NullString{V: *display.Locale, Valid: true}
			}
			credentialClaim.Display = append(credentialClaim.Display, models.ClaimDisplay{
				Name:   display.Name,
				Locale: locale,
			})
		}
		credentialMetadata.Claims = append(credentialMetadata.Claims, credentialClaim)
	}

	return credentialMetadata
}

// matchAllHolderBindingKeys resolves, for every credential in the batch, the
// stored holder binding key its cnf claim names, before anything is written.
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
		cnf := p.SdJwtVc.IssuerSignedJwtPayload.Confirm
		if cnf == nil {
			return nil, fmt.Errorf("credential %d requires holder binding but has no cnf claim", i)
		}
		keyID, err := matchHolderBindingKey(cnf, keyByThumbprint, keyByDidUrl)
		if err != nil {
			return nil, fmt.Errorf("credential %d: %w", i, err)
		}
		result[i] = keyID
	}
	return result, nil
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

func (s *sdJwtVcCredentialService) deleteOrphanedKeys(publicKeyIdentifiers []models.PublicHolderBindingKey) {
	ids := make([]datatypes.UUID, len(publicKeyIdentifiers))
	for i, pk := range publicKeyIdentifiers {
		ids[i] = pk.ID
	}
	if err := s.holderBindingKeyStore.DeleteKeys(ids); err != nil {
		eudi.Logger.Warnf("failed to clean up orphaned holder binding keys: %v", err)
	}
}

func (s *sdJwtVcCredentialService) linkHolderBindingKeys(keyIDs []datatypes.UUID, instances []models.SdJwtVcBatchInstance) {
	for i, keyID := range keyIDs {
		if err := s.holderBindingKeyStore.LinkToInstance(keyID, instances[i].ID); err != nil {
			eudi.Logger.Warnf("failed to link holder binding key %s to instance %s: %v", keyID, instances[i].ID, err)
		}
	}
}

// --- read side shared with the activity log and the logo backfill ---

// sdJwtVcDisplaySource is the SD-JWT VC CredentialDisplaySource: the read side
// that needs only the store.
type sdJwtVcDisplaySource struct {
	store db.SdJwtVcStore
}

func newSdJwtVcDisplaySource(store db.SdJwtVcStore) sdJwtVcDisplaySource {
	return sdJwtVcDisplaySource{store: store}
}

// LiveDisplaysByType resolves the display text per stored vct. When several
// batches share a vct, one carrying credential metadata is preferred.
// Best-effort: on a storage error the map is empty.
func (s sdJwtVcDisplaySource) LiveDisplaysByType(locale string) map[string]ResolvedBatchDisplay {
	batches, err := s.store.GetCredentialBatchList()
	if err != nil {
		eudi.Logger.Warnf("failed to load SD-JWT VC batches for display re-resolution: %v", err)
		return map[string]ResolvedBatchDisplay{}
	}

	preferred := map[string]*models.SdJwtVcBatch{}
	for _, batch := range batches {
		if existing, ok := preferred[batch.VerifiableCredentialType]; ok && existing.CredentialMetadata != nil {
			continue
		}
		preferred[batch.VerifiableCredentialType] = batch
	}

	result := make(map[string]ResolvedBatchDisplay, len(preferred))
	for vct, batch := range preferred {
		result[vct] = ResolveBatchDisplay(batch, locale)
	}
	return result
}

// LogoURIs returns the issuer and credential logo URIs that resolve for the
// locale, one per stored batch.
func (s sdJwtVcDisplaySource) LogoURIs(locale string) (issuer []string, credential []string) {
	batches, err := s.store.GetCredentialBatchList()
	if err != nil {
		eudi.Logger.Warnf("failed to load SD-JWT VC batches for logo backfill: %v", err)
		return nil, nil
	}
	for _, batch := range batches {
		issuer = append(issuer, clientmodels.Resolve(IssuerLogoURIsByLanguage(batch.IssuerDisplay), locale))
		if batch.CredentialMetadata != nil {
			credential = append(credential, clientmodels.Resolve(CredentialLogoURIsByLanguage(batch.CredentialMetadata.Display), locale))
		}
	}
	return issuer, credential
}
