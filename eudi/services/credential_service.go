package services

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/internal/common"
	"gorm.io/datatypes"
)

// CredentialService stores verified SD-JWT VCs and their associated holder binding keys
// in a single atomic transaction.
type CredentialService interface {
	GetCredentialMetadataList() ([]*clientmodels.Credential, error)
	VerifyAndStoreIssuedCredentials(
		verifiedSdJwtVcs []*sdjwtvc.VerifiedSdJwtVc,
		credentialConfigurationId string,
		metadata metadata.CredentialIssuerMetadata,
		requireCryptographicKeyBinding bool,
		publicKeyIdentifiers []models.PublicHolderBindingKey,
	) error

	// DeleteByHash deletes a stored CredentialBatch by its deterministic hash.
	// Returns ErrNotFound if no batch exists with that hash.
	DeleteByHash(hash string) error

	// RefreshStatuses re-fetches every stored instance's Token Status List and
	// writes back its LastKnownStatus. No-op when status checking is disabled.
	RefreshStatuses(ctx context.Context) error
}

type credentialService struct {
	credentialStore       db.CredentialStore
	holderBindingKeyStore db.HolderBindingKeyStore
	fileStorage           filesystem.FileSystemStorage
	// statusChecker performs Token Status List fetches for RefreshStatuses.
	// Nil disables status refresh; the read path still surfaces the stored
	// LastKnownStatus.
	statusChecker *statuslist.Checker
}

func NewCredentialService(
	credentialStore db.CredentialStore,
	holderBindingKeyStore db.HolderBindingKeyStore,
	fileStorage filesystem.FileSystemStorage,
	statusChecker *statuslist.Checker,
) CredentialService {
	return &credentialService{
		credentialStore:       credentialStore,
		holderBindingKeyStore: holderBindingKeyStore,
		fileStorage:           fileStorage,
		statusChecker:         statusChecker,
	}
}

func (s *credentialService) DeleteByHash(hash string) error {
	return s.credentialStore.DeleteBatchByHash(hash)
}

// RefreshStatuses re-fetches Token Status Lists and updates stored statuses,
// checking one representative instance per batch rather than every copy. A
// batch's instances are the same logical credential and are revoked together
// (draft-ietf-oauth-status-list §13.2), so one entry's bit determines the whole
// batch's status; re-checking every copy would be redundant work.
//
// Representatives are grouped by (uri, iss) so a status list shared across many
// batches is fetched once; iss is part of the key so a cross-issuer URI re-use
// can't borrow another issuer's cache slot.
//
// Fail-soft: per-URI and per-instance errors are logged and skipped, leaving
// the previous LastKnownStatus in place. A nil statusChecker makes this a no-op.
func (s *credentialService) RefreshStatuses(ctx context.Context) error {
	if s.statusChecker == nil {
		return nil
	}
	instances, err := s.credentialStore.ListInstancesWithStatusReference()
	if err != nil {
		return fmt.Errorf("load instances: %w", err)
	}

	// Keep one representative instance per batch. Any copy gives the same
	// answer under the whole-batch-revoked assumption, so the first seen wins.
	seenBatch := make(map[datatypes.UUID]struct{}, len(instances))
	representatives := make([]db.CredentialStatusInstance, 0, len(instances))
	for _, inst := range instances {
		if _, ok := seenBatch[inst.BatchID]; ok {
			continue
		}
		seenBatch[inst.BatchID] = struct{}{}
		representatives = append(representatives, inst)
	}

	type key struct{ uri, iss string }
	groups := map[key][]db.CredentialStatusInstance{}
	for _, inst := range representatives {
		k := key{uri: inst.StatusListURI, iss: inst.IssuerURL}
		groups[k] = append(groups[k], inst)
	}

	for k, group := range groups {
		// One Refresh per URI populates the cache; the per-idx Check calls
		// below then read from the warm cache (no extra HTTP traffic).
		if _, err := s.statusChecker.Refresh(ctx, statuslist.Reference{URI: k.uri}, k.iss); err != nil {
			eudi.Logger.Warnf("status refresh: refresh %s failed: %v", common.SanitizeForLog(k.uri), err)
			continue
		}
		now := time.Now()
		for _, inst := range group {
			st, err := s.statusChecker.Check(ctx, statuslist.Reference{URI: k.uri, Index: inst.StatusListIdx}, k.iss)
			if err != nil {
				eudi.Logger.Warnf("status refresh: check idx %d on %s failed: %v", inst.StatusListIdx, common.SanitizeForLog(k.uri), err)
				continue
			}
			if err := s.credentialStore.UpdateInstanceStatus(inst.InstanceID, uint8(st), now); err != nil {
				eudi.Logger.Warnf("status refresh: writeback failed for instance %s: %v", inst.InstanceID, err)
			}
		}
	}
	return nil
}

func (s *credentialService) GetCredentialMetadataList() ([]*clientmodels.Credential, error) {
	m, err := s.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, err
	}

	// Derive per-credential revocation from the stored Token Status List
	// statuses (updated by the background sweep / RefreshStatuses). A batch's
	// instances are the same credential (distinct status bits only for
	// unlinkability) and are revoked together by the issuer, and StatusInvalid
	// is permanent — so the batch is revoked as soon as any status-referenced
	// instance reads StatusInvalid, and supports revocation if it carries any
	// status reference at all. The sweep refreshes only one representative
	// instance per batch, so in practice that representative's bit drives the
	// flag; the "any invalid" rule still holds because non-representatives keep
	// their issuance-time Valid.
	instanceStatuses, err := s.credentialStore.ListStatusReferencedInstanceStatuses()
	if err != nil {
		return nil, err
	}
	revocable := map[string]bool{}
	revoked := map[string]bool{}
	for _, st := range instanceStatuses {
		revocable[st.Hash] = true
		if statuslist.Status(st.LastKnownStatus) == statuslist.StatusInvalid {
			revoked[st.Hash] = true
		}
	}

	// Convert storage models to client models
	clientModels := make([]*clientmodels.Credential, len(m))
	for i, batch := range m {
		var processedSdJwtPayload *sdjwtvc.ProcessedSdJwtPayload
		if err := json.Unmarshal(batch.ProcessedSdJwtPayload, &processedSdJwtPayload); err != nil {
			processedSdJwtPayload = nil // fallback to nil if unmarshalling fails
		}

		issuerDisplays := clientmodels.TranslatedString{}
		for _, d := range batch.IssuerDisplay {
			locale := clientmodels.DefaultFallbackLanguage
			if d.Locale.Valid {
				if base, ok := metadata.TryGetBaseLanguageFromLocale(d.Locale.V); ok {
					locale = base
				}
			}
			issuerDisplays[locale] = d.Name
		}

		credentialDisplays := clientmodels.TranslatedString{}
		claimDisplayLookup := map[string]clientmodels.TranslatedString{}
		metadataOrder := map[string]int{}

		if batch.CredentialMetadata != nil {
			for _, d := range batch.CredentialMetadata.Display {
				locale := clientmodels.DefaultFallbackLanguage
				if d.Locale.Valid {
					if base, ok := metadata.TryGetBaseLanguageFromLocale(d.Locale.V); ok {
						locale = base
					}
				}
				credentialDisplays[locale] = d.Name
			}

			for i, claim := range batch.CredentialMetadata.Claims {
				var path []any
				if err := json.Unmarshal(claim.Path, &path); err != nil {
					continue
				}
				key := clientmodels.ClaimPathKey(path)
				metadataOrder[key] = i
				if len(claim.Display) == 0 {
					continue
				}
				display := clientmodels.TranslatedString{}
				for _, d := range claim.Display {
					locale := clientmodels.DefaultFallbackLanguage
					if d.Locale.Valid {
						if base, ok := metadata.TryGetBaseLanguageFromLocale(d.Locale.V); ok {
							locale = base
						}
					}
					display[locale] = d.Name
				}
				claimDisplayLookup[key] = display
			}
		}

		attrs := buildAttributesFromPayload(processedSdJwtPayload, claimDisplayLookup, metadataOrder)

		var iat, exp *int64
		if batch.ExpiresAt.Valid {
			x := batch.ExpiresAt.V.Unix()
			exp = &x
		}
		if batch.IssuedAt.Valid {
			x := batch.IssuedAt.V.Unix()
			iat = &x
		}

		// Resolve credential/issuer logos from the filesystem cache. Scan ALL
		// display entries (not just Display[0]): multi-locale metadata may carry
		// the logo on a later entry, and only one logo is cached. Break on the
		// first entry that actually resolves, not the first non-empty URI, since a
		// display's URI may not be the one that got cached. Mirrors the
		// issuance/disclosure paths.
		// TODO: pick the logo matching the client's language preference instead of
		// the first that resolves.
		credentialLogoManager := s.fileStorage.Credentials().LogoManager()
		issuerLogoManager := s.fileStorage.Issuers().LogoManager()

		var issuerImage *clientmodels.Image
		for _, d := range batch.IssuerDisplay {
			if !d.LogoURI.Valid || d.LogoURI.V == "" {
				continue
			}
			if img := eudi.LoadLogoImage(issuerLogoManager, d.LogoURI.V); img != nil {
				issuerImage = img
				break
			}
		}

		var credentialImage *clientmodels.Image
		if batch.CredentialMetadata != nil {
			for _, d := range batch.CredentialMetadata.Display {
				if d.LogoURI == "" {
					continue
				}
				if img := eudi.LoadLogoImage(credentialLogoManager, d.LogoURI); img != nil {
					credentialImage = img
					break
				}
			}
		}

		clientModels[i] = &clientmodels.Credential{
			CredentialId: batch.VerifiableCredentialType,
			Hash:         batch.Hash,
			Image:        credentialImage,
			Name:         credentialDisplays,
			Issuer: clientmodels.TrustedParty{
				Id:       batch.CredentialIssuer,
				Name:     issuerDisplays,
				Image:    issuerImage,
				Url:      nil,
				Parent:   nil,
				Verified: false,
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
		}
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

// StoreIssuedCredentials builds a CredentialBatch from the supplied verified credentials and
// metadata, then persists the batch and all its instances in one transaction.
//
// keyModels must either be empty (no cryptographic key binding required) or have exactly the same length as
// verifiedSdJwtVcs (one key per instance). All credentials in the slice are assumed to have been
// issued from the same credential_configuration_id and therefore share vct, issuer, and timing claims.
func (s *credentialService) VerifyAndStoreIssuedCredentials(
	verifiedSdJwtVcs []*sdjwtvc.VerifiedSdJwtVc,
	credentialConfigurationId string,
	issuerMetadata metadata.CredentialIssuerMetadata,
	requireCryptographicKeyBinding bool,
	publicKeyIdentifiers []models.PublicHolderBindingKey,
) error {
	if len(verifiedSdJwtVcs) == 0 {
		return nil // nothing to store
	}

	// A batch's instances are the same logical credential and are revoked
	// together. Per draft-ietf-oauth-status-list §13.2 each one-time-use copy
	// MUST carry its OWN dedicated, distinct status entry (for unlinkability):
	// require all-or-none presence and reject duplicate references. Reject here,
	// before any side effects, so a malformed issuance can't delete the user's
	// existing credential (computeHashAndDeleteExisting below is destructive).
	if err := validateStatusReferences(verifiedSdJwtVcs); err != nil {
		if requireCryptographicKeyBinding {
			s.deleteOrphanedKeys(publicKeyIdentifiers)
		}
		return err
	}

	if requireCryptographicKeyBinding && len(publicKeyIdentifiers) != len(verifiedSdJwtVcs) {
		return fmt.Errorf(
			"publicKeyIdentifiers length (%d) must equal verifiedSdJwtVcs length (%d) when cryptographic key binding is used",
			len(publicKeyIdentifiers), len(verifiedSdJwtVcs),
		)
	}

	// Match all holder binding keys upfront before any side effects, so that a
	// mismatch aborts the issuance without deleting the user's existing batch.
	var matchedKeyIDs []datatypes.UUID
	if requireCryptographicKeyBinding {
		var err error
		matchedKeyIDs, err = matchAllHolderBindingKeys(verifiedSdJwtVcs, publicKeyIdentifiers)
		if err != nil {
			s.deleteOrphanedKeys(publicKeyIdentifiers)
			return err
		}
	}

	// All instances in a batch share the same vct, issuer, and timing claims.
	// Use the first credential as the source of truth for batch-level metadata.
	first := verifiedSdJwtVcs[0]

	hash, processedPayload, err := s.computeHashAndDeleteExisting(first)
	if err != nil {
		return err
	}

	credentialConfiguration := issuerMetadata.CredentialConfigurationsSupported[credentialConfigurationId]

	batch := &models.CredentialBatch{
		IssuerURL:                first.IssuerSignedJwtPayload.Issuer,
		VerifiableCredentialType: first.IssuerSignedJwtPayload.VerifiableCredentialType,
		Format:                   models.CredentialFormat(credentialConfiguration.Format),
		Hash:                     hash,
		ProcessedSdJwtPayload:    datatypes.JSON(processedPayload),
		CredentialIssuer:         first.IssuerSignedJwtPayload.Issuer,
		IssuerDisplay:            slices.Collect(issuerMetadata.Display.ToStorageModelIterator()),
		CredentialMetadata:       convertCredentialMetadata(credentialConfiguration),
		BatchSize:                uint(len(verifiedSdJwtVcs)),
		RemainingCount:           uint(len(verifiedSdJwtVcs)),
		Instances:                buildInstances(verifiedSdJwtVcs),
	}

	if first.IssuerSignedJwtPayload.IssuedAt != nil {
		batch.IssuedAt = datatypes.NullTime{V: time.Unix(*first.IssuerSignedJwtPayload.IssuedAt, 0), Valid: true}
	}
	if first.IssuerSignedJwtPayload.Expiry != nil {
		batch.ExpiresAt = datatypes.NullTime{V: time.Unix(*first.IssuerSignedJwtPayload.Expiry, 0), Valid: true}
	}
	if first.IssuerSignedJwtPayload.NotBefore != nil {
		batch.NotBefore = datatypes.NullTime{V: time.Unix(*first.IssuerSignedJwtPayload.NotBefore, 0), Valid: true}
	}

	if err := s.credentialStore.StoreBatch(batch); err != nil {
		return err
	}

	if requireCryptographicKeyBinding {
		s.linkHolderBindingKeys(matchedKeyIDs, batch.Instances)
	}

	return nil
}

func (s *credentialService) computeHashAndDeleteExisting(vc *sdjwtvc.VerifiedSdJwtVc) (string, []byte, error) {
	processedPayload, err := json.Marshal(vc.ProcessedSdJwtPayload)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal processed SD-JWT payload: %w", err)
	}

	hash, err := hashForSdJwtVc(vc.IssuerSignedJwtPayload.VerifiableCredentialType, processedPayload)
	if err != nil {
		return "", nil, fmt.Errorf("failed to compute credential hash: %w", err)
	}

	// If a batch with this hash already exists, delete it so the new issuance
	// replaces it (e.g. with updated timestamps or a fresh holder binding key).
	if existing, err := s.credentialStore.GetBatchByHash(hash); err == nil {
		if err := s.credentialStore.DeleteBatch(existing.ID); err != nil {
			return "", nil, fmt.Errorf("failed to delete existing batch before re-issuance: %w", err)
		}
	}

	return hash, processedPayload, nil
}

// statusReferenceOf returns the credential's Token Status List reference, or
// the zero Reference when it carries none. The zero value (empty URI) is a
// safe "absent" sentinel because a real reference always has a non-empty URI.
func statusReferenceOf(v *sdjwtvc.VerifiedSdJwtVc) statuslist.Reference {
	if v.IssuerSignedJwtPayload.Status == nil || v.IssuerSignedJwtPayload.Status.StatusList == nil {
		return statuslist.Reference{}
	}
	return *v.IssuerSignedJwtPayload.Status.StatusList
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
func validateStatusReferences(vcs []*sdjwtvc.VerifiedSdJwtVc) error {
	firstHasRef := statusReferenceOf(vcs[0]) != (statuslist.Reference{})
	seen := make(map[statuslist.Reference]int, len(vcs))
	for i, v := range vcs {
		ref := statusReferenceOf(v)
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

func buildInstances(vcs []*sdjwtvc.VerifiedSdJwtVc) []models.IssuedCredentialInstance {
	instances := make([]models.IssuedCredentialInstance, len(vcs))
	now := time.Now()
	for i, v := range vcs {
		inst := models.IssuedCredentialInstance{
			RawCredential: []byte(v.GetRawSdJwtVc()),
		}
		// Persist the status_list reference so the disclosure path and
		// the refresh sweep can run without re-parsing the SD-JWT VC.
		// At issuance time the holder verifier has just confirmed the
		// bit reads StatusValid (or the credential has no status
		// reference), so seed LastKnownStatus accordingly.
		if v.IssuerSignedJwtPayload.Status != nil && v.IssuerSignedJwtPayload.Status.StatusList != nil {
			ref := v.IssuerSignedJwtPayload.Status.StatusList
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

// matchAllHolderBindingKeys matches every credential's cnf claim to a stored
// holder binding key. Returns an error if any credential cannot be matched,
// ensuring the caller can abort before any side effects.
func matchAllHolderBindingKeys(
	vcs []*sdjwtvc.VerifiedSdJwtVc,
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

	result := make([]datatypes.UUID, len(vcs))
	for i, v := range vcs {
		cnf := v.IssuerSignedJwtPayload.Confirm
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
func matchHolderBindingKey(cnf *sdjwtvc.CnfField, keyByThumbprint map[string]datatypes.UUID, keyByDidUrl map[string]datatypes.UUID) (datatypes.UUID, error) {
	// Try DID URL (kid) first.
	if cnf.Kid != nil {
		if keyID, ok := keyByDidUrl[*cnf.Kid]; ok {
			return keyID, nil
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

// BuildAttributesFromPayload walks the credential payload top-down and emits an
// Attribute for every claim it finds. Standard JWT/SD-JWT claims are filtered
// out at the top level. The lookup map (built from issuer metadata) supplies
// display names; claims without a metadata entry produce attributes with
// DisplayName: nil. Top-level keys are ordered by metadata position, then
// alphabetically for keys absent from the metadata.
func BuildAttributesFromPayload(
	payload *sdjwtvc.ProcessedSdJwtPayload,
	lookup map[string]clientmodels.TranslatedString,
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

func buildAttributesFromPayload(
	payload *sdjwtvc.ProcessedSdJwtPayload,
	lookup map[string]clientmodels.TranslatedString,
	metadataOrder map[string]int,
) []clientmodels.Attribute {
	return BuildAttributesFromPayload(payload, lookup, metadataOrder)
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
	lookup map[string]clientmodels.TranslatedString,
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
		var dn *clientmodels.TranslatedString
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
func lookupDisplayName(lookup map[string]clientmodels.TranslatedString, path []any) (clientmodels.TranslatedString, bool) {
	// Exact match.
	if d, ok := lookup[clientmodels.ClaimPathKey(path)]; ok && len(d) > 0 {
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
		if d, ok := lookup[clientmodels.ClaimPathKey(wildcard)]; ok && len(d) > 0 {
			return d, true
		}
	}
	return nil, false
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
func hashForSdJwtVc(credType string, processedSdJwtPayloadBytes []byte) (string, error) {
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

	combined := append([]byte(credType), cleanedBytes...)
	return fmt.Sprintf("%x", sha256.Sum256(combined)), nil
}
