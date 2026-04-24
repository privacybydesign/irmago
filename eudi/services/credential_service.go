package services

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/privacybydesign/irmago/eudi"
	"slices"
	"sort"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
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
}

type credentialService struct {
	credentialStore db.CredentialStore
	fileStorage     filesystem.FileSystemStorage
}

func NewCredentialService(s storage.Storage) CredentialService {
	return &credentialService{
		credentialStore: db.NewCredentialStore(s.Db()),
		fileStorage:     s.FileSystem(),
	}
}

func (s *credentialService) GetCredentialMetadataList() ([]*clientmodels.Credential, error) {
	m, err := s.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, err
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
				locale = d.Locale.V
			}
			issuerDisplays[locale] = d.Name
		}

		attrs := []clientmodels.Attribute{}
		credentialDisplays := clientmodels.TranslatedString{}

		if batch.CredentialMetadata != nil {
			for _, d := range batch.CredentialMetadata.Display {
				locale := clientmodels.DefaultFallbackLanguage
				if d.Locale.Valid {
					locale, _ = metadata.TryGetBaseLanguageFromLocale(d.Locale.V)
				}
				credentialDisplays[locale] = d.Name
			}

			// Build a display lookup from all metadata claims, keyed by serialized path.
			// This allows child paths created during flattening to inherit display names
			// from more specific metadata entries when available.
			claimDisplayLookup := map[string]clientmodels.TranslatedString{}
			for _, claim := range batch.CredentialMetadata.Claims {
				var path []any
				if err := json.Unmarshal(claim.Path, &path); err != nil {
					continue
				}
				display := clientmodels.TranslatedString{}
				for _, d := range claim.Display {
					locale := clientmodels.DefaultFallbackLanguage
					if d.Locale.Valid {
						locale, _ = metadata.TryGetBaseLanguageFromLocale(d.Locale.V)
					}
					display[locale] = d.Name
				}
				key := clientmodels.ClaimPathKey(path)
				claimDisplayLookup[key] = display
			}

			metadataOrder := buildMetadataOrder(batch.CredentialMetadata.Claims)

			// Parse all claim paths upfront to detect parent claims.
			claimPaths := make([][]any, len(batch.CredentialMetadata.Claims))
			for i, claim := range batch.CredentialMetadata.Claims {
				if err := json.Unmarshal(claim.Path, &claimPaths[i]); err != nil {
					eudi.Logger.Warnf("failed to unmarshal claim path for credential %s: %v", batch.VerifiableCredentialType, err)
				}
			}

			for i, claim := range batch.CredentialMetadata.Claims {
				attrDisplay := clientmodels.TranslatedString{}
				for _, d := range claim.Display {
					locale := clientmodels.DefaultFallbackLanguage
					if d.Locale.Valid {
						locale, _ = metadata.TryGetBaseLanguageFromLocale(d.Locale.V)
					}
					attrDisplay[locale] = d.Name
				}

				claimPath := claimPaths[i]

				// Skip wildcard paths (containing null). These are display name
				// templates used by lookupDisplayName during flattening, not
				// concrete claims to resolve.
				if containsNil(claimPath) {
					continue
				}

				// If this claim is a parent of another concrete (non-wildcard)
				// metadata claim, emit only a section header. The concrete children
				// will be handled by their own entries.
				// If all children are wildcards, we must flatten the value ourselves.
				if isParentOfConcreteClaim(claimPath, claimPaths) {
					if len(attrDisplay) > 0 {
						d := attrDisplay
						attrs = append(attrs, clientmodels.Attribute{
							ClaimPath:   claimPath,
							DisplayName: &d,
						})
					}
					continue
				}

				claimValue, err := processedSdJwtPayload.GetClaimValue(claimPath)
				if err != nil {
					eudi.Logger.Debugf("unrecognized claim at path %v; falling back to empty string for claim with path %v: %v", claim.Path, claimPath, err)
					claimValue = ""
				}

				attrs = FlattenClaimValue(attrs, claimPath, claimValue, attrDisplay, claimDisplayLookup, metadataOrder)
			}
		}

		exp := int64(0)
		if batch.ExpiresAt.Valid {
			exp = batch.ExpiresAt.V.Unix()
		}

		// Try get the credential image from filesystem storage, if it exists.
		credentialLogoManager := s.fileStorage.Credentials().LogoManager()
		issuerLogoManager := s.fileStorage.Issuers().LogoManager()

		var issuerImage *clientmodels.Image = nil
		var credentialImage *clientmodels.Image = nil

		// TODO: since we don't know which display is actually used by the client, we are currently just trying to get the logos for the first display. We should implement a more robust solution for this in the future, potentially by storing a separate logo for each display/language in the filesystem and retrieving the correct one based on the client's language preferences.
		if len(batch.IssuerDisplay) > 0 && batch.IssuerDisplay[0].LogoURI != "" {
			display := batch.IssuerDisplay[0]

			eudi.Logger.Debugf("Attempting to retrieve logo for issuer %s from filesystem storage by uri %s", batch.ID, display.LogoURI)
			filename := issuerLogoManager.GetLogoFilenameWithoutExtensionFromUrl(display.LogoURI)

			if exists, err := issuerLogoManager.LogoExists(filename); err == nil && exists {
				logoData, err := issuerLogoManager.GetLogo(filename)
				if err != nil {
					eudi.Logger.Debugf("Error retrieving logo for issuer %s from filesystem storage: %v", batch.ID, err)
				} else {
					issuerImage = &clientmodels.Image{
						Base64: *logoData,
					}
				}
			} else {
				eudi.Logger.Debugf("Couldn't find image")
			}
		}

		var credentialLogoFilename string
		if batch.CredentialMetadata != nil && len(batch.CredentialMetadata.Display) > 0 && batch.CredentialMetadata.Display[0].LogoURI != "" {
			eudi.Logger.Debugf("Attempting to retrieve logo for credential %s from filesystem storage by uri %s", batch.ID, batch.CredentialMetadata.Display[0].LogoURI)
			credentialLogoFilename = credentialLogoManager.GetLogoFilenameWithoutExtensionFromUrl(batch.CredentialMetadata.Display[0].LogoURI)

			if exists, err := credentialLogoManager.LogoExists(credentialLogoFilename); err == nil && exists {
				logoData, err := credentialLogoManager.GetLogo(credentialLogoFilename)
				if err != nil {
					eudi.Logger.Debugf("Error retrieving logo for credential %s from filesystem storage: %v", batch.ID, err)
				} else {
					credentialImage = &clientmodels.Image{
						Base64: *logoData,
					}
				}
			} else {
				eudi.Logger.Debugf("Couldn't find image")
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
			IssuanceDate:                 batch.IssuedAt.Unix(),
			ExpiryDate:                   exp,
			Revoked:                      false, // revocation is not yet implemented, so default to false for now
			RevocationSupported:          false,
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
	metadata metadata.CredentialIssuerMetadata,
	requireCryptographicKeyBinding bool,
	publicKeyIdentifiers []models.PublicHolderBindingKey,
) error {
	if len(verifiedSdJwtVcs) == 0 {
		return nil // nothing to store
	}

	if requireCryptographicKeyBinding && len(publicKeyIdentifiers) != len(verifiedSdJwtVcs) {
		return fmt.Errorf(
			"publicKeyIdentifiers length (%d) must equal verifiedSdJwtVcs length (%d) when cryptographic key binding is used",
			len(publicKeyIdentifiers), len(verifiedSdJwtVcs),
		)
	}

	// All instances in a batch share the same vct, issuer, and timing claims.
	// Use the first credential as the source of truth for batch-level metadata.
	first := verifiedSdJwtVcs[0]

	// The hash will be a hash over the ProcessedSdJwtPayload, which is the same for all credentials in the batch since they share the same claims.
	processedSdJwtPayloadBytes, err := json.Marshal(first.ProcessedSdJwtPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal processed SD-JWT payload: %w", err)
	}

	hash, err := hashForSdJwtVc(first.IssuerSignedJwtPayload.VerifiableCredentialType, processedSdJwtPayloadBytes)
	if err != nil {
		return fmt.Errorf("failed to compute credential hash: %w", err)
	}

	// If a batch with this hash already exists, delete it so the new issuance
	// replaces it (e.g. with updated timestamps or a fresh holder binding key).
	if existing, err := s.credentialStore.GetBatchByHash(hash); err == nil {
		if err := s.credentialStore.DeleteBatch(existing.ID); err != nil {
			return fmt.Errorf("failed to delete existing batch before re-issuance: %w", err)
		}
	}

	issuedAt := time.Unix(first.IssuerSignedJwtPayload.IssuedAt, 0)

	// Since Expiry and NotBefore are not (yet) optional, we will directly assign them to time.Unix, potentially resulting in a zero time if the claims are missing
	exp := datatypes.NullTime{
		V:     time.Unix(first.IssuerSignedJwtPayload.Expiry, 0),
		Valid: true,
	}
	nbf := datatypes.NullTime{
		V:     time.Unix(first.IssuerSignedJwtPayload.NotBefore, 0),
		Valid: true,
	}

	batchSize := uint(len(verifiedSdJwtVcs))
	instances := make([]models.IssuedCredentialInstance, batchSize)
	for i, v := range verifiedSdJwtVcs {
		instances[i] = models.IssuedCredentialInstance{
			RawCredential: []byte(v.GetRawSdJwtVc()),
		}

		// TODO: optional check for future development: search the correct key in the key store based on the cnf in the credential and assign its ID here, instead of assuming the order of publicKeyIdentifiers matches the order of verifiedSdJwtVcs
		//if requireCryptographicKeyBinding {		}
	}

	// Convert metadata to the format expected by storage
	credentialConfiguration := metadata.CredentialConfigurationsSupported[credentialConfigurationId]
	credentialConfigurationModel := models.CredentialMetadata{}
	if credentialConfiguration.CredentialMetadata != nil {
		claimModels := make([]models.CredentialClaim, len(credentialConfiguration.CredentialMetadata.Claims))
		for i, claim := range credentialConfiguration.CredentialMetadata.Claims {
			claimPath, err := json.Marshal(claim.Path)
			if err != nil {
				return fmt.Errorf("failed to marshal claim path: %w", err)
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

		credentialConfigurationModel.Claims = claimModels
		credentialConfigurationModel.Display = slices.Collect(credentialConfiguration.CredentialMetadata.Display.ToStorageModelIterator())
	}

	batch := &models.CredentialBatch{
		IssuerURL:                first.IssuerSignedJwtPayload.Issuer,
		VerifiableCredentialType: first.IssuerSignedJwtPayload.VerifiableCredentialType,
		Format:                   models.CredentialFormat(credentialConfiguration.Format),
		Hash:                     hash,
		ProcessedSdJwtPayload:    datatypes.JSON(processedSdJwtPayloadBytes),
		CredentialIssuer:         first.IssuerSignedJwtPayload.Issuer,
		IssuerDisplay:            slices.Collect(metadata.Display.ToStorageModelIterator()),
		CredentialMetadata:       &credentialConfigurationModel,
		IssuedAt:                 issuedAt,
		ExpiresAt:                exp,
		NotBefore:                nbf,
		BatchSize:                batchSize,
		RemainingCount:           batchSize,
		Instances:                instances,
	}

	return s.credentialStore.StoreBatch(batch)
}

// isParentOfConcreteClaim returns true if path is a strict prefix of any other
// concrete (non-wildcard) path in allPaths.
func isParentOfConcreteClaim(path []any, allPaths [][]any) bool {
	for _, other := range allPaths {
		if containsNil(other) {
			continue
		}
		if len(other) > len(path) {
			match := true
			for i := range path {
				if fmt.Sprintf("%v", path[i]) != fmt.Sprintf("%v", other[i]) {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// FlattenClaimValue recursively flattens arrays and objects into individual scalar
// attributes. Each leaf value gets its own Attribute with the full path from root.
// A section header (Value == nil) is emitted only when the path has an explicit
// display name in the metadata lookup — inherited display names don't trigger headers.
// Object keys are ordered by their position in the metadata (via metadataOrder),
// falling back to alphabetical for keys not in the metadata.
func FlattenClaimValue(
	attrs []clientmodels.Attribute,
	path []any,
	value any,
	display clientmodels.TranslatedString,
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
			childDisplay := childDisplayName(lookup, childPath, display)
			attrs = FlattenClaimValue(attrs, childPath, elem, childDisplay, lookup, metadataOrder)
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
			childDisplay := childDisplayName(lookup, childPath, display)
			attrs = FlattenClaimValue(attrs, childPath, v[key], childDisplay, lookup, metadataOrder)
		}
	default:
		var dn *clientmodels.TranslatedString
		if len(path) == 0 || !isArrayIndex(path[len(path)-1]) {
			d := display
			dn = &d
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

// buildMetadataOrder creates a map from serialized claim path to position index
// for ordering object keys by their metadata position.
func buildMetadataOrder(claims []models.CredentialClaim) map[string]int {
	order := make(map[string]int, len(claims))
	for i, claim := range claims {
		var path []any
		if err := json.Unmarshal(claim.Path, &path); err != nil {
			continue
		}
		order[clientmodels.ClaimPathKey(path)] = i
	}
	return order
}

// containsNil returns true if the path contains a nil component (null wildcard).
func containsNil(path []any) bool {
	for _, c := range path {
		if c == nil {
			return true
		}
	}
	return false
}

// isArrayIndex returns true if the path component is a numeric array index.
func isArrayIndex(component any) bool {
	switch component.(type) {
	case int, float64:
		return true
	}
	return false
}

// childDisplayName looks up display names for a child path created during flattening.
// It first checks whether the metadata contains a claim entry for the exact child path.
// If not, it tries a wildcard match (replacing integer indices with nil).
// If that also fails, it falls back to the parent's display names.
func childDisplayName(lookup map[string]clientmodels.TranslatedString, childPath []any, parentDisplay clientmodels.TranslatedString) clientmodels.TranslatedString {
	if d, ok := lookupDisplayName(lookup, childPath); ok {
		return d
	}
	return parentDisplay
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
