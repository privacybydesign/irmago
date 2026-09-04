package services

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"gorm.io/datatypes"
)

// mdocCredentialService is the mso_mdoc CredentialFormatStore: it matches
// freshly issued documents to the device keys minted for them, persists them as
// one MdocBatch, and renders stored batches for the app. It knows nothing about
// any other format.
type mdocCredentialService struct {
	mdocDisplaySource
	deviceKeys    db.MdocDeviceKeyStore
	fileStorage   filesystem.FileSystemStorage
	currentLocale *clientmodels.CurrentLocale
}

// NewMdocCredentialService returns the mso_mdoc store over the given stores and
// file storage.
func NewMdocCredentialService(
	store db.MdocStore,
	deviceKeys db.MdocDeviceKeyStore,
	fileStorage filesystem.FileSystemStorage,
	currentLocale *clientmodels.CurrentLocale,
) *mdocCredentialService {
	return &mdocCredentialService{
		mdocDisplaySource: newMdocDisplaySource(store),
		deviceKeys:        deviceKeys,
		fileStorage:       fileStorage,
		currentLocale:     currentLocale,
	}
}

var _ CredentialFormatStore = (*mdocCredentialService)(nil)

func (s *mdocCredentialService) DeleteByHash(hash string) error {
	return s.store.DeleteBatchByHash(hash)
}

// List renders every stored mdoc batch for the app. An mdoc carries no Token
// Status List reference today, so nothing here is ever reported revoked.
func (s *mdocCredentialService) List() ([]*clientmodels.Credential, error) {
	batches, err := s.store.ListBatches()
	if err != nil {
		return nil, err
	}

	locale := s.currentLocale.Get()
	credentialLogoManager := s.fileStorage.Credentials().LogoManager()
	issuerLogoManager := s.fileStorage.Issuers().LogoManager()

	result := make([]*clientmodels.Credential, 0, len(batches))
	for _, batch := range batches {
		display := ResolveMdocDisplay(batch, locale)
		// Fall back to the docType when the issuer published no display text this
		// locale can resolve, as mdoc_dcql.credentialDisplayName does for the
		// consent screen. Applied here rather than in ResolveMdocDisplay so the
		// activity log can still tell "no live name" from a real one.
		credentialName := display.CredentialName
		if credentialName == "" {
			credentialName = batch.DocType
		}

		var credentialImage *clientmodels.Image
		if cm := MdocCredentialMetadata(batch); cm != nil {
			credentialImage = LoadResolvedLogo(credentialLogoManager, MdocCredentialLogoURIsByLanguage(cm.Display), locale)
		}

		signedAt := batch.SignedAt.Unix()
		validUntil := batch.ValidUntil.Unix()

		result = append(result, &clientmodels.Credential{
			CredentialId:      batch.DocType,
			Hash:              batch.Hash,
			Image:             credentialImage,
			Name:              credentialName,
			DisplayIsFallback: display.DisplayIsFallback,
			Issuer: clientmodels.TrustedParty{
				Id:       batch.CredentialIssuer,
				Name:     display.IssuerName,
				Image:    LoadResolvedLogo(issuerLogoManager, MdocIssuerLogoURIsByLanguage(MdocIssuerDisplays(batch)), locale),
				Verified: batch.IssuerVerified,
			},
			CredentialInstanceIds: map[clientmodels.CredentialFormat]string{
				clientmodels.Format_MsoMdoc: batch.Hash,
			},
			BatchInstanceCountsRemaining: batchInstanceCounts(models.CredentialFormatMsoMdoc, batch.BatchSize, &batch.RemainingCount),
			Attributes:                   BuildMdocAttributes(batch, locale),
			ExpiryDate:                   &validUntil,
			IssuanceDate:                 &signedAt,
			Revoked:                      false,
			RevocationSupported:          false,
			IssueURL:                     nil,
		})
	}

	return result, nil
}

// Store matches the issued documents to the device keys minted for them,
// builds an MdocBatch and persists it with its instances in one transaction,
// then links each device key to the instance whose MSO carries its public half.
//
// publicKeyIdentifiers must either be empty (no cryptographic key binding
// required) or have exactly the same length as parsedCredentials. All
// credentials are assumed to come from one credential_configuration_id and so
// share docType, issuer and validity.
func (s *mdocCredentialService) Store(
	parsedCredentials []*ParsedCredential,
	credentialConfigurationId string,
	issuerMetadata metadata.CredentialIssuerMetadata,
	requireCryptographicKeyBinding bool,
	publicKeyIdentifiers []models.PublicHolderBindingKey,
) error {
	if len(parsedCredentials) == 0 {
		return nil
	}
	for i, p := range parsedCredentials {
		if p.Mdoc == nil {
			return fmt.Errorf("credential %d is not an mdoc (format %q); the mdoc store cannot hold it", i, p.Format)
		}
	}

	if requireCryptographicKeyBinding && len(publicKeyIdentifiers) != len(parsedCredentials) {
		return fmt.Errorf(
			"publicKeyIdentifiers length (%d) must equal parsedCredentials length (%d) when cryptographic key binding is used",
			len(publicKeyIdentifiers), len(parsedCredentials),
		)
	}

	// Match every device key before any side effect, so a mismatch aborts the
	// issuance without deleting the user's existing batch.
	var matchedKeyIDs []datatypes.UUID
	if requireCryptographicKeyBinding {
		var err error
		matchedKeyIDs, err = matchDeviceKeys(parsedCredentials, publicKeyIdentifiers)
		if err != nil {
			s.deleteOrphanedKeys(publicKeyIdentifiers)
			return err
		}
	}

	first := parsedCredentials[0]

	hash, err := s.computeHashAndDeleteExisting(first)
	if err != nil {
		return err
	}

	// Absent configuration is tolerated: everything read from it below is display
	// metadata, which degrades to empty rather than making a verified credential
	// unstorable.
	credentialConfiguration, credentialConfigurationFound := issuerMetadata.CredentialConfigurationsSupported[credentialConfigurationId]
	if reason := missingDisplayMetadataReason(credentialConfigurationId, credentialConfiguration, credentialConfigurationFound); reason != "" {
		eudi.Logger.Warnf("mdoc from issuer %q will render as its raw docType %q: %s", issuerMetadata.CredentialIssuer, first.Mdoc.DocType, reason)
	}

	issuerDisplay, credentialMetadata, err := mdocDisplaySnapshots(issuerMetadata, credentialConfiguration)
	if err != nil {
		return err
	}

	instances := make([]models.MdocBatchInstance, len(parsedCredentials))
	for i, p := range parsedCredentials {
		instances[i] = models.MdocBatchInstance{IssuerSigned: p.RawCredentialBytes}
	}

	batch := &models.MdocBatch{
		DocType:          first.Mdoc.DocType,
		CredentialIssuer: issuerMetadata.CredentialIssuer,
		Hash:             hash,
		Namespaces:       first.Mdoc.Namespaces,
		SignedAt:         first.Mdoc.ValidityInfo.Signed,
		ValidFrom:        first.Mdoc.ValidityInfo.ValidFrom,
		ValidUntil:       first.Mdoc.ValidityInfo.ValidUntil,
		BatchSize:        uint(len(parsedCredentials)),
		RemainingCount:   uint(len(parsedCredentials)),
		// Reaching this point means issuerAuth verified against an IACA anchor:
		// the parser returns an error, not a ParsedCredential, otherwise.
		IssuerVerified:     true,
		IssuerDisplay:      issuerDisplay,
		CredentialMetadata: credentialMetadata,
		Instances:          instances,
	}

	if err := s.store.StoreBatch(batch); err != nil {
		return err
	}

	if requireCryptographicKeyBinding {
		for i, keyID := range matchedKeyIDs {
			if err := s.deviceKeys.LinkToInstance(keyID, batch.Instances[i].ID); err != nil {
				eudi.Logger.Warnf("failed to link device key %s to mdoc instance %s: %v", keyID, batch.Instances[i].ID, err)
			}
		}
	}

	return nil
}

// mdocDisplaySnapshots encodes the OpenID4VCI display metadata an mdoc batch
// carries: the issuer's display[] and the configuration's credential_metadata,
// as published. Nil where the issuer advertised none.
func mdocDisplaySnapshots(issuerMetadata metadata.CredentialIssuerMetadata, config metadata.CredentialConfiguration) (issuerDisplay, credentialMetadata datatypes.JSON, err error) {
	if len(issuerMetadata.Display) > 0 {
		b, err := json.Marshal(issuerMetadata.Display)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to snapshot issuer display metadata: %w", err)
		}
		issuerDisplay = datatypes.JSON(b)
	}
	if config.CredentialMetadata != nil {
		b, err := json.Marshal(config.CredentialMetadata)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to snapshot credential metadata: %w", err)
		}
		credentialMetadata = datatypes.JSON(b)
	}
	return issuerDisplay, credentialMetadata, nil
}

// computeHashAndDeleteExisting computes the document's content hash — docType,
// credential issuer, element values — and makes room for it, refusing
// while a stored batch under the same hash is still presentable and replacing
// it once it is not. Same rule and same reasoning as the SD-JWT VC store's
// computeHashAndDeleteExisting; see there.
func (s *mdocCredentialService) computeHashAndDeleteExisting(p *ParsedCredential) (string, error) {
	namespaces, err := json.Marshal(p.Mdoc.Namespaces)
	if err != nil {
		return "", fmt.Errorf("failed to encode mdoc namespaces for hashing: %w", err)
	}
	hash, err := hashGeneric(p.Mdoc.DocType, p.IssuerIdentifier, namespaces)
	if err != nil {
		return "", fmt.Errorf("failed to compute credential hash: %w", err)
	}

	if existing, err := s.store.GetBatchByHash(hash); err == nil {
		if reason := mdocBatchStillUsable(existing, time.Now()); reason != "" {
			return "", fmt.Errorf(
				"credential %q is already held (stored copy issued by %q) and %s; re-issuing identical claims would replace it and discard its unused instances",
				existing.DocType, existing.CredentialIssuer, reason)
		}
		if err := s.store.DeleteBatch(existing.ID); err != nil {
			return "", fmt.Errorf("failed to delete existing batch before re-issuance: %w", err)
		}
	}

	return hash, nil
}

// mdocBatchStillUsable reports why a stored batch has unspent documents worth
// keeping, or "" when it may be replaced. The mdoc counterpart of
// batchStillUsable, with the mdoc validity window: a batch of one is always
// replaceable, a batched credential is protected while it is within its
// validity window and has documents left.
func mdocBatchStillUsable(batch *models.MdocBatch, now time.Time) string {
	if batch.BatchSize <= 1 {
		return ""
	}
	if !MdocBatchIsValid(batch, now) {
		return ""
	}
	if batch.RemainingCount == 0 {
		return ""
	}
	return fmt.Sprintf("still has %d of %d instances unused", batch.RemainingCount, batch.BatchSize)
}

// MdocBatchIsValid reports whether now falls inside the batch's MSO validity
// window. Both bounds are mandatory in ISO 18013-5 and stored NOT NULL, so
// there is no "unset" case to special-case.
func MdocBatchIsValid(batch *models.MdocBatch, now time.Time) bool {
	return !now.Before(batch.ValidFrom) && !now.After(batch.ValidUntil)
}

// matchDeviceKeys resolves, for every document in the batch, the minted device
// key whose thumbprint matches the device public key in the document's MSO.
// Thumbprint only: that is the one identity both the mint side (MdocKeyService)
// and the parser derive, whatever binding method the proof used.
func matchDeviceKeys(parsedCredentials []*ParsedCredential, publicKeyIdentifiers []models.PublicHolderBindingKey) ([]datatypes.UUID, error) {
	keyByThumbprint := make(map[string]datatypes.UUID, len(publicKeyIdentifiers))
	for _, pk := range publicKeyIdentifiers {
		if pk.PublicKeyThumbprint != nil {
			keyByThumbprint[*pk.PublicKeyThumbprint] = pk.ID
		}
	}

	result := make([]datatypes.UUID, len(parsedCredentials))
	for i, p := range parsedCredentials {
		if p.Mdoc.DeviceKeyThumbprint == "" {
			return nil, fmt.Errorf("credential %d requires holder binding but its MSO carries no device key", i)
		}
		keyID, ok := keyByThumbprint[p.Mdoc.DeviceKeyThumbprint]
		if !ok {
			return nil, fmt.Errorf("credential %d: no matching device key found for thumbprint %s", i, p.Mdoc.DeviceKeyThumbprint)
		}
		result[i] = keyID
	}
	return result, nil
}

func (s *mdocCredentialService) deleteOrphanedKeys(publicKeyIdentifiers []models.PublicHolderBindingKey) {
	ids := make([]datatypes.UUID, len(publicKeyIdentifiers))
	for i, pk := range publicKeyIdentifiers {
		ids[i] = pk.ID
	}
	if err := s.deviceKeys.DeleteKeys(ids); err != nil {
		eudi.Logger.Warnf("failed to clean up orphaned device keys: %v", err)
	}
}

// --- read side shared with the activity log and the logo backfill ---

// mdocDisplaySource is the mso_mdoc CredentialDisplaySource: the read side that
// needs only the store.
type mdocDisplaySource struct {
	store db.MdocStore
}

func newMdocDisplaySource(store db.MdocStore) mdocDisplaySource {
	return mdocDisplaySource{store: store}
}

// LiveDisplaysByType resolves the display text per stored docType. When several
// batches share a docType, one carrying credential metadata is preferred.
// Best-effort: on a storage error the map is empty.
func (s mdocDisplaySource) LiveDisplaysByType(locale string) map[string]ResolvedBatchDisplay {
	batches, err := s.store.ListBatches()
	if err != nil {
		eudi.Logger.Warnf("failed to load mdoc batches for display re-resolution: %v", err)
		return map[string]ResolvedBatchDisplay{}
	}

	preferred := map[string]*models.MdocBatch{}
	for _, batch := range batches {
		if existing, ok := preferred[batch.DocType]; ok && len(existing.CredentialMetadata) > 0 {
			continue
		}
		preferred[batch.DocType] = batch
	}

	result := make(map[string]ResolvedBatchDisplay, len(preferred))
	for docType, batch := range preferred {
		result[docType] = ResolveMdocDisplay(batch, locale)
	}
	return result
}

// LogoURIs returns the issuer and credential logo URIs that resolve for the
// locale, one per stored batch.
func (s mdocDisplaySource) LogoURIs(locale string) (issuer []string, credential []string) {
	batches, err := s.store.ListBatches()
	if err != nil {
		eudi.Logger.Warnf("failed to load mdoc batches for logo backfill: %v", err)
		return nil, nil
	}
	for _, batch := range batches {
		issuer = append(issuer, clientmodels.Resolve(MdocIssuerLogoURIsByLanguage(MdocIssuerDisplays(batch)), locale))
		if cm := MdocCredentialMetadata(batch); cm != nil {
			credential = append(credential, clientmodels.Resolve(MdocCredentialLogoURIsByLanguage(cm.Display), locale))
		}
	}
	return issuer, credential
}
