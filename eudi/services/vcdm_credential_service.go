package services

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmstatus"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"gorm.io/datatypes"
)

// sdJwtVcdmCredentialService is the SD-JWT-secured W3C VCDM CredentialFormatStore:
// it verifies the holder key bindings of freshly issued VCDM credentials,
// persists them as one VcdmBatch, and renders stored batches for the app.
//
// The holder binding keys are the SD-JWT VC ones (HolderBindingKeyService),
// matched by `cnf` the same way; only the instance they link to differs.
//
// Revocation is reported from the stored status that RevocationService
// maintains.
type sdJwtVcdmCredentialService struct {
	sdJwtVcdmDisplaySource
	holderBindingKeyStore db.HolderBindingKeyStore
	fileStorage           filesystem.FileSystemStorage
	revocation            *RevocationService
	currentLocale         *clientmodels.CurrentLocale
}

// NewSdJwtVcdmCredentialService returns the SD-JWT-secured VCDM store over the
// given stores and file storage. A nil revocation service reports nothing as
// revocable.
func NewSdJwtVcdmCredentialService(
	store db.VcdmStore,
	holderBindingKeyStore db.HolderBindingKeyStore,
	fileStorage filesystem.FileSystemStorage,
	revocation *RevocationService,
	currentLocale *clientmodels.CurrentLocale,
) *sdJwtVcdmCredentialService {
	return &sdJwtVcdmCredentialService{
		sdJwtVcdmDisplaySource: newSdJwtVcdmDisplaySource(store),
		holderBindingKeyStore:  holderBindingKeyStore,
		fileStorage:            fileStorage,
		revocation:             revocation,
		currentLocale:          currentLocale,
	}
}

var _ CredentialFormatStore = (*sdJwtVcdmCredentialService)(nil)

func (s *sdJwtVcdmCredentialService) DeleteByHash(hash string) error {
	return s.store.DeleteBatchByHashAndFormat(hash, models.CredentialFormatSdJwtVcdm)
}

// List renders every stored VCDM batch for the app.
func (s *sdJwtVcdmCredentialService) List() ([]*clientmodels.Credential, error) {
	batches, err := s.store.ListBatches()
	if err != nil {
		return nil, err
	}

	revoked, revocable := map[string]bool{}, map[string]bool{}
	if s.revocation != nil {
		revoked, revocable, err = s.revocation.BatchRevocation(s.store)
		if err != nil {
			return nil, err
		}
	}

	locale := s.currentLocale.Get()
	credentialLogoManager := s.fileStorage.Credentials().LogoManager()
	issuerLogoManager := s.fileStorage.Issuers().LogoManager()

	result := make([]*clientmodels.Credential, 0, len(batches))
	for _, batch := range batches {
		var document vcdm.Document
		if err := json.Unmarshal(batch.ProcessedPayload, &document); err != nil {
			document = nil
		}
		documentDisplay := NewVcdmDocumentDisplay(document, isOpenBadgesBatch(batch))

		display := resolveVcdmDisplay(batch, documentDisplay, locale)
		// Fall back to the type identity when neither the credential nor the
		// issuer gives display text this locale can resolve, as the SD-JWT VC
		// list does with the vct.
		credentialName := display.CredentialName
		if credentialName == "" {
			credentialName = batch.TypeIdentity
		}

		issuedAt := batch.IssuedAt.Unix()
		var exp *int64
		if batch.ExpiresAt.Valid {
			x := batch.ExpiresAt.V.Unix()
			exp = &x
		}

		result = append(result, &clientmodels.Credential{
			CredentialId: batch.TypeIdentity,
			Hash:         batch.Hash,
			Image:        loadDocumentLogo(credentialLogoManager, documentDisplay.CredentialImage, vcdmCredentialLogoURIs(batch), locale),
			Name:         credentialName,
			Issuer: clientmodels.TrustedParty{
				Id:       batch.CredentialIssuer,
				Name:     display.IssuerName,
				Image:    loadDocumentLogo(issuerLogoManager, documentDisplay.IssuerImage, IssuerLogoURIsByLanguage(VcdmIssuerDisplays(batch)), locale),
				Verified: batch.IssuerVerified,
			},
			CredentialInstanceIds: map[clientmodels.CredentialFormat]string{
				clientmodels.Format_SdJwtVcdm: batch.Hash,
			},
			BatchInstanceCountsRemaining: batchInstanceCounts(models.CredentialFormatSdJwtVcdm, batch.BatchSize, &batch.RemainingCount),
			Attributes:                   showVcdmClaimImages(BuildAttributesFromVcdmDocument(document, display.ClaimNames, display.ClaimOrder), document, batch, credentialLogoManager),
			ExpiryDate:                   exp,
			IssuanceDate:                 &issuedAt,
			Revoked:                      revoked[batch.Hash],
			RevocationSupported:          revocable[batch.Hash],
			IssueURL:                     nil,
		})
	}

	return result, nil
}

// Store builds a VcdmBatch from the supplied parsed credentials and metadata,
// then persists the batch and all its instances in one transaction.
//
// publicKeyIdentifiers must either be empty (no cryptographic key binding
// required) or have exactly the same length as parsedCredentials. All
// credentials are assumed to come from one credential_configuration_id and so
// share their type identity, issuer and validity.
func (s *sdJwtVcdmCredentialService) Store(
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
		if p.SdJwtVcdm == nil {
			return fmt.Errorf("credential %d is not an SD-JWT-secured VCDM credential (format %q); the VCDM store cannot hold it", i, p.Format)
		}
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
			deleteOrphanedKeys(s.holderBindingKeyStore, publicKeyIdentifiers)
			return err
		}
	}

	// Each copy has its own status entries, so the references are read per
	// copy. They are read and checked here, before anything is stored, so a
	// malformed issuance fails before it touches the user's existing batch.
	statusRefs := make([]vcdmstatus.StatusReferences, len(parsedCredentials))
	for i, p := range parsedCredentials {
		refs, err := vcdmstatus.ParseStatusReferences(p.SdJwtVcdm.Document)
		if err != nil {
			if requireCryptographicKeyBinding {
				deleteOrphanedKeys(s.holderBindingKeyStore, publicKeyIdentifiers)
			}
			return fmt.Errorf("credential %d: %w", i, err)
		}
		statusRefs[i] = refs
	}
	if err := validateVcdmStatusReferences(statusRefs); err != nil {
		if requireCryptographicKeyBinding {
			deleteOrphanedKeys(s.holderBindingKeyStore, publicKeyIdentifiers)
		}
		return err
	}

	// All instances in a batch are copies of one logical credential; the first
	// is the source of truth for batch-level metadata.
	first := parsedCredentials[0]

	// The parser's CheckBatch expanded the types, or refused the batch.
	if len(first.ExpandedTypes) == 0 {
		err := fmt.Errorf("the credential's types were not expanded")
		if requireCryptographicKeyBinding {
			deleteOrphanedKeys(s.holderBindingKeyStore, publicKeyIdentifiers)
		}
		return err
	}

	expandedTypes, err := json.Marshal(first.ExpandedTypes)
	if err != nil {
		return fmt.Errorf("failed to marshal the expanded types: %w", err)
	}

	processedPayload, err := json.Marshal(first.SdJwtVcdm.Document)
	if err != nil {
		return fmt.Errorf("failed to marshal processed SD-JWT payload: %w", err)
	}

	// The store replaces a batch with this hash, the same credential issued
	// before, in the transaction that stores this one.
	hash, err := hashForVcdmCredential(first.VerifiableCredentialType, first.IssuerIdentifier, sdjwt.ProcessedPayload(first.SdJwtVcdm.Document))
	if err != nil {
		return fmt.Errorf("failed to compute credential hash: %w", err)
	}

	// Absent configuration is tolerated: everything read from it below is
	// display metadata, which degrades to empty rather than making a verified
	// credential unstorable.
	credentialConfiguration, credentialConfigurationFound := issuerMetadata.CredentialConfigurationsSupported[credentialConfigurationId]
	if reason := missingDisplayMetadataReason(credentialConfigurationId, credentialConfiguration, credentialConfigurationFound); reason != "" {
		eudi.Logger.Warnf("VCDM credential from issuer %q will render as its raw type %q: %s", first.IssuerIdentifier, first.VerifiableCredentialType, reason)
	}

	issuerDisplay, credentialMetadata, err := displaySnapshots(issuerMetadata, credentialConfiguration)
	if err != nil {
		return err
	}

	instances := make([]models.VcdmBatchInstance, len(parsedCredentials))
	now := time.Now()
	for i, p := range parsedCredentials {
		instances[i], err = withStatusReferences(models.VcdmBatchInstance{RawCredential: p.RawCredentialBytes}, statusRefs[i], now)
		if err != nil {
			return err
		}
	}

	batch := &models.VcdmBatch{
		TypeIdentity:     first.VerifiableCredentialType,
		IssuerIdentifier: first.IssuerIdentifier,
		CredentialIssuer: issuerMetadata.CredentialIssuer,
		Format:           models.CredentialFormatSdJwtVcdm,
		Hash:             hash,
		ProcessedPayload: datatypes.JSON(processedPayload),
		ExpandedTypes:    expandedTypes,
		BatchSize:        uint(len(parsedCredentials)),
		RemainingCount:   uint(len(parsedCredentials)),
		// Reaching this point means the issuer was authenticated: the parser
		// returns an error, not a ParsedCredential, otherwise.
		IssuerVerified:     true,
		IssuerDisplay:      issuerDisplay,
		CredentialMetadata: credentialMetadata,
		Instances:          instances,
	}

	if first.IssuedAt != nil {
		batch.IssuedAt = time.Unix(*first.IssuedAt, 0)
	} else {
		// Neither a JWT iat nor a document validFrom is present; the batch
		// model requires an issuance timestamp, so record the receipt time.
		batch.IssuedAt = time.Now()
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
		for i, keyID := range matchedKeyIDs {
			if err := s.holderBindingKeyStore.LinkToVcdmInstance(keyID, batch.Instances[i].ID); err != nil {
				eudi.Logger.Warnf("failed to link holder binding key %s to VCDM instance %s: %v", keyID, batch.Instances[i].ID, err)
			}
		}
	}

	return nil
}

// VcdmIssuanceValidity derives the wallet's issuance/validity timestamps for a
// verified SD-JWT-secured VCDM credential. They are the credential's own, the
// JWT iat, nbf and exp, which VC-JOSE-COSE makes the issuance and validity of
// the signature, as SD-JWT VC records them. The document's validFrom and
// validUntil are the validity of the data, which is for a verifier to judge;
// they stand in only when the JWT carries no such claim. This only decides
// which timestamps the wallet records and displays.
func VcdmIssuanceValidity(v *vcdmsdjwt.VerifiedSdJwtVcdm) (issuedAt, expiresAt, notBefore *int64) {
	// Document.Validate ran at receipt, so the error returns are impossible.
	validFrom, hasValidFrom, _ := v.Document.ValidFrom()
	validUntil, hasValidUntil, _ := v.Document.ValidUntil()

	issuedAt, notBefore, expiresAt = v.RegisteredClaims.IssuedAt, v.RegisteredClaims.NotBefore, v.RegisteredClaims.Expiry
	if hasValidFrom {
		unix := validFrom.Unix()
		if issuedAt == nil {
			issuedAt = &unix
		}
		if notBefore == nil {
			notBefore = &unix
		}
	}
	if hasValidUntil && expiresAt == nil {
		unix := validUntil.Unix()
		expiresAt = &unix
	}
	return issuedAt, expiresAt, notBefore
}

// BuildAttributesFromVcdmDocument emits attributes for the credentialSubject
// tree of a VCDM document, with document-rooted claim paths
// (["credentialSubject", ...]). The envelope properties (@context, type,
// issuer, validity, status, ...) are not attributes; they surface through the
// credential's own metadata fields.
func BuildAttributesFromVcdmDocument(
	doc vcdm.Document,
	lookup map[string]string,
	metadataOrder map[string]int,
) []clientmodels.Attribute {
	attrs := []clientmodels.Attribute{}
	subject, ok := doc[vcdm.CredentialSubjectKey]
	if !ok {
		return attrs
	}
	return FlattenClaimValue(attrs, []any{vcdm.CredentialSubjectKey}, subject, lookup, metadataOrder)
}

// validateVcdmStatusReferences enforces the batch status invariants (see
// requireDedicatedStatusEntries) for both kinds of status reference a VCDM
// credential can carry. A Bitstring entry is identified by its list and index:
// two instances on one position share its bit, whatever their purposes.
func validateVcdmStatusReferences(refs []vcdmstatus.StatusReferences) error {
	type bitstringPosition struct {
		list  string
		index uint64
	}
	tokenStatusLists := make([][]statuslist.Reference, len(refs))
	bitstringPositions := make([][]bitstringPosition, len(refs))
	for i, r := range refs {
		if r.TokenStatusList != nil {
			tokenStatusLists[i] = []statuslist.Reference{*r.TokenStatusList}
		}
		for _, entry := range r.Bitstring {
			bitstringPositions[i] = append(bitstringPositions[i], bitstringPosition{entry.StatusListCredential, entry.StatusListIndex})
		}
	}
	if err := requireDedicatedStatusEntries("status_list", tokenStatusLists); err != nil {
		return err
	}
	return requireDedicatedStatusEntries("credentialStatus", bitstringPositions)
}

// vcdmNonContentKeys are the top-level keys stripped before hashing a VCDM
// credential for batch deduplication: the JWT/SD-JWT securing claims plus the
// per-issuance envelope properties (identifier, validity window, status
// references). Two issuances with the same content then produce the same hash,
// so such a re-issuance replaces the stored batch — mirroring hashForSdJwtVc's
// treatment of the IETF SD-JWT VC registered claims. credentialSubject is
// content, its id included: a re-issuance to a new subject id, such as a fresh
// holder DID, is stored as a second credential.
var vcdmNonContentKeys = []string{
	jwt.IssuerKey,
	jwt.SubjectKey,
	jwt.AudienceKey,
	jwt.IssuedAtKey,
	jwt.NotBeforeKey,
	jwt.ExpirationKey,
	jwt.JwtIDKey,
	sdjwt.ConfirmationKey,
	sdjwt.SdKey,
	sdjwt.SdAlgKey,
	statuslist.StatusClaimKey,
	vcdm.IDKey,
	vcdm.ValidFromKey,
	vcdm.ValidUntilKey,
	vcdm.CredentialStatusKey,
}

// hashForVcdmCredential computes the deterministic batch-deduplication hash
// for an SD-JWT-secured VCDM credential over its type identity, its issuer and
// its content (see vcdmNonContentKeys for what is stripped), through the same
// credentialHash every other format uses. Same stability properties as
// hashForSdJwtVc: json.Marshal sorts object keys, array order is significant.
func hashForVcdmCredential(typeIdentity, issuerIdentifier string, payload sdjwt.ProcessedPayload) (string, error) {
	contentBytes, err := json.Marshal(withoutKeys(payload, vcdmNonContentKeys...))
	if err != nil {
		return "", fmt.Errorf("hashForVcdmCredential: failed to marshal content: %w", err)
	}

	return credentialHash(typeIdentity, issuerIdentifier, contentBytes), nil
}

// --- display ---

// VcdmIssuerDisplays decodes the batch's issuer display snapshot into the
// storage shape the SD-JWT VC display helpers read. Malformed or absent JSON
// reads as no display entries.
func VcdmIssuerDisplays(batch *models.VcdmBatch) []models.IssuerMetadataDisplay {
	if len(batch.IssuerDisplay) == 0 {
		return nil
	}
	var displays metadata.CredentialIssuerDisplays
	if err := json.Unmarshal(batch.IssuerDisplay, &displays); err != nil {
		return nil
	}
	return slices.Collect(displays.ToStorageModelIterator())
}

// VcdmCredentialMetadata decodes the batch's credential_metadata snapshot into
// the storage shape the SD-JWT VC display helpers read, or returns nil when the
// issuer advertised none (or the snapshot is unreadable).
func VcdmCredentialMetadata(batch *models.VcdmBatch) *models.CredentialMetadata {
	if len(batch.CredentialMetadata) == 0 {
		return nil
	}
	var cm metadata.CredentialMetadata
	if err := json.Unmarshal(batch.CredentialMetadata, &cm); err != nil {
		return nil
	}
	return convertCredentialMetadata(metadata.CredentialConfiguration{CredentialMetadata: &cm})
}

// ResolveVcdmDisplay is ResolveBatchDisplay for a VCDM batch, with the
// credential's and the issuer's name taken from the document first
// (VcdmDocumentDisplay).
func ResolveVcdmDisplay(batch *models.VcdmBatch, locale string) ResolvedBatchDisplay {
	return resolveVcdmDisplay(batch, vcdmBatchDocumentDisplay(batch), locale)
}

func resolveVcdmDisplay(batch *models.VcdmBatch, document VcdmDocumentDisplay, locale string) ResolvedBatchDisplay {
	d := resolveSdJwtBatchDisplay(batch.CredentialIssuer, VcdmIssuerDisplays(batch), VcdmCredentialMetadata(batch), locale)
	if name := clientmodels.Resolve(document.CredentialNames, locale); name != "" {
		d.CredentialName = name
	}
	if name := clientmodels.Resolve(document.IssuerNames, locale); name != "" {
		d.IssuerNames = document.IssuerNames
		d.IssuerName = name
	}
	return d
}

// VcdmDocumentDisplay is how a VCDM document says it looks: the credential's
// name and image, and its issuer's name and logo. Each comes before what the
// OpenID4VCI metadata says, per field, as an SD-JWT VC's type metadata does:
// OpenID4VCI 1.0 §12.2.4 says "Format-specific mechanisms ... are always
// preferred by the Wallet over the information in this object, which serves as
// the default fallback". The document is also the more specific of the two: the
// metadata describes a credential configuration, the document one credential.
//
// Names are keyed by base language; an image is a URI to download or a data
// URI, "" when there is none.
type VcdmDocumentDisplay struct {
	CredentialNames clientmodels.TranslatedString
	CredentialImage string
	IssuerNames     clientmodels.TranslatedString
	IssuerImage     string
}

// NewVcdmDocumentDisplay reads a document's display. The credential's image is
// its `image`, or in an Open Badges credential without one, its achievement's
// image: the badge's picture.
func NewVcdmDocumentDisplay(document vcdm.Document, openBadges bool) VcdmDocumentDisplay {
	d := VcdmDocumentDisplay{
		CredentialNames: byBaseLanguage(document.Names()),
		IssuerNames:     byBaseLanguage(document.IssuerNames()),
	}
	d.CredentialImage, _ = document.Image()
	if d.CredentialImage == "" && openBadges {
		d.CredentialImage, _ = document.AchievementImage()
	}
	d.IssuerImage, _ = document.IssuerImage()
	return d
}

// vcdmBatchDocumentDisplay is NewVcdmDocumentDisplay over a stored batch. An
// unreadable payload says nothing.
func vcdmBatchDocumentDisplay(batch *models.VcdmBatch) VcdmDocumentDisplay {
	var document vcdm.Document
	if err := json.Unmarshal(batch.ProcessedPayload, &document); err != nil {
		return VcdmDocumentDisplay{}
	}
	return NewVcdmDocumentDisplay(document, isOpenBadgesBatch(batch))
}

// byBaseLanguage keys language-tagged values by base language ("nl-NL" →
// "nl"), as the metadata displays are; nil when there are none.
func byBaseLanguage(values map[string]string) clientmodels.TranslatedString {
	if len(values) == 0 {
		return nil
	}
	result := clientmodels.TranslatedString{}
	for tag, value := range values {
		if base, ok := clientmodels.BaseLanguage(tag); ok {
			tag = base
		}
		result[tag] = value
	}
	return result
}

// vcdmCredentialLogoURIs is CredentialLogoURIsByLanguage over a VCDM batch's
// credential metadata; nil when it has none.
func vcdmCredentialLogoURIs(batch *models.VcdmBatch) clientmodels.TranslatedString {
	if cm := VcdmCredentialMetadata(batch); cm != nil {
		return CredentialLogoURIsByLanguage(cm.Display)
	}
	return nil
}

// loadDocumentLogo loads the document's image from the logo cache or, when it
// is not there (not downloaded yet, or it cannot be), the metadata's logo as
// LoadResolvedLogo resolves it: a logo we have is shown.
func loadDocumentLogo(manager filesystem.LogoManager, documentURI string, metadataURIs clientmodels.TranslatedString, locale string) *clientmodels.Image {
	if img := eudi.LoadLogoImage(manager, documentURI); img != nil {
		return img
	}
	return LoadResolvedLogo(manager, metadataURIs, locale)
}

// VcdmDocumentName resolves the credential's own `name` (VCDM 2.0 §4.6) for the
// locale, or "" when it has none.
func VcdmDocumentName(document vcdm.Document, locale string) string {
	return clientmodels.Resolve(byBaseLanguage(document.Names()), locale)
}

// VcdmPayloadName is VcdmDocumentName over a stored processed payload. An
// unreadable payload has no name.
func VcdmPayloadName(payload datatypes.JSON, locale string) string {
	var document vcdm.Document
	if err := json.Unmarshal(payload, &document); err != nil {
		return ""
	}
	return VcdmDocumentName(document, locale)
}

// sdJwtVcdmDisplaySource is the SD-JWT-secured VCDM CredentialDisplaySource:
// the read side that needs only the store.
type sdJwtVcdmDisplaySource struct {
	store db.VcdmStore
}

func newSdJwtVcdmDisplaySource(store db.VcdmStore) sdJwtVcdmDisplaySource {
	return sdJwtVcdmDisplaySource{store: store}
}

// LiveDisplaysByType resolves the display text per stored type identity. When
// several batches share one, a batch carrying credential metadata is
// preferred. Best-effort: on a storage error the map is empty.
func (s sdJwtVcdmDisplaySource) LiveDisplaysByType(locale string) map[string]ResolvedBatchDisplay {
	batches, err := s.store.ListBatches()
	if err != nil {
		eudi.Logger.Warnf("failed to load VCDM batches for display re-resolution: %v", err)
		return map[string]ResolvedBatchDisplay{}
	}

	preferred := map[string]*models.VcdmBatch{}
	for _, batch := range batches {
		if existing, ok := preferred[batch.TypeIdentity]; ok && len(existing.CredentialMetadata) > 0 {
			continue
		}
		preferred[batch.TypeIdentity] = batch
	}

	result := make(map[string]ResolvedBatchDisplay, len(preferred))
	for typ, batch := range preferred {
		result[typ] = ResolveVcdmDisplay(batch, locale)
	}
	return result
}

// LogoURIs returns the issuer and credential logo URIs that resolve for the
// locale, per stored batch: the document's images, and the metadata's logos
// shown when those cannot be.
func (s sdJwtVcdmDisplaySource) LogoURIs(locale string) (issuer []string, credential []string) {
	batches, err := s.store.ListBatches()
	if err != nil {
		eudi.Logger.Warnf("failed to load VCDM batches for logo backfill: %v", err)
		return nil, nil
	}
	for _, batch := range batches {
		document := vcdmBatchDocumentDisplay(batch)
		issuer = append(issuer, document.IssuerImage, clientmodels.Resolve(IssuerLogoURIsByLanguage(VcdmIssuerDisplays(batch)), locale))
		credential = append(credential, document.CredentialImage, clientmodels.Resolve(vcdmCredentialLogoURIs(batch), locale))
	}
	return issuer, credential
}

// isOpenBadgesBatch reports whether a stored VCDM batch is an Open Badges
// credential, by the expanded types stored with it at issuance. A batch whose
// types cannot be read is not.
func isOpenBadgesBatch(batch *models.VcdmBatch) bool {
	var types []string
	if err := json.Unmarshal(batch.ExpandedTypes, &types); err != nil {
		return false
	}
	return vcdm.IsOpenBadgesCredential(types)
}

// showVcdmClaimImages turns a stored VCDM batch's claim images among attrs
// into pictures, with the images behind a URL from logos, the credential logo
// cache they share with the credential logos.
func showVcdmClaimImages(attrs []clientmodels.Attribute, document vcdm.Document, batch *models.VcdmBatch, logos filesystem.LogoManager) []clientmodels.Attribute {
	openBadges := isOpenBadgesBatch(batch)
	return ShowClaimImages(attrs, document, openBadges, CachedClaimImages(logos, document, openBadges))
}
