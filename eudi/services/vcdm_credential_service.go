package services

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
)

// VerifyAndStoreIssuedVcdmCredentials persists a batch of verified
// SD-JWT-secured VCDM credentials, mirroring VerifyAndStoreIssuedCredentials
// for the W3C VCDM data model. Per the storage decision (#679), the VCDM
// format forms its own logical batch (the cross-data-model grouping that
// would link it to other formats of the same credential is follow-up work):
// the existing CredentialBatch model is reused with the raw secured blob per
// instance plus the extracted document as batch metadata, and the credential
// type identity is the @context+type composite.
//
// W3C VCDM credentials reference status through `credentialStatus`
// (BitstringStatusList), not the IETF Token Status List; the wallet's
// Bitstring checker is separate follow-up work, so no status references are
// validated or seeded here — the instances keep LastKnownStatus's zero value
// (StatusUnknown) and are not status-checkable yet.
func (s *credentialService) VerifyAndStoreIssuedVcdmCredentials(
	verified []*vcdmsdjwt.VerifiedSdJwtVcdm,
	credentialConfigurationId string,
	issuerMetadata metadata.CredentialIssuerMetadata,
	requireCryptographicKeyBinding bool,
	publicKeyIdentifiers []models.PublicHolderBindingKey,
) error {
	if len(verified) == 0 {
		return nil // nothing to store
	}

	if requireCryptographicKeyBinding && len(publicKeyIdentifiers) != len(verified) {
		return fmt.Errorf(
			"publicKeyIdentifiers length (%d) must equal verified credentials length (%d) when cryptographic key binding is used",
			len(publicKeyIdentifiers), len(verified),
		)
	}

	// Match all holder binding keys upfront before any side effects, so that a
	// mismatch aborts the issuance without deleting the user's existing batch.
	var matchedKeyIDs []datatypes.UUID
	if requireCryptographicKeyBinding {
		cnfs := make([]*sdjwt.CnfField, len(verified))
		for i, v := range verified {
			cnfs[i] = v.RegisteredClaims.Confirm
		}
		var err error
		matchedKeyIDs, err = matchAllHolderBindingKeys(cnfs, publicKeyIdentifiers)
		if err != nil {
			s.deleteOrphanedKeys(publicKeyIdentifiers)
			return err
		}
	}

	// All instances in a batch are copies of one logical credential; the first
	// is the source of truth for batch-level metadata.
	first := verified[0]
	typeIdentity := first.Document.TypeIdentity()

	// The document's issuer is authoritative for VCDM (the JWT iss, when
	// present, was cross-checked against it during verification), and it
	// cannot be malformed here: Document.Validate ran at receipt.
	issuerID, err := first.Document.IssuerID()
	if err != nil {
		return fmt.Errorf("failed to read VCDM issuer: %w", err)
	}

	processedPayload, err := json.Marshal(first.ProcessedSdJwtPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal processed SD-JWT payload: %w", err)
	}

	hash, err := hashForVcdmCredential(typeIdentity, first.ProcessedSdJwtPayload)
	if err != nil {
		return fmt.Errorf("failed to compute credential hash: %w", err)
	}

	// If a batch with this hash already exists, delete it so the new issuance
	// replaces it (e.g. with updated timestamps or a fresh holder binding key).
	if err := s.deleteExistingBatchByHash(hash); err != nil {
		return err
	}

	credentialConfiguration := issuerMetadata.CredentialConfigurationsSupported[credentialConfigurationId]

	batch := &models.CredentialBatch{
		IssuerURL:                issuerID,
		VerifiableCredentialType: typeIdentity,
		Format:                   models.CredentialFormatSdJwtVcdm,
		Hash:                     hash,
		ProcessedSdJwtPayload:    datatypes.JSON(processedPayload),
		CredentialIssuer:         issuerID,
		IssuerDisplay:            slices.Collect(issuerMetadata.Display.ToStorageModelIterator()),
		CredentialMetadata:       convertCredentialMetadata(credentialConfiguration),
		BatchSize:                uint(len(verified)),
		RemainingCount:           uint(len(verified)),
		Instances:                buildVcdmInstances(verified),
	}

	issuedAt, expiresAt, notBefore := VcdmIssuanceValidity(first)
	if issuedAt != nil {
		batch.IssuedAt = datatypes.NullTime{V: time.Unix(*issuedAt, 0), Valid: true}
	} else {
		// Neither a JWT iat nor a document validFrom is present; the batch
		// model requires an issuance timestamp, so record the receipt time.
		batch.IssuedAt = datatypes.NullTime{V: time.Now(), Valid: true}
	}
	if expiresAt != nil {
		batch.ExpiresAt = datatypes.NullTime{V: time.Unix(*expiresAt, 0), Valid: true}
	}
	if notBefore != nil {
		batch.NotBefore = datatypes.NullTime{V: time.Unix(*notBefore, 0), Valid: true}
	}

	if err := s.credentialStore.StoreBatch(batch); err != nil {
		return err
	}

	if requireCryptographicKeyBinding {
		s.linkHolderBindingKeys(matchedKeyIDs, batch.Instances)
	}

	return nil
}

func buildVcdmInstances(verified []*vcdmsdjwt.VerifiedSdJwtVcdm) []models.IssuedCredentialInstance {
	instances := make([]models.IssuedCredentialInstance, len(verified))
	for i, v := range verified {
		instances[i] = models.IssuedCredentialInstance{
			RawCredential: []byte(v.GetRawSdJwtVcdm()),
		}
	}
	return instances
}

// VcdmIssuanceValidity derives the wallet's issuance/validity timestamps for a
// verified SD-JWT-secured VCDM credential. The JWT-level iat/nbf are preferred
// when present (VC-JOSE-COSE keeps them optional), falling back to the
// document's validFrom; the expiry prefers the document's validUntil — the
// credential's own validity end — over the JWT exp. All time checks already
// happened at receipt; this only decides which timestamps the wallet records
// and displays.
func VcdmIssuanceValidity(v *vcdmsdjwt.VerifiedSdJwtVcdm) (issuedAt, expiresAt, notBefore *int64) {
	// Document.Validate ran at receipt, so the error returns are impossible.
	validFrom, hasValidFrom, _ := v.Document.ValidFrom()
	validUntil, hasValidUntil, _ := v.Document.ValidUntil()

	issuedAt = v.RegisteredClaims.IssuedAt
	notBefore = v.RegisteredClaims.NotBefore
	if hasValidFrom {
		unix := validFrom.Unix()
		if issuedAt == nil {
			issuedAt = &unix
		}
		if notBefore == nil {
			notBefore = &unix
		}
	}

	expiresAt = v.RegisteredClaims.Expiry
	if hasValidUntil {
		unix := validUntil.Unix()
		expiresAt = &unix
	}
	return issuedAt, expiresAt, notBefore
}

// BuildAttributesFromVcdmDocument emits attributes for the credentialSubject
// tree of a VCDM document, with document-rooted claim paths
// (["credentialSubject", ...]) per the storage decision (#679). The envelope
// properties (@context, type, issuer, validity, status, ...) are not
// attributes; they surface through the credential's own metadata fields.
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

// vcdmNonContentKeys are the top-level keys stripped before hashing a VCDM
// credential for batch deduplication: the JWT/SD-JWT securing claims plus the
// per-issuance envelope properties (identifier, validity window, status
// references). Two issuances of the same logical credential then produce the
// same hash, so a re-issuance replaces the stored batch — mirroring
// hashForSdJwtVc's treatment of the IETF SD-JWT VC registered claims.
var vcdmNonContentKeys = map[string]struct{}{
	jwt.IssuerKey:            {},
	jwt.SubjectKey:           {},
	jwt.AudienceKey:          {},
	jwt.IssuedAtKey:          {},
	jwt.NotBeforeKey:         {},
	jwt.ExpirationKey:        {},
	jwt.JwtIDKey:             {},
	sdjwt.ConfirmationKey:    {},
	sdjwt.SdKey:              {},
	sdjwt.SdAlgKey:           {},
	"status":                 {},
	vcdm.IDKey:               {},
	vcdm.ValidFromKey:        {},
	vcdm.ValidUntilKey:       {},
	vcdm.CredentialStatusKey: {},
}

// hashForVcdmCredential computes the deterministic batch-deduplication hash
// for an SD-JWT-secured VCDM credential over its type identity and content
// (see vcdmNonContentKeys for what is stripped). Same stability properties as
// hashForSdJwtVc: json.Marshal sorts object keys, array order is significant.
func hashForVcdmCredential(typeIdentity string, payload sdjwt.ProcessedPayload) (string, error) {
	content := make(map[string]any, len(payload))
	for key, value := range payload {
		if _, skip := vcdmNonContentKeys[key]; skip {
			continue
		}
		content[key] = value
	}

	contentBytes, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("hashForVcdmCredential: failed to marshal content: %w", err)
	}

	combined := append([]byte(typeIdentity), contentBytes...)
	return fmt.Sprintf("%x", sha256.Sum256(combined)), nil
}
