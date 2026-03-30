package services

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/internal/storage"
	"github.com/privacybydesign/irmago/eudi/internal/storage/models"
)

// IssuedCredentialMetadata carries the issuer and configuration metadata needed to build a
// CredentialBatch record. Callers in the openid4vci package map their types to this struct
// to avoid an import cycle (openid4vci → services → openid4vci).
type IssuedCredentialMetadata struct {
	// CredentialConfigurationID is the credential_configuration_id from the credential offer.
	CredentialConfigurationID string

	// Format is the credential format identifier (e.g. "dc+sd-jwt").
	Format string

	// IssuerDisplays contains the localised display entries from CredentialIssuerMetadata.Display.
	IssuerDisplays []IssuerDisplayMetadata

	// CredentialDisplays contains the localised display entries from CredentialConfiguration.CredentialMetadata.Display.
	CredentialDisplays []CredentialDisplayMetadata
}

// IssuerDisplayMetadata holds one localised display entry for the credential issuer.
type IssuerDisplayMetadata struct {
	Name        string
	Locale      string
	LogoURI     string
	LogoAltText string
}

// CredentialDisplayMetadata holds one localised display entry for the credential type.
type CredentialDisplayMetadata struct {
	Name        string
	Locale      string
	Description string
}

// CredentialService stores verified SD-JWT VCs and their associated holder binding keys
// in a single atomic transaction.
type CredentialService interface {
	VerifyAndStoreIssuedCredentials(
		verifiedSdJwtVcs []*sdjwtvc.VerifiedSdJwtVc,
		processedSdJwtPayload sdjwtvc.ProcessedSdJwtPayload,
		metadata IssuedCredentialMetadata,
		requireCryptographicKeyBinding bool,
		keyIds uuid.UUIDs,
	) error
}

type credentialService struct {
	credentialStore storage.CredentialStore
}

func NewCredentialService(s storage.Storage) CredentialService {
	return &credentialService{
		credentialStore: storage.NewCredentialStore(s),
	}
}

// StoreIssuedCredentials builds a CredentialBatch from the supplied verified credentials and
// metadata, then persists the batch and all its instances in one transaction.
//
// keyModels must either be empty (no cryptographic key binding required) or have exactly the same length as
// verifiedSdJwtVcs (one key per instance). All credentials in the slice are assumed to have been
// issued from the same credential_configuration_id and therefore share vct, issuer, and timing claims.
func (s *credentialService) VerifyAndStoreIssuedCredentials(
	verifiedSdJwtVcs []*sdjwtvc.VerifiedSdJwtVc,
	processedSdJwtPayload sdjwtvc.ProcessedSdJwtPayload,
	metadata IssuedCredentialMetadata,
	requireCryptographicKeyBinding bool,
	keyIds uuid.UUIDs,
) error {
	if len(verifiedSdJwtVcs) == 0 {
		return nil // nothing to store
	}

	if requireCryptographicKeyBinding && len(keyIds) != len(verifiedSdJwtVcs) {
		return fmt.Errorf(
			"keyIds length (%d) must equal verifiedSdJwtVcs length (%d) when cryptographic key binding is used",
			len(keyIds), len(verifiedSdJwtVcs),
		)
	}

	// All instances in a batch share the same vct, issuer, and timing claims.
	// Use the first credential as the source of truth for batch-level metadata.
	first := verifiedSdJwtVcs[0]

	attributes, err := extractScalarAttributes(first)
	if err != nil {
		return fmt.Errorf("failed to extract attributes: %w", err)
	}

	// The hash will be a hash over the ProcessedSdJwtPayload, which is the same for all credentials in the batch since they share the same claims.
	processedSdJwtPayloadBytes, err := json.Marshal(processedSdJwtPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal processed SD-JWT payload: %w", err)
	}

	hash := hashForSdJwtVc(first.VerifiableCredentialType, processedSdJwtPayloadBytes)

	attributesJSON, err := json.Marshal(attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	issuerDisplayJSON, err := marshalIssuerDisplay(metadata.IssuerDisplays)
	if err != nil {
		return fmt.Errorf("failed to marshal issuer display metadata: %w", err)
	}

	credentialDisplayJSON, err := marshalCredentialDisplay(metadata.CredentialDisplays)
	if err != nil {
		return fmt.Errorf("failed to marshal credential display metadata: %w", err)
	}

	issuedAt := time.Unix(first.IssuedAt, 0)

	var expiresAt *time.Time
	if first.Expiry != 0 {
		t := time.Unix(first.Expiry, 0)
		expiresAt = &t
	}

	var notBefore *time.Time
	if first.NotBefore != 0 {
		t := time.Unix(first.NotBefore, 0)
		notBefore = &t
	}

	var status []byte
	if first.Status != "" {
		// The upstream IssuerSignedJwtPayload currently parses the status claim as a plain
		// string. Store the raw bytes for now; once the upstream type is updated to a JSON
		// object (RFC 9596 Token Status List), change this to json.Marshal(first.Status).
		status = []byte(first.Status)
	}

	batchSize := uint(len(verifiedSdJwtVcs))
	instances := make([]models.IssuedCredentialInstance, batchSize)
	for i, v := range verifiedSdJwtVcs {
		instances[i] = models.IssuedCredentialInstance{
			RawCredential: []byte(v.GetRawSdJwtVc()),
		}
		if requireCryptographicKeyBinding {
			instances[i].HolderBindingKeyID = &keyIds[i]
		}
	}

	batch := &models.CredentialBatch{
		IssuerURL:                 first.Issuer,
		CredentialConfigurationID: metadata.CredentialConfigurationID,
		VerifiableCredentialType:  first.VerifiableCredentialType,
		Format:                    models.CredentialFormat(metadata.Format),
		Hash:                      hash,
		ProcessedSdJwtPayload:     string(processedSdJwtPayloadBytes),
		AttributesJSON:            attributesJSON,
		IssuerDisplayJSON:         issuerDisplayJSON,
		CredentialDisplayJSON:     credentialDisplayJSON,
		IssuedAt:                  issuedAt,
		ExpiresAt:                 expiresAt,
		NotBefore:                 notBefore,
		Status:                    status,
		BatchSize:                 batchSize,
		RemainingCount:            batchSize,
		Instances:                 instances,
	}

	return s.credentialStore.StoreBatch(batch)
}

// extractScalarAttributes extracts the top-level scalar claims (string, int, bool, null)
// from the verified SD-JWT VC. Structured claims (objects and arrays) are skipped, matching
// the behaviour of irmaclient.CreateHashForSdJwtVc.
func extractScalarAttributes(v *sdjwtvc.VerifiedSdJwtVc) (map[string]any, error) {
	// TODO: should we include all claims (except for _sd claims) ?
	if v.Claims == nil {
		return map[string]any{}, nil
	}

	attrs := make(map[string]any, len(v.Claims.Object))
	for key, node := range v.Claims.Object {
		switch node.Type {
		case sdjwtvc.Claim_String, sdjwtvc.Claim_Int, sdjwtvc.Claim_Bool, sdjwtvc.Claim_Null:
			attrs[key] = node.Value
		}
	}

	return attrs, nil
}

// hashForSdJwtVc computes the deterministic hash used for batch deduplication.
// The algorithm mirrors irmaclient.CreateHashForSdJwtVc so that hashes are consistent
// across both the IRMA client and the EUDI storage.
func hashForSdJwtVc(credType string, processedSdJwtPayloadBytes []byte) string {
	credTypeBytes := []byte(credType)

	combinedBytes := append([]byte(nil), credTypeBytes...)
	combinedBytes = append(combinedBytes, processedSdJwtPayloadBytes...)

	return fmt.Sprintf("%x", sha256.Sum256(combinedBytes))
}

func marshalIssuerDisplay(displays []IssuerDisplayMetadata) ([]byte, error) {
	if len(displays) == 0 {
		return nil, nil
	}

	out := make([]models.IssuerDisplay, len(displays))
	for i, d := range displays {
		out[i] = models.IssuerDisplay{
			Name:        d.Name,
			Locale:      d.Locale,
			LogoURI:     d.LogoURI,
			LogoAltText: d.LogoAltText,
		}
	}

	return json.Marshal(out)
}

func marshalCredentialDisplay(displays []CredentialDisplayMetadata) ([]byte, error) {
	if len(displays) == 0 {
		return nil, nil
	}

	out := make([]models.CredentialDisplay, len(displays))
	for i, d := range displays {
		out[i] = models.CredentialDisplay{
			Name:        d.Name,
			Locale:      d.Locale,
			Description: d.Description,
		}
	}

	return json.Marshal(out)
}
