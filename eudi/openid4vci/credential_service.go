package openid4vci

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"iter"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/internal/storage"
	"github.com/privacybydesign/irmago/eudi/internal/storage/models"
)

// CredentialService stores verified SD-JWT VCs and their associated holder binding keys
// in a single atomic transaction.
type CredentialService interface {
	VerifyAndStoreIssuedCredentials(
		verifiedSdJwtVcs []*sdjwtvc.VerifiedSdJwtVc,
		credentialConfigurationId string,
		metadata CredentialIssuerMetadata,
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
	credentialConfigurationId string,
	metadata CredentialIssuerMetadata,
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

	// The hash will be a hash over the ProcessedSdJwtPayload, which is the same for all credentials in the batch since they share the same claims.
	processedSdJwtPayloadBytes, err := json.Marshal(first.ProcessedSdJwtPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal processed SD-JWT payload: %w", err)
	}

	hash := hashForSdJwtVc(first.IssuerSignedJwtPayload.VerifiableCredentialType, processedSdJwtPayloadBytes)

	issuedAt := time.Unix(first.IssuerSignedJwtPayload.IssuedAt, 0)

	var expiresAt *time.Time
	if first.IssuerSignedJwtPayload.Expiry != 0 {
		t := time.Unix(first.IssuerSignedJwtPayload.Expiry, 0)
		expiresAt = &t
	}

	var notBefore *time.Time
	if first.IssuerSignedJwtPayload.NotBefore != 0 {
		t := time.Unix(first.IssuerSignedJwtPayload.NotBefore, 0)
		notBefore = &t
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

	// Convert metadata to the format expected by storage
	credentialConfiguration := metadata.CredentialConfigurationsSupported[credentialConfigurationId]

	credentialConfigurationModel := models.CredentialMetadata{}
	if credentialConfiguration.CredentialMetadata != nil {
		credentialConfigurationModel.Display = slices.Collect(credentialConfiguration.CredentialMetadata.Display.ToStorageModelItterator())

		claimModels := make([]models.CredentialClaim, len(credentialConfiguration.CredentialMetadata.Claims))
		for i, claim := range credentialConfiguration.CredentialMetadata.Claims {
			claimPath, err := json.Marshal(claim.Path)
			if err != nil {
				return fmt.Errorf("failed to marshal claim path: %w", err)
			}

			displays := make([]models.ClaimDisplay, len(claim.Display))
			for j, display := range claim.Display {
				displays[j] = models.ClaimDisplay{
					Name:   display.Name,
					Locale: display.Locale,
				}
			}

			claimModels[i] = models.CredentialClaim{
				Path:      string(claimPath),
				Mandatory: *claim.Mandatory,
				Display:   displays,
			}
		}
	}

	issuerMetadataModel := models.IssuerMetadata{
		CredentialIssuer: first.IssuerSignedJwtPayload.Issuer,
		Display:          slices.Collect(metadata.Display.ToStorageModelItterator()),
	}

	batch := &models.CredentialBatch{
		IssuerURL:                first.IssuerSignedJwtPayload.Issuer,
		VerifiableCredentialType: first.IssuerSignedJwtPayload.VerifiableCredentialType,
		Format:                   models.CredentialFormat(credentialConfiguration.Format),
		Hash:                     hash,
		ProcessedSdJwtPayload:    string(processedSdJwtPayloadBytes),
		IssuerMetadata:           &issuerMetadataModel,
		IssuedAt:                 issuedAt,
		ExpiresAt:                expiresAt,
		NotBefore:                notBefore,
		BatchSize:                batchSize,
		RemainingCount:           batchSize,
		Instances:                instances,
	}

	return s.credentialStore.StoreBatch(batch)
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

func (d CredentialIssuerDisplays) ToStorageModelItterator() iter.Seq[models.IssuerMetadataDisplay] {
	return func(yield func(models.IssuerMetadataDisplay) bool) {
		for _, item := range d {
			m := models.IssuerMetadataDisplay{
				Name:   item.Name,
				Locale: item.Locale,
			}

			if item.Logo != nil {
				m.LogoURI = item.Logo.Uri
				m.LogoAltText = item.Logo.AltText
			}

			yield(m)
		}
	}
}

func (d CredentialDisplays) ToStorageModelItterator() iter.Seq[models.CredentialDisplay] {
	return func(yield func(models.CredentialDisplay) bool) {
		for _, item := range d {
			m := models.CredentialDisplay{
				Name:            item.Name,
				Locale:          item.Locale,
				Description:     item.Description,
				BackgroundColor: item.BackgroundColor,
				TextColor:       item.TextColor,
			}

			if item.BackgroundImage != nil {
				m.BackgroundImageURI = item.BackgroundImage.Uri
				m.BackgroundImageAltText = item.BackgroundImage.AltText
			}

			if item.Logo != nil {
				m.LogoURI = item.Logo.Uri
				m.LogoAltText = item.Logo.AltText
			}

			yield(m)
		}
	}
}
