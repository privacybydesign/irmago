package services

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"slices"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/models"
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
	credentialStore storage.CredentialStore
}

func NewCredentialService(s storage.Storage) CredentialService {
	return &credentialService{
		credentialStore: storage.NewCredentialStore(s),
	}
}

func (c *credentialService) GetCredentialMetadataList() ([]*clientmodels.Credential, error) {
	m, err := c.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, err
	}

	// Convert storage models to client models
	clientModels := make([]*clientmodels.Credential, len(m))
	for i, batch := range m {
		var processedSdJwtPayload *sdjwtvc.ProcessedSdJwtPayload
		if err := json.Unmarshal(batch.ProcessedSdJwtPayload, &processedSdJwtPayload); err != nil {
			log.Printf("Error unmarshalling processed SD-JWT payload for batch %s: %v", batch.ID, err)
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

			attrs = make([]clientmodels.Attribute, len(batch.CredentialMetadata.Claims))
			for j, claim := range batch.CredentialMetadata.Claims {
				attrDisplay := clientmodels.TranslatedString{}
				for _, d := range claim.Display {
					locale := clientmodels.DefaultFallbackLanguage
					if d.Locale.Valid {
						locale, _ = metadata.TryGetBaseLanguageFromLocale(d.Locale.V)
					}
					attrDisplay[locale] = d.Name
				}

				// Build a slice from the claim path for processing
				var claimPath []any
				if err := json.Unmarshal(claim.Path, &claimPath); err != nil {
					log.Fatalf("Error unmarshalling JSON: %v", err)
				}

				claimValue, err := processedSdJwtPayload.GetClaimValue(claimPath)
				if err != nil {
					log.Printf("unrecognized claim at path %v; falling back to empty string for claim with path %v: %v", claim.Path, claimPath, err)
					claimValue = "" // fallback to an empty string if claim value cannot be extracted
				}

				// Build the attribute value, based on the value and type extracted from the processed SD-JWT payload.
				attrValue := clientmodels.AttributeValue{}
				rt := reflect.TypeOf(claimValue)
				switch rt.Kind() {
				case reflect.String:
					v := claimValue.(string)
					attrValue.Type = clientmodels.AttributeType_String
					attrValue.String = &v
				case reflect.Bool:
					v := claimValue.(bool)
					attrValue.Type = clientmodels.AttributeType_Bool
					attrValue.Bool = &v
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					v := claimValue.(int64) // JSON numbers are unmarshalled as float64 by default, but if the value is an integer it will be represented as int64 in Go
					attrValue.Type = clientmodels.AttributeType_Int
					attrValue.Int = &v
				case reflect.Float32, reflect.Float64:
					// JSON numbers are unmarshalled as float64 by default, but we will treat them as ints if they have no fractional part
					fClaimValue := claimValue.(float64)
					iClaimValue := int64(fClaimValue)
					if fClaimValue == float64(iClaimValue) {
						attrValue.Type = clientmodels.AttributeType_Int
						attrValue.Int = &iClaimValue
					} else {
						attrValue.Type = clientmodels.AttributeType_String
						str := fmt.Sprintf("%.2f", fClaimValue)
						attrValue.String = &str
					}
				case reflect.Slice, reflect.Array:
					attrValue.Type = clientmodels.AttributeType_Array
					s := reflect.ValueOf(claimValue)
					attrValue.Array = make([]clientmodels.AttributeValue, s.Len())
					for i := 0; i < s.Len(); i++ {
						// TODO:
						// For simplicity, we will treat all array elements as strings by marshalling them to JSON and storing the JSON string as the value. This is a temporary solution until we have a more robust way to represent different attribute types in the client model.
						elemBytes, err := json.Marshal(s.Index(i).Interface())
						if err != nil {
							log.Fatalf("Error marshalling array element to JSON: %v", err)
						}
						elemStr := string(elemBytes)
						attrValue.Array[i] = clientmodels.AttributeValue{
							Type:   clientmodels.AttributeType_String,
							String: &elemStr,
						}
					}
				case reflect.Map, reflect.Struct:
					attrValue.Type = clientmodels.AttributeType_Object
					// TODO: implement
				default:
					// For non-string values, we will treat them as translated strings by marshalling the value to JSON and storing it as a string. This is a temporary solution until we have a more robust way to represent different attribute types in the client model.
				}

				attrs[j] = clientmodels.Attribute{
					Id:          "", // TODO: what to assign here? needs to be different per language/locale?
					DisplayName: attrDisplay,
					Value:       &attrValue, // TODO: fill attributes here; apply JSON Path Pointer to the ProcessedSdJwtPayload to extract the value for this claim
				}
			}
		}

		exp := int64(0)
		if batch.ExpiresAt.Valid {
			exp = batch.ExpiresAt.V.Unix()
		}

		clientModels[i] = &clientmodels.Credential{
			CredentialId: batch.VerifiableCredentialType,
			Hash:         batch.Hash,
			ImagePath:    nil, // TODO: storage credential image somewhere
			Name:         credentialDisplays,
			Issuer: clientmodels.TrustedParty{
				Id:        batch.CredentialIssuer,
				Name:      issuerDisplays,
				Url:       nil,
				ImagePath: nil,
				Parent:    nil,
				Verified:  false,
			},
			CredentialInstanceIds: map[clientmodels.CredentialFormat]string{
				clientmodels.CredentialFormat(batch.Format): batch.Hash,
			},
			BatchInstanceCountsRemaining: map[clientmodels.CredentialFormat]*uint{
				clientmodels.CredentialFormat(batch.Format): &batch.RemainingCount,
			},
			Attributes:          attrs,
			IssuanceDate:        batch.IssuedAt.Unix(),
			ExpiryDate:          exp,
			Revoked:             false, // revocation is not yet implemented, so default to false for now
			RevocationSupported: false,
			IssueURL:            nil, // TODO: add issue URL to storage model so this can be filled in here
		}
	}

	return clientModels, nil
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

	hash := hashForSdJwtVc(first.IssuerSignedJwtPayload.VerifiableCredentialType, processedSdJwtPayloadBytes)

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

// hashForSdJwtVc computes the deterministic hash used for batch deduplication.
// The algorithm mirrors irmaclient.CreateHashForSdJwtVc so that hashes are consistent
// across both the IRMA client and the EUDI storage.
func hashForSdJwtVc(credType string, processedSdJwtPayloadBytes []byte) string {
	credTypeBytes := []byte(credType)

	// TODO: processedSdJwtPayload should not contain fields like iis, iat, nbf before hashing, so only the actual claim fields are compared

	combinedBytes := append([]byte(nil), credTypeBytes...)
	combinedBytes = append(combinedBytes, processedSdJwtPayloadBytes...)

	return fmt.Sprintf("%x", sha256.Sum256(combinedBytes))
}
