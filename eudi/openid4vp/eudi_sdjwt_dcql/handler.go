// Package eudi_sdjwt_dcql implements a DcqlCredentialQueryHandler for SD-JWT-VC
// credentials stored in the eudi SQLite storage (issued via OpenID4VCI).
package eudi_sdjwt_dcql

import (
	"encoding/json"
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/models"
)

// SdJwtVcDcqlHandler implements dcql.DcqlCredentialQueryHandler for SD-JWT-VC
// credentials stored in the eudi storage (SQLite).
type SdJwtVcDcqlHandler struct {
	credentialStore storage.CredentialStore
	keyBinder       sdjwtvc.KeyBinder
}

// NewSdJwtVcDcqlHandler creates a new handler.
func NewSdJwtVcDcqlHandler(eudiStorage storage.Storage) *SdJwtVcDcqlHandler {
	keyStore := storage.NewHolderBindingKeyStore(eudiStorage.Db())
	return &SdJwtVcDcqlHandler{
		credentialStore: storage.NewCredentialStore(eudiStorage),
		keyBinder:       sdjwtvc.NewDefaultKeyBinder(&eudiKeyBindingStorage{keyStore: keyStore}),
	}
}

var _ dcql.DcqlCredentialQueryHandler = (*SdJwtVcDcqlHandler)(nil)

func (h *SdJwtVcDcqlHandler) Format() string {
	return string(clientmodels.Format_SdJwtVc) // "dc+sd-jwt"
}

// Formats returns all format identifiers this handler supports.
// Both "dc+sd-jwt" (current spec) and "vc+sd-jwt" (legacy) are SD-JWT-VC formats.
func (h *SdJwtVcDcqlHandler) Formats() []string {
	return []string{"dc+sd-jwt", "vc+sd-jwt"}
}

func (h *SdJwtVcDcqlHandler) FindCandidates(query dcql.CredentialQuery) (*dcql.CredentialQueryResult, error) {
	result := &dcql.CredentialQueryResult{}

	batches, err := h.findBatches(query)
	if err != nil {
		return nil, err
	}

	for _, batch := range batches {
		attributes, err := parseBatchAttributes(batch, query)
		if err != nil {
			continue
		}
		if attributes == nil {
			continue
		}

		result.OwnedCandidates = append(result.OwnedCandidates, &clientmodels.SelectableCredentialInstance{
			CredentialId:                batch.VerifiableCredentialType,
			Hash:                        batch.Hash,
			Name:                        clientmodels.TranslatedString{"en": batch.VerifiableCredentialType},
			Format:                      clientmodels.Format_SdJwtVc,
			BatchInstanceCountRemaining: &batch.RemainingCount,
			Attributes:                  attributes,
			IssuanceDate:                batch.IssuedAt.Unix(),
			ExpiryDate:                  expiryUnix(batch),
		})
	}

	return result, nil
}

// findBatches returns credential batches matching the query.
// When vct_values are specified, only matching batches are returned.
// When vct_values are absent (per DCQL spec, any VCT is acceptable), all batches are returned.
func (h *SdJwtVcDcqlHandler) findBatches(query dcql.CredentialQuery) ([]*models.CredentialBatch, error) {
	if len(query.Meta.VctValues) == 0 {
		return h.credentialStore.GetCredentialBatchList()
	}

	var all []*models.CredentialBatch
	for _, vct := range query.Meta.VctValues {
		batches, err := h.credentialStore.GetBatchesByVCT(vct)
		if err != nil {
			return nil, fmt.Errorf("failed to get batches for vct %s: %w", vct, err)
		}
		all = append(all, batches...)
	}
	return all, nil
}

func (h *SdJwtVcDcqlHandler) PrepareDisclosure(selections []dcql.DisclosureSelection, nonce string, clientId string) (*dcql.PreparedDisclosure, error) {
	result := &dcql.PreparedDisclosure{}

	for _, sel := range selections {
		batch, err := h.credentialStore.GetBatchByHash(sel.CredentialHash)
		if err != nil {
			return nil, fmt.Errorf("failed to get batch by hash %s: %w", sel.CredentialHash, err)
		}

		instance, err := h.credentialStore.GetUnusedInstance(batch.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get unused instance for batch %s: %w", batch.ID, err)
		}

		rawSdJwt := sdjwtvc.SdJwtVc(instance.RawCredential)

		selected, err := sdjwtvc.SelectDisclosures(rawSdJwt, sel.AttributeNames)
		if err != nil {
			return nil, fmt.Errorf("failed to select disclosures: %w", err)
		}

		kbjwt, err := sdjwtvc.CreateKbJwt(selected, h.keyBinder, nonce, clientId)
		if err != nil {
			return nil, fmt.Errorf("failed to create kbjwt: %w", err)
		}

		sdjwtWithKb := sdjwtvc.AddKeyBindingJwtToSdJwtVc(selected, kbjwt)

		result.QueryResponses = append(result.QueryResponses, dcql.QueryResponse{
			QueryId:     sel.QueryId,
			Credentials: []string{string(sdjwtWithKb)},
		})

		// Mark the instance as used
		if err := h.credentialStore.MarkInstanceUsed(instance.ID); err != nil {
			return nil, fmt.Errorf("failed to mark instance as used: %w", err)
		}

		result.CredentialLogs = append(result.CredentialLogs, buildLogCredential(batch, sel.AttributeNames))
	}

	return result, nil
}

// parseBatchAttributes parses the stored ProcessedSdJwtPayload and matches
// claims against the DCQL query. Returns nil if the credential doesn't match.
func parseBatchAttributes(batch *models.CredentialBatch, query dcql.CredentialQuery) ([]clientmodels.Attribute, error) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(batch.ProcessedSdJwtPayload), &payload); err != nil {
		return nil, err
	}

	var attributes []clientmodels.Attribute
	for _, claim := range query.Claims {
		attrName := claim.Path[0]
		val, ok := payload[attrName]
		if !ok {
			return nil, nil // required claim missing
		}

		valStr, _ := val.(string)

		// Check value constraints
		if len(claim.Values) > 0 {
			matched := false
			for _, reqVal := range claim.Values {
				if reqValStr, ok := reqVal.(string); ok && reqValStr == valStr {
					matched = true
					break
				}
			}
			if !matched {
				return nil, nil
			}
		}

		attr := clientmodels.Attribute{
			Id:          attrName,
			DisplayName: clientmodels.TranslatedString{"en": attrName},
		}
		if valStr != "" {
			ts := clientmodels.TranslatedString{"en": valStr}
			attr.Value = &clientmodels.AttributeValue{
				Type:             clientmodels.AttributeType_TranslatedString,
				TranslatedString: &ts,
			}
		}

		attributes = append(attributes, attr)
	}

	return attributes, nil
}

func buildLogCredential(batch *models.CredentialBatch, attrNames []string) clientmodels.LogCredential {
	var attrs []clientmodels.Attribute
	var payload map[string]any
	json.Unmarshal([]byte(batch.ProcessedSdJwtPayload), &payload)

	for _, name := range attrNames {
		attr := clientmodels.Attribute{
			Id:          name,
			DisplayName: clientmodels.TranslatedString{"en": name},
		}
		if val, ok := payload[name]; ok {
			if valStr, ok := val.(string); ok {
				ts := clientmodels.TranslatedString{"en": valStr}
				attr.Value = &clientmodels.AttributeValue{
					Type:             clientmodels.AttributeType_TranslatedString,
					TranslatedString: &ts,
				}
			}
		}
		attrs = append(attrs, attr)
	}

	return clientmodels.LogCredential{
		CredentialId: batch.VerifiableCredentialType,
		Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
		Name:         clientmodels.TranslatedString{"en": batch.VerifiableCredentialType},
		Attributes:   attrs,
		IssuanceDate: batch.IssuedAt.Unix(),
		ExpiryDate:   expiryUnix(batch),
	}
}

func expiryUnix(batch *models.CredentialBatch) int64 {
	if batch.ExpiresAt.Valid {
		return batch.IssuedAt.Unix()
	}
	return 0
}
