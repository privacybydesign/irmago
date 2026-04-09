// Package eudi_sdjwt_dcql implements a DcqlCredentialQueryHandler for SD-JWT-VC
// credentials stored in the eudi SQLite storage (issued via OpenID4VCI).
package eudi_sdjwt_dcql

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/models"
)

func isURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

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

// CanHandleCredentialQuery returns true when the format is dc+sd-jwt or vc+sd-jwt
// and at least one vct_value is a valid URL (indicating an EUDI credential type).
func (h *SdJwtVcDcqlHandler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	if query.Format != "dc+sd-jwt" && query.Format != "vc+sd-jwt" {
		return false
	}
	// Without vct_values, accept all sd-jwt queries (verifier didn't specify type).
	if len(query.Meta.VctValues) == 0 {
		return true
	}
	for _, vct := range query.Meta.VctValues {
		if isURL(vct) {
			return true
		}
	}
	return false
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

// findBatches returns credential batches matching the query, with metadata
// preloaded (including claim display names). When vct_values are specified,
// only matching batches are returned; otherwise all batches are returned.
func (h *SdJwtVcDcqlHandler) findBatches(query dcql.CredentialQuery) ([]*models.CredentialBatch, error) {
	allBatches, err := h.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, err
	}

	if len(query.Meta.VctValues) == 0 {
		return allBatches, nil
	}

	vctSet := make(map[string]struct{}, len(query.Meta.VctValues))
	for _, vct := range query.Meta.VctValues {
		vctSet[vct] = struct{}{}
	}
	var filtered []*models.CredentialBatch
	for _, batch := range allBatches {
		if _, ok := vctSet[batch.VerifiableCredentialType]; ok {
			filtered = append(filtered, batch)
		}
	}
	return filtered, nil
}

func (h *SdJwtVcDcqlHandler) PrepareDisclosure(selections []dcql.DisclosureSelection, nonce string, clientId string) (*dcql.PreparedDisclosure, error) {
	result := &dcql.PreparedDisclosure{}

	// Load all batches with full metadata so buildLogCredential can resolve display names.
	allBatches, err := h.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, fmt.Errorf("failed to load credential batches: %w", err)
	}
	batchByHash := make(map[string]*models.CredentialBatch, len(allBatches))
	for _, b := range allBatches {
		batchByHash[b.Hash] = b
	}

	for _, sel := range selections {
		batch, ok := batchByHash[sel.CredentialHash]
		if !ok {
			return nil, fmt.Errorf("batch not found for hash %s", sel.CredentialHash)
		}

		instance, err := h.credentialStore.GetUnusedInstance(batch.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get unused instance for batch %s: %w", batch.ID, err)
		}

		rawSdJwt := sdjwtvc.SdJwtVc(instance.RawCredential)

		selected, err := sdjwtvc.CreatePresentation(rawSdJwt, sel.ClaimPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to create presentation: %w", err)
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

		result.CredentialLogs = append(result.CredentialLogs, buildLogCredential(batch, sel.ClaimPaths))
	}

	return result, nil
}

// parseBatchAttributes parses the stored ProcessedSdJwtPayload and matches
// claims against the DCQL query. Returns nil if the credential doesn't match.
func parseBatchAttributes(batch *models.CredentialBatch, query dcql.CredentialQuery) ([]clientmodels.Attribute, error) {
	var payload sdjwtvc.ProcessedSdJwtPayload
	if err := json.Unmarshal([]byte(batch.ProcessedSdJwtPayload), &payload); err != nil {
		return nil, err
	}

	var attributes []clientmodels.Attribute
	for _, claim := range query.Claims {
		// Resolve the claim value using the full path.
		val, err := payload.GetClaimValue([]any(claim.Path))
		if err != nil {
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

		// Use the last string path element as the attribute ID.
		attrName := claim.Path.LastString()
		attr := clientmodels.Attribute{
			Id:          attrName,
			DisplayName: claimDisplayName(batch, attrName),
		}
		attr.Value = buildAttributeValue(val)

		attributes = append(attributes, attr)
	}

	return attributes, nil
}

func buildLogCredential(batch *models.CredentialBatch, claimPaths [][]any) clientmodels.LogCredential {
	var attrs []clientmodels.Attribute
	var payload sdjwtvc.ProcessedSdJwtPayload
	json.Unmarshal([]byte(batch.ProcessedSdJwtPayload), &payload)

	for _, path := range claimPaths {
		if len(path) == 0 {
			continue
		}
		attrName := dcql.ClaimsPathPointer(path).LastString()
		attr := clientmodels.Attribute{
			Id:          attrName,
			DisplayName: claimDisplayName(batch, attrName),
		}
		if val, err := payload.GetClaimValue(path); err == nil {
			if valStr, ok := val.(string); ok {
				attr.Value = &clientmodels.AttributeValue{
					Type:   clientmodels.AttributeType_String,
					String: &valStr,
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

// buildAttributeValue converts a claim value from the processed SD-JWT payload
// into a clientmodels.AttributeValue.
func buildAttributeValue(val any) *clientmodels.AttributeValue {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: &v}
	case bool:
		return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Bool, Bool: &v}
	case float64:
		i := int64(v)
		if v == float64(i) {
			return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Int, Int: &i}
		}
		s := fmt.Sprintf("%g", v)
		return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: &s}
	case []any:
		arr := make([]clientmodels.AttributeValue, len(v))
		for i, elem := range v {
			if av := buildAttributeValue(elem); av != nil {
				arr[i] = *av
			}
		}
		return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Array, Array: arr}
	case map[string]any:
		var obj []clientmodels.Attribute
		for key, elem := range v {
			obj = append(obj, clientmodels.Attribute{
				Id:    key,
				Value: buildAttributeValue(elem),
			})
		}
		return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Object, Object: obj}
	default:
		s := fmt.Sprintf("%v", v)
		return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: &s}
	}
}

// claimDisplayName looks up the display name for a claim from the stored credential metadata.
// Falls back to the raw claim name if no display metadata is available.
func claimDisplayName(batch *models.CredentialBatch, claimName string) clientmodels.TranslatedString {
	if batch.CredentialMetadata != nil {
		for _, claim := range batch.CredentialMetadata.Claims {
			var path []string
			if err := json.Unmarshal(claim.Path, &path); err == nil {
				if len(path) > 0 && path[len(path)-1] == claimName {
					ts := clientmodels.TranslatedString{}
					for _, d := range claim.Display {
						locale := "en"
						if d.Locale.Valid {
							locale = d.Locale.V
						}
						ts[locale] = d.Name
					}
					if len(ts) > 0 {
						return ts
					}
				}
			}
		}
	}
	return clientmodels.TranslatedString{}
}
