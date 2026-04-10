// Package eudi_sdjwt_dcql implements a DcqlCredentialQueryHandler for SD-JWT-VC
// credentials stored in the eudi SQLite storage (issued via OpenID4VCI).
package eudi_sdjwt_dcql

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

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

	now := time.Now()
	for _, batch := range batches {
		if !isBatchValid(batch, now) {
			continue
		}

		attributes, err := parseBatchAttributes(batch, query, h.credentialStore)
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
// preloaded (including claim display names). Only batches whose VCT matches
// one of the requested vct_values are returned. When no vct_values are
// specified, no batches are returned.
func (h *SdJwtVcDcqlHandler) findBatches(query dcql.CredentialQuery) ([]*models.CredentialBatch, error) {
	if len(query.Meta.VctValues) == 0 {
		return nil, nil
	}

	allBatches, err := h.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, err
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
// Non-SD claims (always shared when presenting) are included in the result so
// the user sees everything they will be sharing.
func parseBatchAttributes(batch *models.CredentialBatch, query dcql.CredentialQuery, credStore storage.CredentialStore) ([]clientmodels.Attribute, error) {
	var payload sdjwtvc.ProcessedSdJwtPayload
	if err := json.Unmarshal([]byte(batch.ProcessedSdJwtPayload), &payload); err != nil {
		return nil, err
	}

	// Check that all requested claims exist and match value constraints.
	var attributes []clientmodels.Attribute
	requestedKeys := make(map[string]struct{})
	for _, claim := range query.Claims {
		val, err := payload.GetClaimValue([]any(claim.Path))
		if err != nil {
			return nil, nil // required claim missing
		}

		valStr, _ := val.(string)

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

		attrName := claim.Path.LastString()
		requestedKeys[attrName] = struct{}{}
		attr := clientmodels.Attribute{
			Id:          attrName,
			DisplayName: claimDisplayName(batch, attrName),
		}
		attr.Value = clientmodels.NewAttributeValue(val)
		attributes = append(attributes, attr)
	}

	// Include non-SD claims: these are always visible in the JWT payload and
	// will be shared regardless of which disclosures the user selects.
	nonSdClaims := getNonSdClaimNames(batch, credStore)
	for _, name := range nonSdClaims {
		if _, alreadyIncluded := requestedKeys[name]; alreadyIncluded {
			continue
		}
		val, err := payload.GetClaimValue([]any{name})
		if err != nil {
			continue
		}
		attr := clientmodels.Attribute{
			Id:          name,
			DisplayName: claimDisplayName(batch, name),
		}
		attr.Value = clientmodels.NewAttributeValue(val)
		attributes = append(attributes, attr)
	}

	return attributes, nil
}

// getNonSdClaimNames returns the names of claims in the issuer JWT payload that
// are NOT selectively disclosable (i.e., always shared). These are claims present
// directly in the payload, not behind _sd hashes.
func getNonSdClaimNames(batch *models.CredentialBatch, credStore storage.CredentialStore) []string {
	instance, err := credStore.GetUnusedInstance(batch.ID)
	if err != nil {
		return nil
	}

	rawJwt := sdjwtvc.SdJwtVc(instance.RawCredential)
	jwtPayload, err := sdjwtvc.DecodeJwtPayload(rawJwt)
	if err != nil {
		return nil
	}

	// Standard SD-JWT claims that are not user data.
	standardClaims := map[string]struct{}{
		"iss": {}, "sub": {}, "iat": {}, "exp": {}, "nbf": {},
		"vct": {}, "cnf": {}, "_sd": {}, "_sd_alg": {}, "status": {},
	}

	var names []string
	for key := range jwtPayload {
		if _, isStandard := standardClaims[key]; isStandard {
			continue
		}
		// If the key is directly in the payload (not a nested _sd reference),
		// it's a non-SD claim.
		names = append(names, key)
	}
	return names
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
		return batch.ExpiresAt.V.Unix()
	}
	return 0
}

// isBatchValid returns false if the credential batch is expired or not yet valid.
// Unix epoch (time.Unix(0,0)) is treated as "not set" because the storage layer
// currently always marks ExpiresAt/NotBefore as Valid, even when the JWT has no
// exp/nbf claims — storing 0 as the timestamp.
func isBatchValid(batch *models.CredentialBatch, now time.Time) bool {
	epoch := time.Unix(0, 0)
	if batch.ExpiresAt.Valid && !batch.ExpiresAt.V.Equal(epoch) && now.After(batch.ExpiresAt.V) {
		return false
	}
	if batch.NotBefore.Valid && !batch.NotBefore.V.Equal(epoch) && now.Before(batch.NotBefore.V) {
		return false
	}
	return true
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
