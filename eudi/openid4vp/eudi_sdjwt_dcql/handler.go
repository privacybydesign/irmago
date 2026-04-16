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
	"github.com/privacybydesign/irmago/eudi/services"
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
	keyService := services.NewHolderBindingKeyService(eudiStorage)
	return &SdJwtVcDcqlHandler{
		credentialStore: storage.NewCredentialStore(eudiStorage),
		keyBinder:       sdjwtvc.NewDefaultKeyBinder(keyService),
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
	if len(query.VctValues()) == 0 {
		return true
	}
	for _, vct := range query.VctValues() {
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
	vctValues := query.VctValues()
	if len(vctValues) == 0 {
		return nil, nil
	}

	allBatches, err := h.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, err
	}

	vctSet := make(map[string]struct{}, len(vctValues))
	for _, vct := range vctValues {
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

func (h *SdJwtVcDcqlHandler) PrepareDisclosure(selections []dcql.DisclosureSelection, ctx dcql.DisclosureContext) (*dcql.PreparedDisclosure, error) {
	nonce := ctx.Nonce
	clientId := ctx.ClientId
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

		presentation := string(selected)
		if sel.RequireHolderBinding {
			kbjwt, err := sdjwtvc.CreateKbJwt(selected, h.keyBinder, nonce, clientId)
			if err != nil {
				return nil, fmt.Errorf("failed to create kbjwt: %w", err)
			}
			presentation = string(sdjwtvc.AddKeyBindingJwtToSdJwtVc(selected, kbjwt))
		}

		result.QueryResponses = append(result.QueryResponses, dcql.QueryResponse{
			QueryId:     sel.QueryId,
			Credentials: []string{presentation},
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
//
// When claim_sets is present, each set is tried in order and the first fully
// satisfiable set determines which claims are included. Without claim_sets,
// all claims must match.
func parseBatchAttributes(batch *models.CredentialBatch, query dcql.CredentialQuery, credStore storage.CredentialStore) ([]clientmodels.Attribute, error) {
	var payload sdjwtvc.ProcessedSdJwtPayload
	if err := json.Unmarshal([]byte(batch.ProcessedSdJwtPayload), &payload); err != nil {
		return nil, err
	}

	claims := selectClaims(query, &payload)
	if claims == nil {
		// nil means the credential doesn't satisfy the query's value constraints.
		return nil, nil
	}

	// Use a non-nil slice so that non-SD claims can still be appended even when
	// no SD claims are requested (claims is empty but non-nil).
	// OpenID4VP Section 6.3: wallets should ignore duplicate claim queries.
	// Dedup by the full serialized path so that different paths with the same
	// leaf name (e.g., ["address","street"] vs ["billing","street"]) are not
	// confused.
	attributes := make([]clientmodels.Attribute, 0)
	seenPaths := make(map[string]struct{})
	requestedKeys := make(map[string]struct{})
	for _, claim := range claims {
		pathKey := clientmodels.ClaimPathKey(claim.Path)
		if _, duplicate := seenPaths[pathKey]; duplicate {
			continue
		}
		seenPaths[pathKey] = struct{}{}

		val, _ := payload.GetClaimValue(claim.Path)

		// When the path ends with nil (null wildcard for all array elements),
		// expand into individual attributes with indexed paths.
		if len(claim.Path) > 0 && claim.Path[len(claim.Path)-1] == nil {
			if arr, ok := val.([]any); ok {
				basePath := claim.Path[:len(claim.Path)-1]
				displayName := claimDisplayName(batch, basePath)
				for i, elem := range arr {
					elemPath := make([]any, len(basePath)+1)
					copy(elemPath, basePath)
					elemPath[len(basePath)] = i
					pk := clientmodels.ClaimPathKey(elemPath)
					requestedKeys[pk] = struct{}{}
					attributes = append(attributes, clientmodels.Attribute{
						ClaimPath:   elemPath,
						DisplayName: displayName,
						Value:       clientmodels.NewAttributeValue(elem),
					})
				}
				continue
			}
		}

		// When the value is an array (path doesn't end in nil but resolves to an array),
		// also expand into indexed elements.
		if arr, ok := val.([]any); ok {
			displayName := claimDisplayName(batch, claim.Path)
			for i, elem := range arr {
				elemPath := append(append([]any{}, claim.Path...), i)
				pk := clientmodels.ClaimPathKey(elemPath)
				requestedKeys[pk] = struct{}{}
				attributes = append(attributes, clientmodels.Attribute{
					ClaimPath:   elemPath,
					DisplayName: displayName,
					Value:       clientmodels.NewAttributeValue(elem),
				})
			}
			continue
		}

		// When the value is a nested object, flatten into individual attributes.
		if obj, ok := val.(map[string]any); ok {
			for key, elem := range obj {
				elemPath := append(append([]any{}, claim.Path...), key)
				pk := clientmodels.ClaimPathKey(elemPath)
				requestedKeys[pk] = struct{}{}
				attributes = append(attributes, clientmodels.Attribute{
					ClaimPath:   elemPath,
					DisplayName: claimDisplayName(batch, elemPath),
					Value:       clientmodels.NewAttributeValue(elem),
				})
			}
			continue
		}

		// Scalar value — single attribute.
		requestedKeys[pathKey] = struct{}{}
		attributes = append(attributes, clientmodels.Attribute{
			ClaimPath:   claim.Path,
			DisplayName: claimDisplayName(batch, claim.Path),
			Value:       clientmodels.NewAttributeValue(val),
		})
	}

	// Include non-SD claims: these are always visible in the JWT payload and
	// will be shared regardless of which disclosures the user selects.
	nonSdClaims := getNonSdClaimNames(batch, credStore)
	for _, name := range nonSdClaims {
		if _, alreadyIncluded := requestedKeys[clientmodels.ClaimPathKey([]any{name})]; alreadyIncluded {
			continue
		}
		val, err := payload.GetClaimValue([]any{name})
		if err != nil {
			continue
		}
		attr := clientmodels.Attribute{
			ClaimPath:   []any{name},
			DisplayName: claimDisplayName(batch, []any{name}),
		}
		attr.Value = clientmodels.NewAttributeValue(val)
		attributes = append(attributes, attr)
	}

	return attributes, nil
}

// selectClaims determines which claims to use for matching. When claim_sets is
// present, it tries each set in order and returns the claims from the first
// fully satisfiable set. Without claim_sets, all claims must match.
// Returns nil if the credential doesn't satisfy the query.
func selectClaims(query dcql.CredentialQuery, payload *sdjwtvc.ProcessedSdJwtPayload) []dcql.Claim {
	// OpenID4VP Section 6.4.1: if claims is absent, the verifier requests no
	// selectively disclosable claims. Return empty (non-nil) to indicate the
	// credential matches but no SD claims are requested.
	if len(query.Claims) == 0 {
		return []dcql.Claim{}
	}

	if len(query.ClaimSets) == 0 {
		// No claim_sets: all claims must match.
		for _, claim := range query.Claims {
			if !claimMatches(claim, payload) {
				return nil
			}
		}
		return query.Claims
	}

	// Build lookup from claim ID to claim.
	claimById := make(map[string]dcql.Claim, len(query.Claims))
	for _, claim := range query.Claims {
		if claim.Id != "" {
			claimById[claim.Id] = claim
		}
	}

	// Try each claim set in order; return the first where every claim matches.
	for _, set := range query.ClaimSets {
		var matched []dcql.Claim
		allFound := true
		for _, id := range set {
			claim, ok := claimById[id]
			if !ok || !claimMatches(claim, payload) {
				allFound = false
				break
			}
			matched = append(matched, claim)
		}
		if allFound {
			return matched
		}
	}

	return nil
}

// claimMatches checks whether a single claim exists in the payload and satisfies
// any value constraints. Supports string, boolean, and numeric comparisons as
// required by the DCQL spec (OpenID4VP Section 6.3).
func claimMatches(claim dcql.Claim, payload *sdjwtvc.ProcessedSdJwtPayload) bool {
	val, err := payload.GetClaimValue(claim.Path)
	if err != nil {
		return false
	}
	if len(claim.Values) > 0 {
		for _, reqVal := range claim.Values {
			if claimValuesEqual(val, reqVal) {
				return true
			}
		}
		return false
	}
	return true
}

// claimValuesEqual compares two values from JSON-decoded data. JSON numbers are
// float64, so we normalize both sides to float64 for numeric comparison.
func claimValuesEqual(actual, expected any) bool {
	// Direct equality covers strings and booleans.
	if actual == expected {
		return true
	}
	// JSON numbers are float64; the constraint value may also be float64.
	// Normalize both to float64 for comparison.
	af, aOk := toFloat64(actual)
	ef, eOk := toFloat64(expected)
	return aOk && eOk && af == ef
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
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
		attr := clientmodels.Attribute{
			ClaimPath:   path,
			DisplayName: claimDisplayName(batch, path),
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
func claimDisplayName(batch *models.CredentialBatch, claimPath []any) clientmodels.TranslatedString {
	if batch.CredentialMetadata != nil {
		for _, claim := range batch.CredentialMetadata.Claims {
			var path []string
			if err := json.Unmarshal(claim.Path, &path); err == nil {
				if claimPathMatchesStringPath(claimPath, path) {
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

// claimPathMatchesStringPath checks if a []any claim path matches a []string
// metadata path. Integer components in claimPath are skipped for matching
// (metadata paths don't contain array indices).
func claimPathMatchesStringPath(claimPath []any, metadataPath []string) bool {
	// Extract only the string components from the claim path.
	var stringParts []string
	for _, c := range claimPath {
		if s, ok := c.(string); ok {
			stringParts = append(stringParts, s)
		}
	}
	if len(stringParts) != len(metadataPath) {
		return false
	}
	for i := range stringParts {
		if stringParts[i] != metadataPath[i] {
			return false
		}
	}
	return true
}
