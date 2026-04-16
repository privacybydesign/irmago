// Package eudi_sdjwt_dcql implements a DcqlCredentialQueryHandler for SD-JWT-VC
// credentials stored in the eudi SQLite storage (issued via OpenID4VCI).
package eudi_sdjwt_dcql

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
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
	hasExhaustedBatch := false
	for _, batch := range batches {
		if !isBatchValid(batch, now) {
			continue
		}
		// Skip exhausted batches: when a batch was issued with multiple instances
		// and all have been used, the credential is no longer disclosable.
		if batch.BatchSize > 1 && batch.RemainingCount == 0 {
			hasExhaustedBatch = true
			continue
		}

		nonSdClaims := getNonSdClaimNames(batch, h.credentialStore)
		attributes, err := parseBatchAttributes(batch, query, nonSdClaims)
		if err != nil {
			continue
		}
		if attributes == nil {
			continue
		}

		result.OwnedCandidates = append(result.OwnedCandidates, &clientmodels.SelectableCredentialInstance{
			CredentialId:                batch.VerifiableCredentialType,
			Hash:                        batch.Hash,
			Name:                        credentialDisplayName(batch),
			Issuer:                      issuerTrustedParty(batch),
			Format:                      clientmodels.Format_SdJwtVc,
			BatchInstanceCountRemaining: &batch.RemainingCount,
			Attributes:                  attributes,
			IssuanceDate:                batch.IssuedAt.Unix(),
			ExpiryDate:                  expiryUnix(batch),
		})
	}

	// If matching batches exist but all are exhausted and no usable candidates
	// remain, return an error so the session fails instead of showing an empty
	// disclosure plan.
	if hasExhaustedBatch && len(result.OwnedCandidates) == 0 {
		return nil, fmt.Errorf("all credential instances for the requested type are exhausted")
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

		// Only mark the instance as used when the original batch had multiple instances.
		// A batch of 1 keeps its single instance reusable.
		if batch.BatchSize > 1 {
			if err := h.credentialStore.MarkInstanceUsed(instance.ID); err != nil {
				return nil, fmt.Errorf("failed to mark instance as used: %w", err)
			}
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
func parseBatchAttributes(batch *models.CredentialBatch, query dcql.CredentialQuery, nonSdClaims []string) ([]clientmodels.Attribute, error) {
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
		// When the path ends with nil (null wildcard for all array elements),
		// resolve the base path and expand the array.
		claimPath := claim.Path
		if len(claimPath) > 0 && claimPath[len(claimPath)-1] == nil {
			claimPath = claimPath[:len(claimPath)-1]
			val, _ = payload.GetClaimValue(claimPath)
		}

		displayName := claimDisplayName(batch, claimPath)
		prevLen := len(attributes)
		attributes = flattenForDisclosure(attributes, requestedKeys, batch, claimPath, val, displayName)

		// When the DCQL claim specifies a value constraint, set RequestedValue on the
		// newly added leaf attributes so the UI can show what the verifier asked for.
		if len(claim.Values) > 0 {
			for i := prevLen; i < len(attributes); i++ {
				if attributes[i].Value != nil {
					attributes[i].RequestedValue = attributes[i].Value
				}
			}
		}
	}

	// Include non-SD claims: these are always visible in the JWT payload and
	// will be shared regardless of which disclosures the user selects.
	for _, name := range nonSdClaims {
		if _, alreadyIncluded := requestedKeys[clientmodels.ClaimPathKey([]any{name})]; alreadyIncluded {
			continue
		}
		val, err := payload.GetClaimValue([]any{name})
		if err != nil {
			continue
		}
		dn := claimDisplayName(batch, []any{name})
		attr := clientmodels.Attribute{
			ClaimPath:   []any{name},
			DisplayName: &dn,
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
		dn := claimDisplayName(batch, path)
		attr := clientmodels.Attribute{
			ClaimPath:   path,
			DisplayName: &dn,
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
		Name:         credentialDisplayName(batch),
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

// flattenForDisclosure recursively flattens arrays and objects into scalar
// attributes, emitting a section header (Value == nil) before each compound
// value that has a display name. Only leaf attributes are added to requestedKeys.
func flattenForDisclosure(
	attrs []clientmodels.Attribute,
	requestedKeys map[string]struct{},
	batch *models.CredentialBatch,
	path []any,
	value any,
	display clientmodels.TranslatedString,
) []clientmodels.Attribute {
	switch v := value.(type) {
	case []any:
		if d := claimDisplayName(batch, path); len(d) > 0 {
			dn := d
			attrs = append(attrs, clientmodels.Attribute{
				ClaimPath:   path,
				DisplayName: &dn,
			})
		}
		for i, elem := range v {
			elemPath := append(append([]any{}, path...), i)
			elemDisplay := claimDisplayName(batch, elemPath)
			if len(elemDisplay) == 0 {
				elemDisplay = display
			}
			attrs = flattenForDisclosure(attrs, requestedKeys, batch, elemPath, elem, elemDisplay)
		}
	case map[string]any:
		if d := claimDisplayName(batch, path); len(d) > 0 {
			dn := d
			attrs = append(attrs, clientmodels.Attribute{
				ClaimPath:   path,
				DisplayName: &dn,
			})
		}
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			elemPath := append(append([]any{}, path...), key)
			elemDisplay := claimDisplayName(batch, elemPath)
			if len(elemDisplay) == 0 {
				elemDisplay = display
			}
			attrs = flattenForDisclosure(attrs, requestedKeys, batch, elemPath, v[key], elemDisplay)
		}
	default:
		pk := clientmodels.ClaimPathKey(path)
		requestedKeys[pk] = struct{}{}
		var dn *clientmodels.TranslatedString
		if len(path) == 0 || !isArrayIndex(path[len(path)-1]) {
			d := display
			dn = &d
		}
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   path,
			DisplayName: dn,
			Value:       clientmodels.NewAttributeValue(value),
		})
	}
	return attrs
}

// isArrayIndex returns true if the path component is a numeric array index.
func isArrayIndex(component any) bool {
	switch component.(type) {
	case int, float64:
		return true
	}
	return false
}

// issuerTrustedParty builds a TrustedParty from the stored issuer display metadata.
func issuerTrustedParty(batch *models.CredentialBatch) clientmodels.TrustedParty {
	name := clientmodels.TranslatedString{}
	for _, d := range batch.IssuerDisplay {
		locale := clientmodels.DefaultFallbackLanguage
		if d.Locale.Valid {
			locale = d.Locale.V
		}
		name[locale] = d.Name
	}
	return clientmodels.TrustedParty{
		Id:   batch.CredentialIssuer,
		Name: name,
	}
}

// credentialDisplayName returns the display name for a credential from its stored metadata.
// Falls back to the VCT if no display metadata is available.
func credentialDisplayName(batch *models.CredentialBatch) clientmodels.TranslatedString {
	if batch.CredentialMetadata != nil {
		ts := clientmodels.TranslatedString{}
		for _, d := range batch.CredentialMetadata.Display {
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
	return clientmodels.TranslatedString{"en": batch.VerifiableCredentialType}
}

// claimDisplayName looks up the display name for a claim from the stored credential metadata.
// Falls back to the raw claim name if no display metadata is available.
func claimDisplayName(batch *models.CredentialBatch, claimPath []any) clientmodels.TranslatedString {
	if batch.CredentialMetadata != nil {
		for _, claim := range batch.CredentialMetadata.Claims {
			var path []any
			if err := json.Unmarshal(claim.Path, &path); err == nil {
				if claimPathMatchesMetadataPath(claimPath, path) {
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

// claimPathMatchesMetadataPath checks if a concrete claim path matches a metadata
// path that may contain null wildcards. Null in the metadata path matches any
// integer index in the claim path.
func claimPathMatchesMetadataPath(claimPath []any, metadataPath []any) bool {
	if len(claimPath) != len(metadataPath) {
		return false
	}
	for i := range claimPath {
		if metadataPath[i] == nil {
			// Null wildcard matches any integer index.
			if !isArrayIndex(claimPath[i]) {
				return false
			}
		} else {
			if fmt.Sprintf("%v", claimPath[i]) != fmt.Sprintf("%v", metadataPath[i]) {
				return false
			}
		}
	}
	return true
}
