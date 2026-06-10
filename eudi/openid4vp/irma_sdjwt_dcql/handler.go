package irma_sdjwt_dcql

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

// SdJwtVcDcqlHandler implements dcql.DcqlCredentialQueryHandler for SD-JWT-VC credentials.
type SdJwtVcDcqlHandler struct {
	storage   irmaclient.SdJwtVcStorage
	config    *irma.Configuration
	keyBinder sdjwtvc.KeyBinder
}

// NewIrmaSdJwtVcDcqlHandler creates a new handler for DCQL credential queries for SD-JWT-VC credentials issued over IRMA.
func NewIrmaSdJwtVcDcqlHandler(storage irmaclient.SdJwtVcStorage, config *irma.Configuration, keyBinder sdjwtvc.KeyBinder) *SdJwtVcDcqlHandler {
	return &SdJwtVcDcqlHandler{
		storage:   storage,
		config:    config,
		keyBinder: keyBinder,
	}
}

// Compile-time check that SdJwtVcDcqlHandler implements the interface.
var _ dcql.DcqlCredentialQueryHandler = (*SdJwtVcDcqlHandler)(nil)

// CanHandleCredentialQuery returns true when the format is dc+sd-jwt and at least
// one vct_value is a dot-separated IRMA credential type identifier found in the
// IRMA configuration (e.g., "test.test.email").
func (h *SdJwtVcDcqlHandler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	if query.Format != "dc+sd-jwt" {
		return false
	}
	for _, vct := range query.VctValues() {
		parts := strings.Split(vct, ".")
		if len(parts) != 3 {
			continue
		}
		credTypeId := irma.NewCredentialTypeIdentifier(vct)
		if _, ok := h.config.CredentialTypes[credTypeId]; ok {
			return true
		}
	}
	return false
}

// FindCandidates finds all credential instances that match the given DCQL credential query.
func (h *SdJwtVcDcqlHandler) FindCandidates(query dcql.CredentialQuery) (*dcql.CredentialQueryResult, error) {
	result := &dcql.CredentialQueryResult{}

	// For each VCT value, find matching credentials from storage
	for _, vct := range query.VctValues() {
		entries := h.storage.GetCredentialsForId(vct)
		candidates, err := h.filterCredentialsWithClaims(entries, query)
		if err != nil {
			return nil, fmt.Errorf("failed to filter credentials for vct %s: %w", vct, err)
		}

		for _, candidate := range candidates {
			instance, err := h.buildSelectableInstance(candidate, query)
			if err != nil {
				return nil, fmt.Errorf("failed to build selectable instance: %w", err)
			}
			result.OwnedCandidates = append(result.OwnedCandidates, instance)
		}

		// Build obtainable descriptor for this VCT
		credTypeId := irma.NewCredentialTypeIdentifier(vct)
		descriptor, err := h.buildCredentialDescriptor(credTypeId, query)
		if err != nil {
			// If the credential type is not in the configuration, we skip it
			// (it may not be obtainable)
			irma.Logger.Debugf("skipping obtainable descriptor for %s: %v", vct, err)
		} else {
			result.ObtainableDescriptors = append(result.ObtainableDescriptors, descriptor)
		}
	}

	return result, nil
}

// PrepareDisclosure prepares the selected credentials for inclusion in the VP token.
func (h *SdJwtVcDcqlHandler) PrepareDisclosure(selections []dcql.DisclosureSelection, nonce string, clientId string) (*dcql.PreparedDisclosure, error) {
	result := &dcql.PreparedDisclosure{}

	for _, sel := range selections {
		cred, err := h.storage.GetCredentialByHash(sel.CredentialHash)
		if err != nil {
			return nil, fmt.Errorf("failed to get credential by hash %s: %w", sel.CredentialHash, err)
		}

		err = h.storage.RemoveLastUsedInstanceOfCredentialByHash(sel.CredentialHash)
		if err != nil {
			return nil, fmt.Errorf("failed to remove instance of credential %s: %w", sel.CredentialHash, err)
		}

		sdjwtSelected, err := sdjwtvc.CreatePresentation(cred.SdJwtVc, sel.ClaimPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to create presentation: %w", err)
		}

		presentation := string(sdjwtSelected)
		if sel.RequireHolderBinding {
			kbjwt, err := sdjwtvc.CreateKbJwt(sdjwtSelected, h.keyBinder, nonce, clientId)
			if err != nil {
				return nil, fmt.Errorf("failed to create kbjwt: %w", err)
			}
			presentation = string(sdjwtvc.AddKeyBindingJwtToSdJwtVc(sdjwtSelected, kbjwt))
		}

		result.QueryResponses = append(result.QueryResponses, dcql.QueryResponse{
			QueryId:     sel.QueryId,
			Credentials: []string{presentation},
		})

		credLog := h.buildLogCredential(cred.Metadata, sel.ClaimPaths)
		result.CredentialLogs = append(result.CredentialLogs, credLog)
	}

	return result, nil
}

// ============================================================================
// Claim matching (ported from eudi/openid4vp/client/dcql.go)
// ============================================================================

type dcqlClaimMatch struct {
	claimKey       string
	attributeName  string
	attributeValue string
	hasValue       bool
}

// dcqlClaimKey returns the claim's ID if set, otherwise the serialized claim path.
func dcqlClaimKey(claim dcql.Claim) string {
	if claim.Id != "" {
		return claim.Id
	}
	return clientmodels.ClaimPathKey(claim.Path)
}

// getClaimMatches checks which claims from the query match the credential's attributes.
func getClaimMatchesForQuery(metadata irmaclient.SdJwtVcBatchMetadata, claims []dcql.Claim) map[string]dcqlClaimMatch {
	result := make(map[string]dcqlClaimMatch)
	for _, claim := range claims {
		if len(claim.Path) == 0 {
			continue
		}
		attrName, ok := claim.Path[0].(string)
		if !ok {
			continue
		}
		attributeValue, ok := metadata.Attributes[attrName]
		if !ok {
			continue
		}
		attributeValueString, _ := attributeValue.(string)
		key := dcqlClaimKey(claim)

		if len(claim.Values) != 0 {
			for _, requestedValueAny := range claim.Values {
				requestedValueString, _ := requestedValueAny.(string)
				if attributeValueString == requestedValueString {
					result[key] = dcqlClaimMatch{
						claimKey:       key,
						attributeName:  attrName,
						attributeValue: attributeValueString,
						hasValue:       true,
					}
					break
				}
			}
		} else {
			result[key] = dcqlClaimMatch{
				claimKey:       key,
				attributeName:  attrName,
				attributeValue: attributeValueString,
				hasValue:       false,
			}
		}
	}
	return result
}

// filterClaimMatchesForQuery filters claim matches based on claim_sets or all claims.
func filterClaimMatchesForQuery(query dcql.CredentialQuery, matches map[string]dcqlClaimMatch) []dcqlClaimMatch {
	if len(query.ClaimSets) != 0 {
		for _, claimSet := range query.ClaimSets {
			var result []dcqlClaimMatch
			allFound := true
			for _, key := range claimSet {
				match, ok := matches[key]
				if !ok {
					allFound = false
					break
				}
				result = append(result, match)
			}
			if allFound {
				return result
			}
		}
		return nil
	}

	var result []dcqlClaimMatch
	for _, claim := range query.Claims {
		match, ok := matches[dcqlClaimKey(claim)]
		if !ok {
			return nil
		}
		result = append(result, match)
	}
	return result
}

type sdJwtVcCredCandidate struct {
	entry        irmaclient.SdJwtVcAndInfo
	claimMatches []dcqlClaimMatch
}

// filterCredentialsWithClaims returns only credentials that have ALL required claims.
func (h *SdJwtVcDcqlHandler) filterCredentialsWithClaims(entries []irmaclient.SdJwtVcAndInfo, query dcql.CredentialQuery) ([]sdJwtVcCredCandidate, error) {
	var result []sdJwtVcCredCandidate
	for _, e := range entries {
		claimMatches := getClaimMatchesForQuery(e.Metadata, query.Claims)
		if matches := filterClaimMatchesForQuery(query, claimMatches); matches != nil {
			result = append(result, sdJwtVcCredCandidate{
				entry:        e,
				claimMatches: matches,
			})
		}
	}
	return result, nil
}

// ============================================================================
// Display metadata enrichment
// ============================================================================

// buildSelectableInstance creates a SelectableCredentialInstance with full display metadata
// for a matched credential candidate.
func (h *SdJwtVcDcqlHandler) buildSelectableInstance(candidate sdJwtVcCredCandidate, query dcql.CredentialQuery) (*clientmodels.SelectableCredentialInstance, error) {
	metadata := candidate.entry.Metadata
	credTypeId := irma.NewCredentialTypeIdentifier(metadata.CredentialType)

	credType, ok := h.config.CredentialTypes[credTypeId]
	if !ok {
		return nil, fmt.Errorf("credential type %s not found in configuration", credTypeId.String())
	}

	issuerId := credType.IssuerIdentifier()
	issuer, ok := h.config.Issuers[issuerId]
	if !ok {
		return nil, fmt.Errorf("issuer %s not found in configuration", issuerId.String())
	}

	// Build attributes for the matched claims, using display metadata from irma.Configuration
	attributes := h.buildMatchedAttributes(credType, candidate.claimMatches, metadata)

	remainingCount := metadata.RemainingInstanceCount
	return &clientmodels.SelectableCredentialInstance{
		CredentialId:                credTypeId.String(),
		Hash:                        metadata.Hash,
		Image:                       clientmodels.ImageFromFile(credType.Logo(h.config)),
		Name:                        clientmodels.TranslatedString(credType.Name),
		Issuer:                      buildIssuerTrustedParty(h.config, issuer),
		Format:                      clientmodels.Format_SdJwtVc,
		BatchInstanceCountRemaining: &remainingCount,
		Attributes:                  attributes,
		IssuanceDate:                time.Time(metadata.SignedOn).Unix(),
		ExpiryDate:                  time.Time(metadata.Expires).Unix(),
		IssueURL:                    convertOptionalTranslatedString(credType.IssueURL),
	}, nil
}

// buildMatchedAttributes builds Attribute objects for the matched claims with display names and values.
func (h *SdJwtVcDcqlHandler) buildMatchedAttributes(
	credType *irma.CredentialType,
	matches []dcqlClaimMatch,
	metadata irmaclient.SdJwtVcBatchMetadata,
) []clientmodels.Attribute {
	var attributes []clientmodels.Attribute

	// Build a lookup of attribute types by ID for efficient access
	attrTypesByID := make(map[string]*irma.AttributeType, len(credType.AttributeTypes))
	for _, at := range credType.AttributeTypes {
		attrTypesByID[at.ID] = at
	}

	for _, match := range matches {
		at, ok := attrTypesByID[match.attributeName]
		if !ok {
			// If the attribute type is not in the schema, create a basic attribute
			dn := clientmodels.TranslatedString{"en": match.attributeName}
			attr := clientmodels.Attribute{
				ClaimPath:   []any{match.attributeName},
				DisplayName: &dn,
			}
			if rawVal, exists := metadata.Attributes[match.attributeName]; exists {
				if strVal, ok := rawVal.(string); ok {
					attr.Value = buildAttributeValue("", &strVal)
				}
			}
			attributes = append(attributes, attr)
			continue
		}

		description := clientmodels.TranslatedString(at.Description)
		displayName := clientmodels.TranslatedString(at.Name)
		attr := clientmodels.Attribute{
			ClaimPath:   []any{at.ID},
			DisplayName: &displayName,
			Description: &description,
		}

		// Set the actual value from the credential's stored attributes
		if rawVal, exists := metadata.Attributes[match.attributeName]; exists {
			if strVal, ok := rawVal.(string); ok {
				attr.Value = buildAttributeValue(at.DisplayHint, &strVal)
			}
		}

		// Set the requested value if the claim had specific value constraints
		if match.hasValue {
			attr.RequestedValue = &clientmodels.AttributeValue{
				Type:   clientmodels.AttributeType_String,
				String: &match.attributeValue,
			}
		}

		attributes = append(attributes, attr)
	}

	// Display in schema order (DisplayIndex if all attributes have one, else
	// XML position) regardless of the verifier's claim order. Frontends expect
	// stable ordering for rendering.
	return sortAttributesBySchema(attributes, credType)
}

// sortAttributesBySchema returns attrs reordered to follow credType's display
// order. Mirrors the helper of the same name in client/session_handler.go;
// duplicated here because that package can't be imported (it depends on this
// one). Attributes whose first claim-path element doesn't resolve to a known
// schema attribute are kept after the known ones in their original order.
func sortAttributesBySchema(attrs []clientmodels.Attribute, credType *irma.CredentialType) []clientmodels.Attribute {
	if credType == nil || len(attrs) <= 1 {
		return attrs
	}
	sortedTypes := SortedAttributeTypes(credType.AttributeTypes)
	position := make(map[string]int, len(sortedTypes))
	for i, at := range sortedTypes {
		position[at.ID] = i
	}
	unknown := len(sortedTypes)
	posOf := func(a clientmodels.Attribute) int {
		if len(a.ClaimPath) == 0 {
			return unknown
		}
		name, ok := a.ClaimPath[0].(string)
		if !ok {
			return unknown
		}
		if p, ok := position[name]; ok {
			return p
		}
		return unknown
	}
	out := make([]clientmodels.Attribute, len(attrs))
	copy(out, attrs)
	slices.SortStableFunc(out, func(a, b clientmodels.Attribute) int {
		return posOf(a) - posOf(b)
	})
	return out
}

// buildCredentialDescriptor creates a CredentialDescriptor for an obtainable credential type,
// with only the requested attributes from the query.
func (h *SdJwtVcDcqlHandler) buildCredentialDescriptor(credTypeId irma.CredentialTypeIdentifier, query dcql.CredentialQuery) (*clientmodels.CredentialDescriptor, error) {
	credType, ok := h.config.CredentialTypes[credTypeId]
	if !ok {
		return nil, fmt.Errorf("credential type %s not found in configuration", credTypeId.String())
	}

	issuerId := credType.IssuerIdentifier()
	issuer, ok := h.config.Issuers[issuerId]
	if !ok {
		return nil, fmt.Errorf("issuer %s not found in configuration", issuerId.String())
	}

	// Determine which claims to show. When claim_sets are present,
	// only include claims from the first claim_set (matching old behavior).
	claimsToShow := query.Claims
	if len(query.ClaimSets) > 0 {
		claimMap := make(map[string]dcql.Claim)
		for _, c := range query.Claims {
			key := c.Id
			if key == "" {
				key = clientmodels.ClaimPathKey(c.Path)
			}
			claimMap[key] = c
		}
		claimsToShow = nil
		for _, key := range query.ClaimSets[0] {
			if c, ok := claimMap[key]; ok {
				claimsToShow = append(claimsToShow, c)
			}
		}
	}

	// Build attributes for the selected claims
	var attributes []clientmodels.Attribute
	for _, claim := range claimsToShow {
		pathKey := clientmodels.ClaimPathKey(claim.Path)
		dn := clientmodels.TranslatedString{"en": pathKey}
		attr := clientmodels.Attribute{
			ClaimPath:   claim.Path,
			DisplayName: &dn,
		}

		// Look up display metadata from the credential type schema
		for _, at := range credType.AttributeTypes {
			if clientmodels.ClaimPathKey([]any{at.ID}) == pathKey {
				name := clientmodels.TranslatedString(at.Name)
				attr.DisplayName = &name
				break
			}
		}

		// Always set RequestedValue on obtainable descriptors (at minimum with just the type).
		// When specific values are requested, include the value.
		requestedValue := &clientmodels.AttributeValue{
			Type: clientmodels.AttributeType_String,
		}
		if len(claim.Values) != 0 {
			if firstValue, ok := claim.Values[0].(string); ok {
				requestedValue.String = &firstValue
			}
		}
		attr.RequestedValue = requestedValue

		attributes = append(attributes, attr)
	}

	// Display in schema order rather than the verifier's claim order.
	attributes = sortAttributesBySchema(attributes, credType)

	return &clientmodels.CredentialDescriptor{
		CredentialId: credTypeId.String(),
		Name:         clientmodels.TranslatedString(credType.Name),
		Issuer:       buildIssuerTrustedParty(h.config, issuer),
		Category:     convertOptionalTranslatedString(credType.Category),
		Image:        clientmodels.ImageFromFile(credType.Logo(h.config)),
		Attributes:   attributes,
		IssueURL:     convertOptionalTranslatedString(credType.IssueURL),
	}, nil
}

// buildLogCredential creates a LogCredential for a disclosed credential.
func (h *SdJwtVcDcqlHandler) buildLogCredential(metadata irmaclient.SdJwtVcBatchMetadata, disclosedClaimPaths [][]any) clientmodels.LogCredential {
	credTypeId := irma.NewCredentialTypeIdentifier(metadata.CredentialType)

	logCred := clientmodels.LogCredential{
		CredentialId: metadata.CredentialType,
		Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
		IssuanceDate: time.Time(metadata.SignedOn).Unix(),
		ExpiryDate:   time.Time(metadata.Expires).Unix(),
	}

	// Enrich with display metadata if available
	if credType, ok := h.config.CredentialTypes[credTypeId]; ok {
		logCred.Name = clientmodels.TranslatedString(credType.Name)
		logCred.Image = clientmodels.ImageFromFile(credType.Logo(h.config))

		if issuer, ok := h.config.Issuers[credType.IssuerIdentifier()]; ok {
			logCred.Issuer = buildIssuerTrustedParty(h.config, issuer)
		}

		logCred.IssueURL = convertOptionalTranslatedString(credType.IssueURL)
	}

	// Build disclosed attributes
	var attributes []clientmodels.Attribute
	for _, claimPath := range disclosedClaimPaths {
		pathKey := clientmodels.ClaimPathKey(claimPath)
		dn := clientmodels.TranslatedString{"en": pathKey}
		attr := clientmodels.Attribute{
			ClaimPath:   claimPath,
			DisplayName: &dn,
		}

		// Look up display name and value from schema.
		// IRMA attributes are flat, so ClaimPathKey([]any{at.ID}) matches the path key.
		var matchedAtType *irma.AttributeType
		if credType, ok := h.config.CredentialTypes[credTypeId]; ok {
			for _, at := range credType.AttributeTypes {
				if clientmodels.ClaimPathKey([]any{at.ID}) == pathKey {
					name := clientmodels.TranslatedString(at.Name)
					description := clientmodels.TranslatedString(at.Description)
					attr.DisplayName = &name
					attr.Description = &description
					matchedAtType = at
					break
				}
			}
		}

		// Set the disclosed value
		if matchedAtType != nil {
			if rawVal, exists := metadata.Attributes[matchedAtType.ID]; exists {
				if strVal, ok := rawVal.(string); ok {
					attr.Value = buildAttributeValue(matchedAtType.DisplayHint, &strVal)
				}
			}
		}

		attributes = append(attributes, attr)
	}
	logCred.Attributes = attributes

	return logCred
}

// ============================================================================
// Shared helper functions
// ============================================================================

// buildIssuerTrustedParty constructs a TrustedParty for an issuer, including its logo
// and the scheme manager as parent.
func buildIssuerTrustedParty(irmaConfig *irma.Configuration, issuer *irma.Issuer) clientmodels.TrustedParty {
	scheme := irmaConfig.SchemeManagers[issuer.SchemeManagerIdentifier()]
	parent := clientmodels.TrustedParty{
		Id:       scheme.Identifier().String(),
		Name:     clientmodels.TranslatedString(scheme.Name),
		Verified: scheme.Status == irma.SchemeManagerStatusValid,
	}
	return clientmodels.TrustedParty{
		Id:       issuer.Identifier().String(),
		Name:     clientmodels.TranslatedString(issuer.Name),
		Image:    clientmodels.ImageFromFile(issuer.Logo(irmaConfig)),
		Verified: scheme.Status == irma.SchemeManagerStatusValid,
		Parent:   &parent,
	}
}

// convertOptionalTranslatedString converts an irma.TranslatedString pointer to a clientmodels.TranslatedString pointer.
func convertOptionalTranslatedString(s *irma.TranslatedString) *clientmodels.TranslatedString {
	if s == nil {
		return nil
	}
	t := clientmodels.TranslatedString(*s)
	return &t
}

// displayHintToAttributeType converts an irma display hint to a clientmodels.AttributeType.
func displayHintToAttributeType(s string) clientmodels.AttributeType {
	switch s {
	case "portraitPhoto":
		return clientmodels.AttributeType_Base64Image
	case "yesno":
		return clientmodels.AttributeType_Bool
	default:
		return clientmodels.AttributeType_String
	}
}

// buildAttributeValue creates an AttributeValue with the value in the correct field
// based on the attribute's display hint.
func buildAttributeValue(displayHint string, rawValue *string) *clientmodels.AttributeValue {
	attrType := displayHintToAttributeType(displayHint)
	val := &clientmodels.AttributeValue{Type: attrType}
	if rawValue == nil {
		return val
	}
	switch attrType {
	case clientmodels.AttributeType_Base64Image:
		val.Base64Image = rawValue
	case clientmodels.AttributeType_Bool:
		switch strings.ToLower(*rawValue) {
		case "yes":
			t := true
			val.Bool = &t
		case "no":
			f := false
			val.Bool = &f
		default:
			val.Type = clientmodels.AttributeType_String
			val.String = rawValue
		}
	default:
		val.String = rawValue
	}
	return val
}

// SortedAttributeTypes returns attribute types sorted by DisplayIndex.
func SortedAttributeTypes(attrs []*irma.AttributeType) []*irma.AttributeType {
	sorted := make([]*irma.AttributeType, len(attrs))
	copy(sorted, attrs)
	slices.SortStableFunc(sorted, func(a, b *irma.AttributeType) int {
		aHas := a.DisplayIndex != nil
		bHas := b.DisplayIndex != nil
		if aHas && bHas {
			return *a.DisplayIndex - *b.DisplayIndex
		}
		if aHas {
			return -1
		}
		if bHas {
			return 1
		}
		return 0
	})
	return sorted
}
