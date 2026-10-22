package services

import (
	"sort"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// Flattening of a credential's claim values into the attribute rows the app
// renders, for every format: a nested claims object becomes one row per leaf,
// each carrying the full path it was reached by, labelled and ordered from the
// resolved display metadata. Format-neutral; both the SD-JWT VC and the mdoc
// services build their attribute lists through these.

// BuildAttributesFromPayload walks the credential payload top-down and emits an
// Attribute for every claim it finds. Standard JWT/SD-JWT claims are filtered
// out at the top level. The lookup map (built from issuer metadata, resolved
// to the current locale) supplies display names; claims without a metadata
// entry produce attributes with DisplayName: nil. Top-level keys are ordered
// by metadata position, then alphabetically for keys absent from the metadata.
func BuildAttributesFromPayload(
	payload *sdjwt.ProcessedPayload,
	lookup map[string]string,
	metadataOrder map[string]int,
) []clientmodels.Attribute {
	attrs := []clientmodels.Attribute{}
	if payload == nil {
		return attrs
	}
	topLevel := make(map[string]any, len(*payload))
	for k, v := range *payload {
		if _, isStd := sdjwtvc.StandardClaims[k]; isStd {
			continue
		}
		topLevel[k] = v
	}
	for _, key := range sortObjectKeys(topLevel, []any{}, metadataOrder) {
		attrs = FlattenClaimValue(attrs, []any{key}, topLevel[key], lookup, metadataOrder)
	}
	return attrs
}

// FlattenClaimValue recursively flattens arrays and objects into individual scalar
// attributes. Each leaf value gets its own Attribute with the full path from root.
// A section header (Value == nil) is emitted only when the path has an explicit
// display name in the metadata lookup. Object keys are ordered by their position
// in the metadata (via metadataOrder), falling back to alphabetical for keys not
// in the metadata.
func FlattenClaimValue(
	attrs []clientmodels.Attribute,
	path []any,
	value any,
	lookup map[string]string,
	metadataOrder map[string]int,
) []clientmodels.Attribute {
	switch v := value.(type) {
	case []any:
		if d, ok := lookupDisplayName(lookup, path); ok {
			dn := d
			attrs = append(attrs, clientmodels.Attribute{
				ClaimPath:   path,
				DisplayName: &dn,
			})
		}
		for i, elem := range v {
			childPath := append(append([]any{}, path...), i)
			attrs = FlattenClaimValue(attrs, childPath, elem, lookup, metadataOrder)
		}
	case map[string]any:
		if d, ok := lookupDisplayName(lookup, path); ok {
			dn := d
			attrs = append(attrs, clientmodels.Attribute{
				ClaimPath:   path,
				DisplayName: &dn,
			})
		}
		keys := sortObjectKeys(v, path, metadataOrder)
		for _, key := range keys {
			childPath := append(append([]any{}, path...), key)
			attrs = FlattenClaimValue(attrs, childPath, v[key], lookup, metadataOrder)
		}
	default:
		var dn *string
		if d, ok := lookupDisplayName(lookup, path); ok {
			dnCopy := d
			dn = &dnCopy
		}
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   path,
			DisplayName: dn,
			Value:       clientmodels.NewAttributeValue(value),
		})
	}
	return attrs
}

// sortObjectKeys returns the keys of an object sorted by their position in the
// issuer metadata. Keys not in the metadata are appended alphabetically.
func sortObjectKeys(obj map[string]any, parentPath []any, metadataOrder map[string]int) []string {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		pi := metadataOrderForKey(parentPath, keys[i], metadataOrder)
		pj := metadataOrderForKey(parentPath, keys[j], metadataOrder)
		if pi != pj {
			return pi < pj
		}
		return keys[i] < keys[j]
	})
	return keys
}

// metadataOrderForKey returns the metadata order index for a child key under parentPath.
// Tries both exact and wildcard (null) path matching. Returns maxInt if not found.
func metadataOrderForKey(parentPath []any, key string, metadataOrder map[string]int) int {
	childPath := append(append([]any{}, parentPath...), key)
	// Exact match.
	if idx, ok := metadataOrder[clientmodels.ClaimPathKey(childPath)]; ok {
		return idx
	}
	// Wildcard match.
	wildcard := make([]any, len(childPath))
	hasIndex := false
	for i, c := range childPath {
		if isArrayIndex(c) {
			wildcard[i] = nil
			hasIndex = true
		} else {
			wildcard[i] = c
		}
	}
	if hasIndex {
		if idx, ok := metadataOrder[clientmodels.ClaimPathKey(wildcard)]; ok {
			return idx
		}
	}
	return 1<<31 - 1
}

// isArrayIndex returns true if the path component is a numeric array index.
func isArrayIndex(component any) bool {
	switch component.(type) {
	case int, float64:
		return true
	}
	return false
}

// lookupDisplayName checks the lookup map for the given path, first by exact match,
// then by replacing integer indices with nil (null wildcard) to match metadata paths
// like ["faculties", null, "faculty_name"].
func lookupDisplayName(lookup map[string]string, path []any) (string, bool) {
	// Exact match.
	if d, ok := lookup[clientmodels.ClaimPathKey(path)]; ok && d != "" {
		return d, true
	}
	// Wildcard match: replace integer indices with nil.
	wildcard := make([]any, len(path))
	hasIndex := false
	for i, c := range path {
		if isArrayIndex(c) {
			wildcard[i] = nil
			hasIndex = true
		} else {
			wildcard[i] = c
		}
	}
	if hasIndex {
		if d, ok := lookup[clientmodels.ClaimPathKey(wildcard)]; ok && d != "" {
			return d, true
		}
	}
	return "", false
}
