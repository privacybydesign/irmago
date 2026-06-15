package sdjwtvc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

type indexedDisclosure struct {
	encoded EncodedDisclosure
	decoded DisclosureContent
}

// CreatePresentation creates a new SD-JWT VC containing only the disclosures
// that correspond to the given claim paths. Each path is a list of string keys
// that navigate into the (possibly nested) SD-JWT payload.
//
// For a path like ["address", "street"], the function includes:
//   - the disclosure for "address" (if it is selectively disclosed at the top level)
//   - the disclosure for "street" (nested inside the address object's _sd)
//
// The returned SD-JWT VC has the same issuer-signed JWT but only the selected
// disclosures appended.
func CreatePresentation(fullSdJwt SdJwtVc, claimPaths [][]any) (SdJwtVc, error) {
	issuerSignedJwt, payload, byHash, err := decodeAndIndex(fullSdJwt)
	if err != nil {
		return "", err
	}

	selectedSet, selected := collectSelectedDisclosures(payload, byHash, claimPaths)

	// SD-JWT spec Section 4.2.6: validate that every selected disclosure is
	// reachable from the top-level payload through other selected disclosures.
	// This ensures the verifier can locate all included disclosures.
	if err := validateDisclosureDependencies(payload, selectedSet, byHash); err != nil {
		return "", err
	}

	return CreateSdJwtVc(issuerSignedJwt, selected), nil
}

// PostDisclosureView returns the JSON value a verifier would see if a
// presentation were built for the given claim paths. The returned map has the
// same shape as the JWT payload with the selected disclosures applied: bundled
// fields from a single disclosure value appear inline, hidden _sd entries are
// dropped, and hidden array-element digests stay as nil placeholders so array
// indices remain stable. Standard JWT/SD-JWT meta keys (_sd, _sd_alg) are
// stripped from objects in the returned view.
//
// Use this to drive UI/log flattening: the disclosure plan and disclosure log
// should reflect what the verifier actually receives, not just the requested
// paths. When the issuer chose a coarse SD granularity (multiple fields
// bundled into one disclosure value), those bundled fields show up here so
// the user sees them up front.
func PostDisclosureView(fullSdJwt SdJwtVc, claimPaths [][]any) (map[string]any, error) {
	_, payload, byHash, err := decodeAndIndex(fullSdJwt)
	if err != nil {
		return nil, err
	}
	selectedSet, _ := collectSelectedDisclosures(payload, byHash, claimPaths)
	view, _ := applyDisclosures(payload, selectedSet, byHash).(map[string]any)
	return view, nil
}

// decodeAndIndex splits and decodes an SD-JWT VC and indexes its disclosures
// by hash, ready for path-walking and disclosure-application logic.
func decodeAndIndex(fullSdJwt SdJwtVc) (IssuerSignedJwt, map[string]any, map[string]indexedDisclosure, error) {
	issuerSignedJwt, allDisclosures, err := splitSdJwtVc(fullSdJwt)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to split SD-JWT VC: %v", err)
	}
	payload, err := decodeJwtPayloadFromJwt(issuerSignedJwt)
	if err != nil {
		return "", nil, nil, err
	}

	// SD-JWT spec Section 4.1.1: default to sha-256 if _sd_alg is absent.
	hashAlg, ok := payload[Key_SdAlg].(string)
	if !ok {
		hashAlg = string(iana.SHA256)
	}

	byHash := make(map[string]indexedDisclosure, len(allDisclosures))
	for _, enc := range allDisclosures {
		hash, err := CreateUrlEncodedHash(iana.HashingAlgorithm(hashAlg), string(enc))
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to hash disclosure: %v", err)
		}
		dec, err := DecodeDisclosure(enc)
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to decode disclosure: %v", err)
		}
		byHash[hash] = indexedDisclosure{encoded: enc, decoded: dec}
	}
	return issuerSignedJwt, payload, byHash, nil
}

// collectSelectedDisclosures walks each claim path through the SD-JWT payload
// and returns the set of disclosures that must be included to expose those
// leaves to a verifier. The slice is in walk order; the set is for fast
// dedup/lookup.
func collectSelectedDisclosures(
	payload map[string]any,
	byHash map[string]indexedDisclosure,
	claimPaths [][]any,
) (map[string]struct{}, []EncodedDisclosure) {
	selectedSet := make(map[string]struct{})
	var selected []EncodedDisclosure

	addDisclosure := func(hashStr string) {
		if entry, ok := byHash[hashStr]; ok {
			if _, dup := selectedSet[hashStr]; !dup {
				selectedSet[hashStr] = struct{}{}
				selected = append(selected, entry.encoded)
			}
		}
	}

	for _, path := range claimPaths {
		// currentValue tracks the value at the current position in the path walk.
		// It starts as the top-level payload (a map) and may become an array or
		// nested map as we descend.
		var currentValue any = payload

		for _, component := range path {
			switch key := component.(type) {
			case string:
				// String component: navigate into an object, checking _sd for SD claims.
				obj, ok := currentValue.(map[string]any)
				if !ok {
					currentValue = nil
					break
				}

				sdArray, _ := obj[Key_Sd].([]any)
				if sdArray != nil {
					found := false
					for _, h := range sdArray {
						hashStr, ok := h.(string)
						if !ok {
							continue
						}
						entry, exists := byHash[hashStr]
						if !exists || entry.decoded.Key != key {
							continue
						}
						addDisclosure(hashStr)
						currentValue = entry.decoded.Value
						found = true
						break
					}
					if !found {
						// The key might be a plaintext claim at this level.
						currentValue = obj[key]
					}
				} else {
					currentValue = obj[key]
				}

			case float64:
				// JSON numbers decode as float64; treat as array index.
				currentValue = resolveArrayIndex(currentValue, int(key), addDisclosure, byHash)

			case int:
				currentValue = resolveArrayIndex(currentValue, key, addDisclosure, byHash)

			default:
				// nil (wildcard) or unsupported — stop descending.
				currentValue = nil
			}

			if currentValue == nil {
				break
			}
		}
	}

	return selectedSet, selected
}

// applyDisclosures returns the JSON value a verifier would see after the
// selected disclosures are applied to the payload. _sd arrays are replaced by
// their disclosed children, _sd_alg is dropped, and unselected array-element
// digests stay as nil placeholders so array indices remain stable.
func applyDisclosures(value any, selected map[string]struct{}, byHash map[string]indexedDisclosure) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, child := range v {
			switch k {
			case Key_Sd:
				hashes, ok := child.([]any)
				if !ok {
					continue
				}
				for _, h := range hashes {
					hashStr, ok := h.(string)
					if !ok {
						continue
					}
					if _, sel := selected[hashStr]; !sel {
						continue
					}
					entry, ok := byHash[hashStr]
					if !ok {
						continue
					}
					out[entry.decoded.Key] = applyDisclosures(entry.decoded.Value, selected, byHash)
				}
			case Key_SdAlg:
				// metadata only, never user data
			default:
				out[k] = applyDisclosures(child, selected, byHash)
			}
		}
		return out
	case []any:
		// Preserve length and indices: hidden array-element digests stay as
		// nil placeholders so callers can compare authorized leaf paths
		// against the verifier-side view without index-shift surprises.
		out := make([]any, len(v))
		for i, elem := range v {
			if obj, ok := elem.(map[string]any); ok {
				if digest, ok := obj["..."].(string); ok {
					if _, sel := selected[digest]; !sel {
						continue
					}
					entry, ok := byHash[digest]
					if !ok {
						continue
					}
					out[i] = applyDisclosures(entry.decoded.Value, selected, byHash)
					continue
				}
			}
			out[i] = applyDisclosures(elem, selected, byHash)
		}
		return out
	default:
		return v
	}
}

// validateDisclosureDependencies checks that every selected disclosure hash is
// reachable from the top-level JWT payload. A disclosure is reachable if its
// hash appears in an _sd array or {"..."} entry that can be navigated to from
// the root, following only other selected disclosures to reveal nested structures.
func validateDisclosureDependencies(payload map[string]any, selectedSet map[string]struct{}, byHash map[string]indexedDisclosure) error {
	reachable := make(map[string]struct{})
	collectReachableHashes(payload, selectedSet, byHash, reachable)

	for hash := range selectedSet {
		if _, ok := reachable[hash]; !ok {
			entry := byHash[hash]
			return fmt.Errorf(
				"disclosure dependency violation (SD-JWT Section 4.2.6): disclosure for %q is not reachable from the top-level payload — a parent disclosure is missing",
				entry.decoded.Key,
			)
		}
	}
	return nil
}

// collectReachableHashes walks a JSON value and collects all disclosure hashes
// that are reachable. When a reachable hash belongs to a selected disclosure
// whose value is an object or array, that value is walked recursively.
func collectReachableHashes(value any, selectedSet map[string]struct{}, byHash map[string]indexedDisclosure, reachable map[string]struct{}) {
	switch v := value.(type) {
	case map[string]any:
		// Check _sd array for object-level SD claims.
		if sdArray, ok := v[Key_Sd].([]any); ok {
			for _, h := range sdArray {
				hashStr, ok := h.(string)
				if !ok {
					continue
				}
				reachable[hashStr] = struct{}{}
				// If this disclosure is selected, recurse into its value.
				if _, selected := selectedSet[hashStr]; selected {
					if entry, ok := byHash[hashStr]; ok {
						collectReachableHashes(entry.decoded.Value, selectedSet, byHash, reachable)
					}
				}
			}
		}
		// Recurse into all object values (non-_sd keys may contain nested structures).
		for key, child := range v {
			if key != Key_Sd {
				collectReachableHashes(child, selectedSet, byHash, reachable)
			}
		}
	case []any:
		for _, elem := range v {
			// Check for SD array element: {"...": "<digest>"}
			if obj, ok := elem.(map[string]any); ok {
				if digest, ok := obj["..."].(string); ok {
					reachable[digest] = struct{}{}
					if _, selected := selectedSet[digest]; selected {
						if entry, ok := byHash[digest]; ok {
							collectReachableHashes(entry.decoded.Value, selectedSet, byHash, reachable)
						}
					}
					continue
				}
			}
			collectReachableHashes(elem, selectedSet, byHash, reachable)
		}
	}
}

// resolveArrayIndex navigates to a specific index in an array value.
// If the element at that index is an SD-JWT array element digest ({"...": hash}),
// the corresponding disclosure is added via addFn and the disclosed value is returned
// so that deeper path components can continue navigating into it.
func resolveArrayIndex(currentValue any, idx int, addFn func(string), byHash map[string]indexedDisclosure) any {
	arr, ok := currentValue.([]any)
	if !ok || idx < 0 || idx >= len(arr) {
		return nil
	}
	elem := arr[idx]

	// Check if this is an SD array element: {"...": "<digest>"}
	if obj, ok := elem.(map[string]any); ok {
		if digest, ok := obj["..."].(string); ok {
			addFn(digest)
			// Return the disclosed value so deeper path components can navigate into it.
			if entry, ok := byHash[digest]; ok {
				return entry.decoded.Value
			}
			return nil
		}
	}

	return elem
}

// DecodeJwtPayload extracts and decodes the payload of the issuer-signed JWT
// from an SD-JWT VC. The disclosures and KB-JWT suffix are stripped first.
func DecodeJwtPayload(sdJwt SdJwtVc) (map[string]any, error) {
	issJwt, _, err := splitSdJwtVc(sdJwt)
	if err != nil {
		return nil, err
	}
	return decodeJwtPayloadFromJwt(issJwt)
}

func decodeJwtPayloadFromJwt(jwt IssuerSignedJwt) (map[string]any, error) {
	parts := strings.Split(string(jwt), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to base64url-decode JWT payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload JSON: %v", err)
	}
	return payload, nil
}
