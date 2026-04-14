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
	issuerSignedJwt, allDisclosures, err := splitSdJwtVc(fullSdJwt)
	if err != nil {
		return "", fmt.Errorf("failed to split SD-JWT VC: %v", err)
	}

	payload, err := decodeJwtPayloadFromJwt(issuerSignedJwt)
	if err != nil {
		return "", err
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
			return "", fmt.Errorf("failed to hash disclosure: %v", err)
		}
		dec, err := DecodeDisclosure(enc)
		if err != nil {
			return "", fmt.Errorf("failed to decode disclosure: %v", err)
		}
		byHash[hash] = indexedDisclosure{encoded: enc, decoded: dec}
	}

	// For each claim path, walk the payload _sd structure and collect needed disclosures.
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

	return CreateSdJwtVc(issuerSignedJwt, selected), nil
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
