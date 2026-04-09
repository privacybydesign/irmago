package sdjwtvc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

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

	payload, err := decodeJwtPayload(issuerSignedJwt)
	if err != nil {
		return "", err
	}

	hashAlg, ok := payload[Key_SdAlg].(string)
	if !ok {
		return "", fmt.Errorf("missing or invalid %s in JWT payload", Key_SdAlg)
	}

	// Index all disclosures by their hash.
	type indexedDisclosure struct {
		encoded EncodedDisclosure
		decoded DisclosureContent
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

	for _, path := range claimPaths {
		currentObj := payload
		for _, component := range path {
			// Only string components navigate into objects and _sd arrays.
			// Integer/null components (array indices) don't affect disclosure selection.
			key, ok := component.(string)
			if !ok {
				continue
			}

			sdArray, _ := currentObj[Key_Sd].([]any)

			if sdArray != nil {
				// This level has selectively disclosed claims — look for the key in _sd.
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

					if _, dup := selectedSet[hashStr]; !dup {
						selectedSet[hashStr] = struct{}{}
						selected = append(selected, entry.encoded)
					}

					// Descend into the disclosure value for the next path segment.
					if nested, ok := entry.decoded.Value.(map[string]any); ok {
						currentObj = nested
					}
					found = true
					break
				}
				if !found {
					// The key might be a plaintext claim at this level (not in _sd).
					if nested, ok := currentObj[key].(map[string]any); ok {
						currentObj = nested
					} else {
						break
					}
				}
			} else {
				// No _sd at this level — the key must be a plaintext claim.
				if nested, ok := currentObj[key].(map[string]any); ok {
					currentObj = nested
				} else {
					break
				}
			}
		}
	}

	return CreateSdJwtVc(issuerSignedJwt, selected), nil
}

// decodeJwtPayload decodes the payload part of a JWT as raw JSON.
func decodeJwtPayload(jwt IssuerSignedJwt) (map[string]any, error) {
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
