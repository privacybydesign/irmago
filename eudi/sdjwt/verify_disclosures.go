package sdjwt

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

func ParseSdField(value any) ([]HashedDisclosure, error) {
	strs, ok := value.([]any)
	if !ok {
		return []HashedDisclosure{}, fmt.Errorf("failed to convert _sd field to []any (%s)", value)
	}
	if len(strs) == 0 {
		return []HashedDisclosure{}, fmt.Errorf("when the _sd field is present it may not be empty")
	}
	result := []HashedDisclosure{}
	for _, s := range strs {
		sStr, ok := s.(string)
		if !ok {
			return []HashedDisclosure{}, fmt.Errorf("failed to convert value in _sd array to string (%v)", s)
		}
		result = append(result, HashedDisclosure(sStr))
	}
	return result, nil
}

func ParseConfirmField(value any) (*CnfField, error) {
	anyMap, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("failed to parse as anymap: %v", value)
	}

	// We support jwk and kid (with did:jwk method) confirmations.
	jwkAny, ok := anyMap["jwk"]
	if ok {
		jwkJson, err := json.Marshal(jwkAny)
		if err != nil {
			return nil, err
		}
		key, err := jwk.ParseKey(jwkJson)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key (%v) from json: %v", value, err)
		}
		return &CnfField{Jwk: &key}, nil
	}
	kidAny, ok := anyMap["kid"]
	if ok {
		kidStr, ok := kidAny.(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse kid field as string: %v", kidAny)
		}
		return &CnfField{Kid: &kidStr}, nil
	}

	return nil, fmt.Errorf("failed to parse cnf field: unsupported confirmation method, expected jwk or did:jwk: %v", value)
}

func VerifyAndProcessDisclosures(sdAlg iana.HashingAlgorithm,
	issuerSignedJwtClaims *map[string]any,
	disclosures []EncodedDisclosure,
) (ProcessedPayload, []*DisclosureContent, error) {
	// Step 3.a: decode all disclosures and calculate their digests
	decodedDisclosuresMap := make(map[HashedDisclosure]*DisclosureContent, len(disclosures))
	for _, disc := range disclosures {
		decodedDisclosure, err := DecodeDisclosure(disc)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode disclosure: %v", err)
		}

		digest, err := HashEncodedDisclosure(sdAlg, disc)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to hash disclosure: %v", err)
		}

		decodedDisclosuresMap[digest] = &decodedDisclosure
	}

	// Keep a list of all disclosures for return value
	decodedDisclosures := slices.Collect(maps.Values(decodedDisclosuresMap))

	// Step 3.b - 3.e: Identify all digests in the Issuer-Signed JWT recursively and replace them with the actual disclosure values
	err := processEmbeddedDisclosures(issuerSignedJwtClaims, decodedDisclosuresMap)
	if err != nil {
		return nil, nil, err
	}

	// Step 4: double encountered digests are signalled as soon as they are found during processing

	// Step 5: if a disclosure was not referenced (i.e. removed from the map), the SD-JWT is invalid
	for _, disclosure := range decodedDisclosuresMap {
		if !disclosure.IsTouched() {
			return nil, nil, fmt.Errorf("one or more disclosures were not referenced in the issuer signed jwt")
		}
	}

	// Step 3.f: remove the _sd_alg field from the claims
	if issuerSignedJwtClaims == nil {
		issuerSignedJwtClaims = &map[string]any{}
	}
	delete(*issuerSignedJwtClaims, SdAlgKey)

	return ProcessedPayload(*issuerSignedJwtClaims), decodedDisclosures, nil
}

func processEmbeddedDisclosures(claims *map[string]any, decodedDisclosures map[HashedDisclosure]*DisclosureContent) error {
	// Only process if there are any claims
	if claims == nil {
		return nil
	}

	// Start with _sd field first
	err := processSdClaim(claims, decodedDisclosures)
	if err != nil {
		return err
	}

	// Then process all other claims
	for claimKey, claimValue := range *claims {
		// If the property is a nested object, recursively process it
		if claimMap, ok := claimValue.(map[string]any); ok {
			err := processEmbeddedDisclosures(&claimMap, decodedDisclosures)
			if err != nil {
				return err
			}
			(*claims)[claimKey] = claimMap
			continue
		}

		// Or, of it is an array, process each element
		if arrayValue, ok := claimValue.([]any); ok {
			processedArray := []any{}
			for _, arrayElemValue := range arrayValue {
				// Check if the value is a disclosure (format should be {"...":"<digest>"}) or not, and if so,
				// verify the array element disclosure exists
				if valMap, ok := arrayElemValue.(map[string]any); ok {
					if arrayElemDisclosureDigestVal, ok := valMap[EllipsisKey]; ok {
						// It's an embedded disclosure digest...
						arrayElemDisclosureDigestStr, ok := arrayElemDisclosureDigestVal.(string)
						if !ok {
							return fmt.Errorf(
								"array element, which should be an embedded disclosure digest, is not a valid digest: %v",
								arrayElemDisclosureDigestStr,
							)
						}

						disclosureDigest := HashedDisclosure(arrayElemDisclosureDigestStr)
						if embeddedDisclosure, ok := decodedDisclosures[disclosureDigest]; ok {
							// Check for array element validity (i.e. should be in format ["...": "<digest>"])
							if embeddedDisclosure.IsTouched() {
								return fmt.Errorf(
									"digest %s has been referenced multiple time in the SD-JWT",
									disclosureDigest,
								)
							}
							if !embeddedDisclosure.IsArrayElement() {
								return fmt.Errorf(
									"embedded disclosure %s is expected to be an array element, but is not",
									embeddedDisclosure.Key,
								)
							}

							// Otherwise, replace the array element with the actual value from the disclosure
							embeddedDisclosure.Touch()
							processedArray = append(processedArray, embeddedDisclosure.Value)
						}

						// In case no disclosure is found for the digest; the value will be ignored (potential decoy digest)
						// Either way; we can continue to the next array element
						continue
					}

					// Complex value, but no embedded digest: just copy it
					// Recursively process the claim map to find further embedded digests
					err := processEmbeddedDisclosures(&valMap, decodedDisclosures)
					if err != nil {
						return err
					}
					processedArray = append(processedArray, valMap)
				} else {
					// Simple value, just copy it
					processedArray = append(processedArray, arrayElemValue)
				}
			}

			(*claims)[claimKey] = processedArray
			continue
		}

		// No embedded disclosures found, just copy the claim as is
		(*claims)[claimKey] = claimValue
	}

	return nil
}

func processSdClaim(claims *map[string]any, decodedDisclosures map[HashedDisclosure]*DisclosureContent) error {
	// Only process if there are any claims
	if claims == nil {
		return nil
	}

	// Check if there's an _sd field at this level
	sdValue, ok := (*claims)[SdKey]
	if !ok {
		return nil
	}

	// Found disclosure digests at this level.. replace with disclosure values
	sdDigests, err := ParseSdField(sdValue)
	if err != nil {
		return fmt.Errorf("failed to parse digests for claim %q: %v", SdKey, err)
	}

	for _, sdDigest := range sdDigests {
		// Disclosure cannot be found for digest; ignore the digest
		if embeddedDisclosure, ok := decodedDisclosures[sdDigest]; ok {
			if embeddedDisclosure.IsTouched() {
				return fmt.Errorf("digest %s has been referenced multiple time in the SD-JWT", sdDigest)
			}
			if embeddedDisclosure.IsArrayElement() {
				return fmt.Errorf("embedded disclosure %s appears to be an array element, which is not expected here", embeddedDisclosure.Key)
			}
			if embeddedDisclosure.Key == SdKey {
				return fmt.Errorf("embedded disclosure %s has an `_sd` field, which is not allowed", embeddedDisclosure.Key)
			}
			if embeddedDisclosure.Key == EllipsisKey {
				return fmt.Errorf("embedded disclosure %s has an `...` field, which is not allowed", embeddedDisclosure.Key)
			}
			if _, ok := (*claims)[embeddedDisclosure.Key]; ok {
				return fmt.Errorf("embedded disclosure key %q already exists at this level", embeddedDisclosure.Key)
			}

			embeddedDisclosure.Touch()
			(*claims)[embeddedDisclosure.Key] = embeddedDisclosure.Value
		}
	}

	// Delete the _sd field after processing
	delete(*claims, SdKey)

	return nil
}

func ExtractClaimsAndDisclosureDigestsFromToken(token jwt.Token) (map[string]any, error) {
	issuerSignedJwtClaims := map[string]any{}
	for _, key := range token.Keys() {
		value, err := jwt.Get[any](token, key)
		if err != nil {
			return nil, fmt.Errorf("failed to get extra claim %s: %v", key, err)
		}

		issuerSignedJwtClaims[key] = value
	}
	return issuerSignedJwtClaims, nil
}
