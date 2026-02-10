package sdjwtvc

import (
	"fmt"

	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

type HolderSdJwt struct {
	IssuerSignedJwt IssuerSignedJwt
	// OPTIONAL: The identifier of the Subject of the Verifiable Credential.
	// The Issuer MAY use it to provide the Subject identifier known by the Issuer.
	// There is no requirement for a binding to exist between sub and cnf claims
	Subject string

	// REQUIRED: the type of verifiable credential
	VerifiableCredentialType string

	// OPTIONAL: expiry time, must not be accepted after this moment
	Expiry int64

	// OPTIONAL: time of issuance
	IssuedAt int64

	// OPTIONAL: The time before which the verifiable credential MUST NOT be accepted before validating
	NotBefore int64

	// OPTIONAL. As defined in Section 4.1.1 of [RFC7519] this claim explicitly indicates the Issuer of the Verifiable Credential
	// when it is not conveyed by other means (e.g., the subject of the end-entity certificate of an x5c header)
	Issuer string

	Claims      *claimNode
	Disclosures *disclosureLookupTable

	// OPTIONAL: hashing algorithm to be used for the disclosure hashes in `_sd` and the hash over
	// the complete SD-JWT VC that can be found in the key binding JWT
	SdAlg iana.HashingAlgorithm

	// OPTIONAL: Public key (JWK format) of the holder, which can be used to verify the key binding jwt
	Confirm *CnfField

	// OPTIONAL: The information on how to read the status of the verifiable credential
	Status string

	KeyBindingJwt *KeyBindingJwtPayload
}

func (h *HolderSdJwt) CreateDisclosure(claimPaths [][]any) (SdJwtVc, error) {
	// set of relevantDisclosures so we don't get duplicates
	relevantDisclosures := map[EncodedDisclosure]struct{}{}
	for _, path := range claimPaths {
		discs, err := h.Claims.getDisclosuresForClaimPath(h.Disclosures, path)
		if err != nil {
			return "", err
		}
		for _, d := range discs {
			relevantDisclosures[d] = struct{}{}
		}
	}
	discs := ""
	for d := range relevantDisclosures {
		discs = fmt.Sprintf("%s%s~", discs, d)
	}

	return SdJwtVc(fmt.Sprintf("%s~%s", h.IssuerSignedJwt, discs)), nil
}

func getAndDelete[T any](claims map[string]any, key string) (T, error) {
	claimAny, ok := claims[key]
	var d T
	if !ok {
		return d, fmt.Errorf("claim '%s' is required but not present", key)
	}
	claim, ok := claimAny.(T)
	if !ok {
		return d, fmt.Errorf("claim '%s' is present but not of the required type", key)
	}
	delete(claims, Key_Issuer)
	return claim, nil
}

func getAndDeleteOptional[T any](claims map[string]any, key string) (T, error) {
	claimAny, ok := claims[key]
	var d T
	if !ok {
		return d, nil
	}
	claim, ok := claimAny.(T)
	if !ok {
		return d, fmt.Errorf("claim '%s' is present but not of the required type", key)
	}
	delete(claims, Key_Issuer)
	return claim, nil
}

type claimNode struct {
	Key    string
	Sd     *HashedDisclosure
	Type   ClaimType
	Value  any
	Object map[string]*claimNode
	Array  []*claimNode
}

func (n *claimNode) getDisclosuresForClaimPath(
	lookup *disclosureLookupTable,
	claimPath []any,
) ([]EncodedDisclosure, error) {
	result := []EncodedDisclosure{}

	// if this is a selectively disclosable node we need to include it, either because it's the leaf
	// node or because it's a link in the chain to resolve to the leaf node
	if n.Sd != nil {
		result = append(result, lookup.Encoded[*n.Sd])
	}
	// when the path is empty we can return the result
	if len(claimPath) == 0 {
		return result, nil
	}
	key := claimPath[0]

	switch k := key.(type) {
	// when it's a string, it has to be a lookup key in an object node
	case string:
		if n.Type != Claim_Object {
			return nil, fmt.Errorf("can't do lookup if claim is not object")
		}
		d, err := n.Object[k].getDisclosuresForClaimPath(lookup, claimPath[1:])
		if err != nil {
			return nil, err
		}
		result = append(result, d...)

	// when it's a number, it has to lookup a single value inside an array
	case int:
		if n.Type != Claim_Array {
			return nil, fmt.Errorf("can't do integer lookup if claim is not an array")
		}
		if a := n.Array; len(a) <= k {
			return nil, fmt.Errorf("index (%v) higher than array length (%v)", k, len(a))
		}
		d, err := n.Array[k].getDisclosuresForClaimPath(lookup, claimPath[1:])
		if err != nil {
			return nil, err
		}
		result = append(result, d...)

	// when it's a nil value, it has to lookup the complete array
	case nil:
		if n.Type != Claim_Array {
			return nil, fmt.Errorf("can't do null lookup if claim is not an array")
		}
		for _, n := range n.Array {
			d, err := n.getDisclosuresForClaimPath(lookup, claimPath[1:])
			if err != nil {
				return nil, err
			}
			result = append(result, d...)
		}
	}

	return result, nil
}

func getSelectivelyDisclosableArrayElement(missingDisclosuresPolicy MissingDisclosuresPolicy, disclosureLookup *disclosureLookupTable, value any) (*claimNode, error) {
	switch m := value.(type) {
	case map[string]any:
		if len(m) != 1 {
			return nil, nil
		}
		hashAny, ok := m["..."]
		if !ok {
			return nil, nil
		}
		hashStr, ok := hashAny.(string)
		if !ok {
			return nil, nil
		}

		hash := HashedDisclosure(hashStr)
		disclosure, ok := disclosureLookup.Contents[hash]
		if !ok {
			return nil, fmt.Errorf("no disclosure found for hash %v", hash)
		}
		node, err := parseClaimValue(missingDisclosuresPolicy, "", disclosure.Value, disclosureLookup)
		node.Sd = &hash

		return node, err
	}
	return nil, nil
}

func parseClaimValue(missingDisclosuresPolicy MissingDisclosuresPolicy, key string, value any, disclosureLookup *disclosureLookupTable) (*claimNode, error) {
	// regular non-sd claim
	switch v := value.(type) {
	case map[string]any:
		node, err := parseClaims(missingDisclosuresPolicy, v, disclosureLookup)
		if err != nil {
			return nil, err
		}
		node.Key = key
		return node, nil
	case []any:
		arrayValues := []*claimNode{}
		for _, c := range v {
			sdNode, err := getSelectivelyDisclosableArrayElement(missingDisclosuresPolicy, disclosureLookup, c)
			if err != nil {
				return nil, err
			}
			if sdNode != nil {
				// if the sd node is not nil we can assume it's a sd array element
				arrayValues = append(arrayValues, sdNode)
			} else {
				// else we assume it to be a normal element
				av, err := parseClaimValue(missingDisclosuresPolicy, "", c, disclosureLookup)
				if err != nil {
					return nil, fmt.Errorf("failed to parse array item: %w", err)
				}
				arrayValues = append(arrayValues, av)
			}
		}
		return &claimNode{
			Key:   key,
			Type:  Claim_Array,
			Array: arrayValues,
		}, nil
	case float64, float32, int:
		return &claimNode{
			Key:   key,
			Type:  Claim_Int,
			Value: v,
		}, nil
	case string:
		return &claimNode{
			Key:   key,
			Type:  Claim_String,
			Value: v,
		}, nil
	case bool:
		return &claimNode{
			Key:   key,
			Type:  Claim_Bool,
			Value: v,
		}, nil
	case nil:
		return &claimNode{
			Key:  key,
			Type: Claim_Null,
		}, nil
	default:
		return nil, fmt.Errorf("claim %v is of unknown type (value: %v)", key, v)
	}
}

type disclosureLookupTable struct {
	Contents map[HashedDisclosure]DisclosureContent
	Encoded  map[HashedDisclosure]EncodedDisclosure
}

// policy for what to do when there's a hash in the _sd field that doesn't have a
// corresponding disclosure
type MissingDisclosuresPolicy int

const (
	MissingDisclosuresPolicy_Allow MissingDisclosuresPolicy = iota
	MissingDisclosuresPolicy_Deny
)

func parseClaims(missingDisclosuresPolicy MissingDisclosuresPolicy, claims map[string]any, disclosureLookup *disclosureLookupTable) (*claimNode, error) {
	result := map[string]*claimNode{}

	for key, value := range claims {
		if key == Key_Sd {
			hashes, ok := value.([]any)
			if !ok {
				return nil, fmt.Errorf("failed to parse sd field: _sd field is not an array: %v", value)
			}

			if len(hashes) == 0 {
				return nil, fmt.Errorf("failed to parse sd field: when the _sd field is present it may not be empty")
			}

			// for each hash find the corresponding disclosure content
			for _, hashAny := range hashes {
				hashStr, ok := hashAny.(string)
				if !ok {
					return nil, fmt.Errorf("hash not of type string: %v", value)
				}
				hash := HashedDisclosure(hashStr)

				disclosure, ok := disclosureLookup.Contents[hash]
				if !ok {
					if missingDisclosuresPolicy == MissingDisclosuresPolicy_Allow {
						continue
					}

					return nil, fmt.Errorf("missing disclosure for %v", hashAny)
				}

				value, err := parseClaimValue(missingDisclosuresPolicy, disclosure.Key, disclosure.Value, disclosureLookup)
				if err != nil {
					return nil, fmt.Errorf("failed to parse claim for disclosure with key %v: %w", disclosure.Key, err)
				}

				value.Sd = &hash
				result[disclosure.Key] = value
			}
		} else {
			claim, err := parseClaimValue(missingDisclosuresPolicy, key, value, disclosureLookup)
			if err != nil {
				return nil, fmt.Errorf("failed to parse claim %v: %w", key, err)
			}
			result[key] = claim
		}
	}
	return &claimNode{
		Type:   Claim_Object,
		Object: result,
	}, nil
}

func createDisclosureLookupTable(
	hashAlg iana.HashingAlgorithm,
	disclosures []EncodedDisclosure,
) (*disclosureLookupTable, error) {
	result := &disclosureLookupTable{
		Contents: map[HashedDisclosure]DisclosureContent{},
		Encoded:  map[HashedDisclosure]EncodedDisclosure{},
	}
	for _, d := range disclosures {
		hash, err := HashEncodedDisclosure(hashAlg, d)
		if err != nil {
			return nil, fmt.Errorf("failed to hash %v: %w", d, err)
		}
		r, err := DecodeDisclosure(d)
		if err != nil {
			return nil, fmt.Errorf("failed to decode %v: %w", d, err)
		}
		result.Contents[hash] = r
		result.Encoded[hash] = d
	}
	return result, nil
}

func Parse(context SdJwtVcVerificationContext, sdjwt SdJwtVc) (*HolderSdJwt, error) {
	issuerSignedJwt, disclosures, err := splitSdJwtVc(sdjwt)
	if err != nil {
		return nil, err
	}

	header, claims, err := decodeJwtWithoutCheckingSignature(string(issuerSignedJwt))
	if err != nil {
		return nil, err
	}

	if header[Key_Typ] != SdJwtVcTyp {
		return nil, fmt.Errorf("header typ not correct")
	}

	issClaim, err := getAndDelete[string](claims, Key_Issuer)
	if err != nil {
		return nil, err
	}

	sdAlgClaim, err := getAndDeleteOptional[string](claims, Key_SdAlg)
	if err != nil {
		return nil, err
	}
	if disclosures != nil && sdAlgClaim == "" {
		return nil, fmt.Errorf("sd-jwt has disclosures but _sd_alg was not specified")
	}
	if sdAlgClaim != string(iana.SHA256) {
		return nil, fmt.Errorf("_sd_alg claim value not supported")
	}

	disclosureLookup, err := createDisclosureLookupTable(iana.SHA256, disclosures)
	if err != nil {
		return nil, err
	}

	claimNode, err := parseClaims(MissingDisclosuresPolicy_Deny, claims, disclosureLookup)
	if err != nil {
		return nil, err
	}

	return &HolderSdJwt{
		IssuerSignedJwt: issuerSignedJwt,
		Issuer:          issClaim,
		SdAlg:           iana.HashingAlgorithm(sdAlgClaim),
		Claims:          claimNode,
		Disclosures:     disclosureLookup,
	}, nil
}
