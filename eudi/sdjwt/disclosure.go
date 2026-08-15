package sdjwt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"iter"

	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

// The format of an SD-JWT:
//
// Without any disclosures:
//     <Issuer signed JWT>~
//
// With disclosures:
//     <Issuer signed JWT>~<Disclosure 1>~<Disclosure2>~...~<Disclosure N>~
//
// Without disclosures, but with a KB-JWT:
//     <Issuer signed JWT>~<KB-JWT>
//
// With disclosures and a KB-JWT:
//     <Issuer signed JWT>~<Disclosure 1>~<Disclosure2>~...~<Disclosure N>~<KB-JWT>
//
// The Disclosures are base64url encoded from a json array of `[salt, key, value]`
// where the salt should be a cryptographically random string, the key a string
// and the value a valid json value

// DisclosureContent is an easier to use representation of the content of a disclosure.
// This should be turned into a json array before processing further.
type DisclosureContent struct {
	// RECOMMENDED to base64url-encode a minimum of 128 bits of cryptographically secure random data,
	// producing a string. The salt value MUST be unique for each claim that is to be selectively disclosed.
	// The Issuer MUST NOT reveal the salt value to any party other than the Holder
	Salt string
	Key  string
	// This value can be any type that is allowed in JSON
	Value any

	// Processing related fields
	isArrayElement bool
	touched        bool
}

type DisclosureContents []DisclosureContent

func (d *DisclosureContent) IsArrayElement() bool {
	return d.isArrayElement
}

func (d *DisclosureContent) Touch() {
	d.touched = true
}

func (d *DisclosureContent) IsTouched() bool {
	return d.touched
}

func (d DisclosureContents) Keys() iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, item := range d {
			if !yield(item.Key) {
				break
			}
		}
	}
}

func generateSalt(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewDisclosureContent creates a disclosure content struct with a salt
func NewDisclosureContent(key string, value any) (DisclosureContent, error) {
	salt, err := generateSalt(16) // 128 bit salt
	if err != nil {
		return DisclosureContent{}, err
	}
	return DisclosureContent{
		Salt:  salt,
		Key:   key,
		Value: value,
	}, nil
}

func NewArrayItemDisclosureContent(value any) (DisclosureContent, error) {
	salt, err := generateSalt(16) // 128 bit salt
	if err != nil {
		return DisclosureContent{}, err
	}
	return DisclosureContent{
		Salt:           salt,
		Value:          value,
		isArrayElement: true,
	}, nil
}

func MultipleNewDisclosureContents[T any](values map[string]T) ([]DisclosureContent, error) {
	result := []DisclosureContent{}
	for key, value := range values {
		disc, err := NewDisclosureContent(key, value)
		if err != nil {
			return []DisclosureContent{}, err
		}
		result = append(result, disc)
	}
	return result, nil
}

func DecodeDisclosure(disclosure EncodedDisclosure) (DisclosureContent, error) {
	decodedBytes, err := base64.RawURLEncoding.DecodeString(string(disclosure))
	if err != nil {
		return DisclosureContent{}, fmt.Errorf("failed to decode disclosure: %v (%s)", err, disclosure)
	}

	var array []any
	err = json.Unmarshal(decodedBytes, &array)
	if err != nil {
		return DisclosureContent{}, fmt.Errorf("failed to parse json from decoded disclosure bytes: %v", err)
	}

	num := len(array)
	if num != 2 && num != 3 {
		return DisclosureContent{}, fmt.Errorf("disclosure array length should be 2 (for array ellements) or 3 (for object properties) but is %v", num)
	}

	salt, ok := array[0].(string)
	if !ok {
		return DisclosureContent{}, fmt.Errorf("failed to get salt from disclosure array: %v", array)
	}

	var key string
	var value any
	if num == 2 {
		// This is an array element disclosure
		value = array[1]
	} else {
		// This is an object property disclosure
		key, ok = array[1].(string)
		if !ok {
			return DisclosureContent{}, fmt.Errorf("failed to get key from disclosure array: %v", array)
		}

		value = array[2]
	}

	return DisclosureContent{
		Salt:           salt,
		Key:            key,
		Value:          value,
		isArrayElement: num == 2,
	}, nil
}

// EncodedDisclosure is the base64url encoded version of a json array based on the `DisclosureContent` struct
// (without any ~ before or after it)
type EncodedDisclosure string

// HashedDisclosure is the hashed + base64url-encoded version of the `EncodedDisclosure` type
type HashedDisclosure string

func HashEncodedDisclosure(algorithm iana.HashingAlgorithm, disclosure EncodedDisclosure) (HashedDisclosure, error) {
	hash, err := iana.CreateUrlEncodedHash(algorithm, string(disclosure))
	if err != nil {
		return "", err
	}
	return HashedDisclosure(hash), nil
}

func HashEncodedDisclosures(algorithm iana.HashingAlgorithm, disclosures []EncodedDisclosure) ([]HashedDisclosure, error) {
	result := []HashedDisclosure{}
	for _, d := range disclosures {
		hash, err := HashEncodedDisclosure(algorithm, d)
		if err != nil {
			return []HashedDisclosure{}, err
		}
		result = append(result, hash)
	}
	return result, nil
}

func HashDisclosure(algorithm iana.HashingAlgorithm, claim DisclosureContent) (HashedDisclosure, error) {
	disclosure, err := EncodeDisclosure(claim)
	if err != nil {
		return "", err
	}
	return HashEncodedDisclosure(algorithm, disclosure)
}

func HashDisclosures(algorithm iana.HashingAlgorithm, disclosures []DisclosureContent) ([]HashedDisclosure, error) {
	result := []HashedDisclosure{}
	for _, d := range disclosures {
		hash, err := HashDisclosure(algorithm, d)
		if err != nil {
			return []HashedDisclosure{}, nil
		}
		result = append(result, hash)
	}
	return result, nil
}

func makeClaimDisclosureArrayJson(claim DisclosureContent) ([]byte, error) {
	var claimArray []any

	if claim.isArrayElement {
		claimArray = []any{claim.Salt, claim.Value}
	} else {
		claimArray = []any{claim.Salt, claim.Key, claim.Value}
	}
	jsonBytes, err := json.Marshal(claimArray)
	if err != nil {
		return []byte{}, err
	}
	return jsonBytes, nil
}

// EncodeDisclosure creates a base64url encoded disclosure
func EncodeDisclosure(sdClaim DisclosureContent) (EncodedDisclosure, error) {
	jsonBytes, err := makeClaimDisclosureArrayJson(sdClaim)

	if err != nil {
		return "", nil
	}

	encoded := base64.RawURLEncoding.EncodeToString(jsonBytes)
	return EncodedDisclosure(encoded), nil
}

// EncodeDisclosures encodes the list of claims for the disclosure part of the sd jwt
func EncodeDisclosures(disclosures []DisclosureContent) ([]EncodedDisclosure, error) {
	result := []EncodedDisclosure{}
	for _, c := range disclosures {
		disc, err := EncodeDisclosure(c)
		if err != nil {
			return []EncodedDisclosure{}, err
		}
		result = append(result, disc)
	}
	return result, nil
}
