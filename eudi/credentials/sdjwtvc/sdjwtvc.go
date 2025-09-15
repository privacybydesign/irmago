package sdjwtvc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// The format of an SD-JWT VC:
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
	Value interface{}
}

type DisclosureContents []DisclosureContent

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

	if num := len(array); num != 3 {
		return DisclosureContent{}, fmt.Errorf("disclosure array length should be 3 but is %v", num)
	}

	salt, ok := array[0].(string)
	if !ok {
		return DisclosureContent{}, fmt.Errorf("failed to get salt from disclosure array: %v", array)
	}

	key, ok := array[1].(string)
	if !ok {
		return DisclosureContent{}, fmt.Errorf("failed to get key from disclosure array: %v", array)
	}

	value := array[2]

	return DisclosureContent{
		Salt:  salt,
		Key:   key,
		Value: value,
	}, nil
}

func DecodeDisclosures(disclosures []EncodedDisclosure) ([]DisclosureContent, error) {
	result := []DisclosureContent{}
	for _, d := range disclosures {
		decoded, err := DecodeDisclosure(d)
		if err != nil {
			return []DisclosureContent{}, err
		}
		result = append(result, decoded)
	}
	return result, nil
}

// EncodedDisclosure is the base64url encoded version of a json array based on the `DisclosureContent` struct
// (without any ~ before or after it)
type EncodedDisclosure string

// HashedDisclosure is the hashed + base64url-encoded version of the `EncodedDisclosure` type
type HashedDisclosure string

type CnfField struct {
	Jwk jwk.Key `json:"jwk"`
}

type HashingAlgorithm string

// IssuerSignedJwtPayload_ToJson converts the payload of the issuer signed jwt to json,
// taking into account some sdjwtvc specific rules
func IssuerSignedJwtPayload_ToJson(payload IssuerSignedJwtPayload) (string, error) {
	jsonValues := make(map[string]interface{})

	if !strings.HasPrefix(payload.Issuer, "https://") {
		return "", fmt.Errorf("issuer (`iss`) field is required to be an https link, but is %s", payload.Issuer)
	}

	if len(payload.Sd) != 0 {
		jsonValues[Key_Sd] = payload.Sd
	}

	if payload.SdAlg != "" {
		jsonValues[Key_SdAlg] = payload.SdAlg
	}

	if payload.Confirm.Jwk != nil {
		jsonValues[Key_Confirmationkey] = payload.Confirm
	}

	jsonValues[Key_VerifiableCredentialType] = payload.VerifiableCredentialType
	jsonValues[Key_ExpiryTime] = payload.Expiry
	jsonValues[Key_IssuedAt] = payload.IssuedAt
	jsonValues[Key_Subject] = payload.Subject
	jsonValues[Key_Issuer] = payload.Issuer

	jsonBytes, err := json.Marshal(jsonValues)
	return string(jsonBytes), err
}

// SelectDisclosures removes all disclosures at the end of the provided sdjwtvc,
// except the ones specified.
// Note that this expects an sdjwtvc without a kbjwt, as it would not make sense to
// remove disclosures from an sdjwtvc with a kbjwt.
func SelectDisclosures(fullSdjwt SdJwtVc, disclosureNames []string) (SdJwtVc, error) {
	issuerSignedJwt, disclosures, _, err := SplitSdJwtVc(fullSdjwt)
	if err != nil {
		return "", fmt.Errorf("failed to split sdjwtvc: %v", err)
	}

	disclosuresToKeep := []EncodedDisclosure{}
	for _, disclosure := range disclosures {
		decoded, err := DecodeDisclosure(disclosure)
		if err != nil {
			return "", fmt.Errorf("failed to decode disclosure: %v", err)
		}
		if slices.Contains(disclosureNames, decoded.Key) {
			disclosuresToKeep = append(disclosuresToKeep, disclosure)
		}
	}

	return CreateSdJwtVc(issuerSignedJwt, disclosuresToKeep), nil
}

const (
	HashAlg_Sha256 HashingAlgorithm = "sha-256"

	Key_Subject                  string = "sub"
	Key_VerifiableCredentialType string = "vct"
	Key_ExpiryTime               string = "exp"
	Key_IssuedAt                 string = "iat"
	Key_Issuer                   string = "iss"
	Key_Sd                       string = "_sd"
	Key_SdAlg                    string = "_sd_alg"
	Key_Confirmationkey          string = "cnf"
	Key_Status                   string = "status"
	Key_NotBefore                string = "nbf"
	Key_Typ                      string = "typ"
	Key_X5c                      string = "x5c"

	SdJwtVcTyp        string = "dc+sd-jwt"
	SdJwtVcTyp_Legacy string = "vc+sd-jwt"
	KbJwtTyp          string = "kb+jwt"
)

// IssuerSignedJwtPayload is a representation of the payload of the issuer signed jwt part of an SD-JWT VC
type IssuerSignedJwtPayload struct {
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

	// OPTIONAL. As defined in Section 4.1.1 of [RFC7519] this claim explicitly indicates the Issuer of the Verifiable Credential
	// when it is not conveyed by other means (e.g., the subject of the end-entity certificate of an x5c header)
	Issuer string

	// OPTIONAL: list of hashed -> base64url encoded disclosures
	// hashing algorithm is defined by `_sd_alg` field
	// is allowed to be omitted, and is not allowed to be empty (should be omitted in that case)
	Sd []HashedDisclosure

	// OPTIONAL: hashing algorithm to be used for the disclosure hashes in `_sd` and the hash over
	// the complete SD-JWT VC that can be found in the key binding JWT
	SdAlg HashingAlgorithm

	// OPTIONAL: Public key (JWK format) of the holder, which can be used to verify the key binding jwt
	Confirm CnfField

	// OPTIONAL: The information on how to read the status of the verifiable credential
	Status string

	// OPTIONAL: The time before which the verifiable credential MUST NOT be accepted before validating
	NotBefore int64
}

// IssuerSignedJwt is the issued signed jwt as a string (so only the section of the sd-jwt vc up to and NOT including the first ~)
type IssuerSignedJwt string

// SdJwtVc represents any full sd-jwt vc as a string, be it with or without disclosures or key binding jwt
type SdJwtVc string

// SdJwtVc_IssuerRepresentation is a representation of the SD-JWT VC that can be used by the issuer or holder to issue and disclose
type SdJwtVc_IssuerRepresentation struct {
	IssuerSignedJwt IssuerSignedJwt
	Disclosures     []DisclosureContent
}

func CreateHash(algorithm HashingAlgorithm, content string) (string, error) {
	if algorithm != HashAlg_Sha256 {
		return "", fmt.Errorf("%s is not a supported hashing algorithm, valid choice: %s", algorithm, HashAlg_Sha256)
	}
	hash := sha256.Sum256([]byte(content))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func HashEncodedDisclosure(algorithm HashingAlgorithm, disclosure EncodedDisclosure) (HashedDisclosure, error) {
	hash, err := CreateHash(algorithm, string(disclosure))
	if err != nil {
		return "", err
	}
	return HashedDisclosure(hash), nil
}

func HashEncodedDisclosures(algorithm HashingAlgorithm, disclosures []EncodedDisclosure) ([]HashedDisclosure, error) {
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

func HashDisclosure(algorithm HashingAlgorithm, claim DisclosureContent) (HashedDisclosure, error) {
	disclosure, err := EncodeDisclosure(claim)
	if err != nil {
		return "", err
	}
	return HashEncodedDisclosure(algorithm, disclosure)
}

func HashDisclosures(algorithm HashingAlgorithm, disclosures []DisclosureContent) ([]HashedDisclosure, error) {
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
	claimArray := []interface{}{claim.Salt, claim.Key, claim.Value}
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

func CreateSdJwtVc(issJwt IssuerSignedJwt, disclosures []EncodedDisclosure) SdJwtVc {
	discs := ""
	for _, d := range disclosures {
		discs = fmt.Sprintf("%s%s~", discs, d)
	}

	return SdJwtVc(fmt.Sprintf("%s~%s", issJwt, discs))
}

func CreateSdJwtVcWithDisclosureContents(issJwt IssuerSignedJwt, disclosures []DisclosureContent) (SdJwtVc, error) {
	discs := ""
	for _, d := range disclosures {
		encD, err := EncodeDisclosure(d)
		if err != nil {
			return "", err
		}
		discs = fmt.Sprintf("%s%s~", discs, encD)
	}

	return SdJwtVc(fmt.Sprintf("%s~%s", issJwt, discs)), nil
}

func AddKeyBindingJwtToSdJwtVc(sdjwtvc SdJwtVc, kbjwt KeyBindingJwt) SdJwtVc {
	return SdJwtVc(fmt.Sprintf("%s%s", sdjwtvc, kbjwt))
}

func CreateIssuerSignedJwt(payload IssuerSignedJwtPayload, jwtCreator JwtCreator) (IssuerSignedJwt, error) {
	json, err := IssuerSignedJwtPayload_ToJson(payload)
	if err != nil {
		return "", err
	}

	customHeaders := map[string]any{
		"typ": SdJwtVcTyp,
	}
	jwt, err := jwtCreator.CreateSignedJwt(customHeaders, json)
	if err != nil {
		return "", err
	}
	return IssuerSignedJwt(jwt), nil
}

func CreateTestSdJwtVc() (SdJwtVc, error) {
	sdClaims, err := MultipleNewDisclosureContents(map[string]string{
		"family_name": "Yivi",
		"location":    "Utrecht",
	})

	if err != nil {
		return "", err
	}

	sdClaimHashes, err := HashDisclosures(HashAlg_Sha256, sdClaims)
	if err != nil {
		return "", err
	}

	holderKey, err := readHolderPublicJwk()
	if err != nil {
		return "", err
	}

	sdJwtClaims := IssuerSignedJwtPayload{
		Subject:                  "6c5c0a49-b589-431d-bae7-219122a9ec2c",
		Sd:                       sdClaimHashes,
		SdAlg:                    HashAlg_Sha256,
		Issuer:                   "https://openid4vc.staging.yivi.app",
		Confirm:                  holderKey,
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
		Expiry:                   1835689661,
		IssuedAt:                 1516239022,
	}

	signer := NewEcdsaJwtCreatorWithIssuerTestkey()
	jwt, err := CreateIssuerSignedJwt(sdJwtClaims, signer)

	if err != nil {
		return "", err
	}

	sdJwtVc, err := CreateSdJwtVcWithDisclosureContents(jwt, sdClaims)

	if err != nil {
		return "", err
	}

	return sdJwtVc, nil
}
