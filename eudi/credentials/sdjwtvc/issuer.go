package sdjwtvc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

type SdJwtVcBuilder struct {
	issuerCertificateChain *[]string
	expiry                 *int64
	issuedAt               *int64
	issuerUrl              *string
	cnfPubKey              *CnfField
	status                 *string
	subject                *string
	vct                    *string
	sdAlg                  *iana.HashingAlgorithm
	disclosures            []DisclosureContent
	ensureHaipCompatible   bool
}

type ClaimType string

const (
	Claim_String ClaimType = "string"
	Claim_Int    ClaimType = "integer"
	Claim_Bool   ClaimType = "boolean"
	Claim_Object ClaimType = "object"
	Claim_Array  ClaimType = "array"
	Claim_Null   ClaimType = "null"
)

type Null struct{}

type LeafClaimDataType interface {
	~string | ~int | ~bool | Null
}

func LeafNodeDataTypeToClaimType[T LeafClaimDataType](v T) ClaimType {
	switch any(v).(type) {
	case string:
		return Claim_String
	case int:
		return Claim_Int
	case bool:
		return Claim_Bool
	default:
		return Claim_Null
	}
}

type SerializedClaim interface {
	Element()
}

type EmbeddedClaimElement struct {
	Key         string
	Value       json.RawMessage
	Disclosures []EncodedDisclosure
}

func (s *EmbeddedClaimElement) Element() {}

type SdClaimElement struct {
	Digest      HashedDisclosure
	Disclosures []EncodedDisclosure
}

func (s *SdClaimElement) Element() {}

// An element in the claim tree of an sdjwt
// Can be used to serialize the claims and create selectively disclosable parts
type ClaimElement struct {
	Type                   ClaimType
	Key                    string
	Value                  any
	SubClaims              []*ClaimElement
	SelectivelyDisclosable bool
}

func (e *ClaimElement) EncodeValueOnly() (SerializedClaim, error) {
	switch e.Type {
	case Claim_Array:
		return e.encodeArrayValueOnly()
	case Claim_Object:
		return e.encodeObjectValueOnly()
	case Claim_Bool:
		return e.encodeLeafValueOnly()
	case Claim_Int:
		return e.encodeLeafValueOnly()
	case Claim_String:
		return e.encodeLeafValueOnly()
	case Claim_Null:
		return e.encodeLeafValueOnly()
	}
	return nil, fmt.Errorf("unsupported claim type: '%v' (%v, %v, %v)", e.Type, e.Key, e.Value, e.SelectivelyDisclosable)
}

func (e *ClaimElement) Encode() (SerializedClaim, error) {
	switch e.Type {
	case Claim_Array:
		return e.encodeArray()
	case Claim_Object:
		return e.encodeObject()
	case Claim_Bool:
		return e.encodeLeaf()
	case Claim_Int:
		return e.encodeLeaf()
	case Claim_String:
		return e.encodeLeaf()
	case Claim_Null:
		return e.encodeLeaf()
	}
	return nil, fmt.Errorf("unsupported claim type: '%v' (%v, %v, %v)", e.Type, e.Key, e.Value, e.SelectivelyDisclosable)
}

func (e *ClaimElement) encodeLeaf() (SerializedClaim, error) {
	if e.SelectivelyDisclosable {
		disclosure, err := NewDisclosureContent(e.Key, e.Value)
		if err != nil {
			return nil, err
		}
		encodedDisclosure, err := EncodeDisclosure(disclosure)
		if err != nil {
			return nil, err
		}
		hash, err := HashEncodedDisclosure(iana.SHA256, encodedDisclosure)
		if err != nil {
			return nil, err
		}
		return &SdClaimElement{
			Digest:      hash,
			Disclosures: []EncodedDisclosure{encodedDisclosure},
		}, nil
	}

	value, err := json.Marshal(e.Value)
	if err != nil {
		return nil, err
	}

	return &EmbeddedClaimElement{
		Key:         e.Key,
		Value:       value,
		Disclosures: []EncodedDisclosure{},
	}, nil
}

func (e *ClaimElement) encodeLeafValueOnly() (SerializedClaim, error) {
	if e.SelectivelyDisclosable {
		disclosure, err := NewArrayItemDisclosureContent(e.Value)
		if err != nil {
			return nil, err
		}
		encodedDisclosure, err := EncodeDisclosure(disclosure)
		if err != nil {
			return nil, err
		}
		hash, err := HashEncodedDisclosure(iana.SHA256, encodedDisclosure)
		if err != nil {
			return nil, err
		}
		return &SdClaimElement{
			Digest:      hash,
			Disclosures: []EncodedDisclosure{encodedDisclosure},
		}, nil
	}

	value, err := json.Marshal(e.Value)
	if err != nil {
		return nil, err
	}

	return &EmbeddedClaimElement{
		Key:         e.Key,
		Value:       value,
		Disclosures: []EncodedDisclosure{},
	}, nil
}

func (e *ClaimElement) encodeObjectValueOnly() (SerializedClaim, error) {
	return nil, nil
}

func (e *ClaimElement) encodeObject() (SerializedClaim, error) {
	result := map[string]any{}
	sd := []HashedDisclosure{}
	disclosures := []EncodedDisclosure{}

	for _, c := range e.SubClaims {
		subClaim, err := c.Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode: %w", err)
		}

		if sdClaim, ok := subClaim.(*SdClaimElement); ok {
			sd = append(sd, sdClaim.Digest)
			disclosures = append(disclosures, sdClaim.Disclosures...)
		} else if emClaim, ok := subClaim.(*EmbeddedClaimElement); ok {
			result[emClaim.Key] = emClaim.Value
			disclosures = append(disclosures, emClaim.Disclosures...)
		} else {
			return nil, fmt.Errorf("somehow claim element not a valid type...")
		}
	}

	result["_sd"] = sd

	if e.SelectivelyDisclosable {
		disclosure, err := NewDisclosureContent(e.Key, result)
		if err != nil {
			return nil, err
		}
		encodedDisclosure, err := EncodeDisclosure(disclosure)
		if err != nil {
			return nil, err
		}
		hash, err := HashEncodedDisclosure(iana.SHA256, encodedDisclosure)
		if err != nil {
			return nil, err
		}
		disclosures = append(disclosures, encodedDisclosure)
		return &SdClaimElement{
			Digest:      hash,
			Disclosures: disclosures,
		}, nil

	}

	value, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return &EmbeddedClaimElement{
		Key:         e.Key,
		Value:       value,
		Disclosures: disclosures,
	}, nil
}

func (e *ClaimElement) encodeArrayValueOnly() (SerializedClaim, error) {
	return nil, nil
}

func (e *ClaimElement) encodeArray() (SerializedClaim, error) {
	result := []any{}
	disclosures := []EncodedDisclosure{}

	for _, c := range e.SubClaims {
		subClaim, err := c.EncodeValueOnly()
		if err != nil {
			return nil, fmt.Errorf("failed to encode: %w", err)
		}

		if sdClaim, ok := subClaim.(*SdClaimElement); ok {
			result = append(result, map[string]HashedDisclosure{"...": sdClaim.Digest})
			disclosures = append(disclosures, sdClaim.Disclosures...)
		} else if emClaim, ok := subClaim.(*EmbeddedClaimElement); ok {
			result = append(result, emClaim.Value)
			disclosures = append(disclosures, emClaim.Disclosures...)
		} else {
			return nil, fmt.Errorf("somehow claim element not a valid type...")
		}
	}

	if e.SelectivelyDisclosable {
		disclosure, err := NewDisclosureContent(e.Key, result)
		if err != nil {
			return nil, err
		}
		encodedDisclosure, err := EncodeDisclosure(disclosure)
		if err != nil {
			return nil, err
		}
		hash, err := HashEncodedDisclosure(iana.SHA256, encodedDisclosure)
		if err != nil {
			return nil, err
		}
		disclosures = append(disclosures, encodedDisclosure)
		return &SdClaimElement{
			Digest:      hash,
			Disclosures: disclosures,
		}, nil

	}

	value, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return &EmbeddedClaimElement{
		Key:         e.Key,
		Value:       value,
		Disclosures: disclosures,
	}, nil
}

type SdJwtBuilder struct {
	claims          []*ClaimElement
	issuerCertChain []string
}

func SdItem[T LeafClaimDataType](value T) *ClaimElement {
	return SdClaim("", value)
}

func Item[T LeafClaimDataType](value T) *ClaimElement {
	return Claim("", value)
}

func Array(key string, items ...*ClaimElement) *ClaimElement {
	return &ClaimElement{
		Type:                   Claim_Array,
		Key:                    key,
		SubClaims:              items,
		SelectivelyDisclosable: false,
	}
}

func SdArray(key string, items ...*ClaimElement) *ClaimElement {
	return &ClaimElement{
		Type:                   Claim_Array,
		Key:                    key,
		SubClaims:              items,
		SelectivelyDisclosable: true,
	}
}

func SdObject(key string, subClaims ...*ClaimElement) *ClaimElement {
	return &ClaimElement{
		Type:                   Claim_Object,
		Key:                    key,
		SubClaims:              subClaims,
		SelectivelyDisclosable: true,
	}
}

func Object(key string, subClaims ...*ClaimElement) *ClaimElement {
	return &ClaimElement{
		Type:                   Claim_Object,
		Key:                    key,
		SubClaims:              subClaims,
		SelectivelyDisclosable: false,
	}
}

func Claim[T LeafClaimDataType](key string, value T) *ClaimElement {
	return &ClaimElement{
		Type:                   LeafNodeDataTypeToClaimType(value),
		Key:                    key,
		Value:                  value,
		SubClaims:              nil,
		SelectivelyDisclosable: false,
	}
}

func SdClaim[T LeafClaimDataType](key string, value T) *ClaimElement {
	return &ClaimElement{
		Type:                   LeafNodeDataTypeToClaimType(value),
		Key:                    key,
		Value:                  value,
		SubClaims:              nil,
		SelectivelyDisclosable: true,
	}
}

func (b *SdJwtBuilder) WithPayload(claims ...*ClaimElement) *SdJwtBuilder {
	b.claims = claims
	return b
}

func (b *SdJwtBuilder) WithIssuerCertificateChain(certChain []string) *SdJwtBuilder {
	b.issuerCertChain = certChain
	return b
}

func (b *SdJwtBuilder) Build(jwtCreator JwtCreator) (SdJwtVc, error) {
	rootNode := &ClaimElement{
		Type:                   Claim_Object,
		SubClaims:              b.claims,
		SelectivelyDisclosable: false,
	}
	claims, err := rootNode.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode root node: %w", err)
	}

	claimsJson, ok := claims.(*EmbeddedClaimElement)
	if !ok {
		return "", fmt.Errorf("root node is not of type EmbeddedClaimElement")
	}

	header := map[string]any{
		"x5c": b.issuerCertChain,
		"typ": "dc+sd-jwt",
	}

	result, err := jwtCreator.CreateSignedJwt(header, string(claimsJson.Value))

	if err != nil {
		return "", fmt.Errorf("failed to create issuer signed payload: %w", err)
	}

	return CreateSdJwtVc(IssuerSignedJwt(result), claimsJson.Disclosures), nil
}

func NewSdJwtBuilder() *SdJwtBuilder {
	return &SdJwtBuilder{}
}

func (b *SdJwtVcBuilder) WithClaims(builders ...*ClaimElement) *SdJwtVcBuilder {
	return nil
}

func NewSdJwtVcBuilder() *SdJwtVcBuilder {
	return &SdJwtVcBuilder{}
}

func (b *SdJwtVcBuilder) WithIssuerCertificateChain(certChain []string) *SdJwtVcBuilder {
	b.issuerCertificateChain = &certChain
	return b
}

func (b *SdJwtVcBuilder) WithExpiresAt(unixTime int64) *SdJwtVcBuilder {
	b.expiry = &unixTime
	return b
}

func (b *SdJwtVcBuilder) WithHaipCompatibility() *SdJwtVcBuilder {
	b.ensureHaipCompatible = true
	return b
}

func (b *SdJwtVcBuilder) WithIssuerUrl(url string) *SdJwtVcBuilder {
	b.issuerUrl = &url
	return b
}

func (b *SdJwtVcBuilder) WithSubject(sub string) *SdJwtVcBuilder {
	b.subject = &sub
	return b
}

func (b *SdJwtVcBuilder) WithStatus(status string) *SdJwtVcBuilder {
	b.status = &status
	return b
}

func (b *SdJwtVcBuilder) WithVerifiableCredentialType(vct string) *SdJwtVcBuilder {
	b.vct = &vct
	return b
}

func (b *SdJwtVcBuilder) WithHashingAlgorithm(alg iana.HashingAlgorithm) *SdJwtVcBuilder {
	b.sdAlg = &alg
	return b
}

func (b *SdJwtVcBuilder) WithDisclosures(disclosures []DisclosureContent) *SdJwtVcBuilder {
	b.disclosures = disclosures
	return b
}

func (b *SdJwtVcBuilder) WithIssuedAt(unixTime int64) *SdJwtVcBuilder {
	b.issuedAt = &unixTime
	return b
}

func (b *SdJwtVcBuilder) WithHolderKey(key jwk.Key) *SdJwtVcBuilder {
	b.cnfPubKey = &CnfField{
		Jwk: key,
	}
	return b
}

func (b *SdJwtVcBuilder) Build(jwtCreator JwtCreator) (SdJwtVc, error) {
	payload := map[string]any{}

	if b.issuerUrl != nil {
		if !strings.HasPrefix(*b.issuerUrl, "https://") {
			return "", fmt.Errorf("issuer url (iss) is required to be a valid https link when provided (but was '%s')", *b.issuerUrl)
		}
		payload[Key_Issuer] = *b.issuerUrl
	}
	if b.cnfPubKey != nil {
		payload[Key_Confirmationkey] = *b.cnfPubKey
	}

	if b.vct != nil {
		payload[Key_VerifiableCredentialType] = *b.vct
	} else {
		return "", fmt.Errorf("'%s' is required but was not supplied", Key_VerifiableCredentialType)
	}

	if b.subject != nil {
		payload[Key_Subject] = *b.subject
	}

	if b.issuedAt != nil {
		payload[Key_IssuedAt] = *b.issuedAt
	}

	if b.expiry != nil {
		payload[Key_ExpiryTime] = *b.expiry
	}

	disclosures, err := EncodeDisclosures(b.disclosures)
	if err != nil {
		return "", err
	}

	if len(b.disclosures) != 0 {
		if b.sdAlg == nil {
			return "", fmt.Errorf("no hashing algorithm defined while there are disclosures")
		}
		encoded, err := HashEncodedDisclosures(*b.sdAlg, disclosures)
		if err != nil {
			return "", err
		}
		payload[Key_Sd] = encoded
	}

	if b.sdAlg != nil {
		payload[Key_SdAlg] = *b.sdAlg
	}
	if b.status != nil {
		payload[Key_Status] = *b.status
	}

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to serialize payload: %v", err)
	}

	headers := map[string]any{
		"typ": SdJwtVcTyp,
	}

	if b.issuerCertificateChain != nil {
		headers["x5c"] = b.issuerCertificateChain
	}

	jwt, err := jwtCreator.CreateSignedJwt(headers, string(payloadJson))
	if err != nil {
		return "", fmt.Errorf("failed to create jwt: %v", err)
	}

	return CreateSdJwtVc(IssuerSignedJwt(jwt), disclosures), nil
}
