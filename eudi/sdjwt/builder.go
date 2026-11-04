package sdjwt

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

type ClaimType string

const (
	Claim_String ClaimType = "string"
	Claim_Int    ClaimType = "integer"
	Claim_Bool   ClaimType = "boolean"
	Claim_Object ClaimType = "object"
	Claim_Array  ClaimType = "array"
	Claim_Null   ClaimType = "null"
)

type encodeMode int

const (
	encodeFullClaim encodeMode = iota
	encodeValueOnly
)

func sdElementFromDisclosure(content DisclosureContent, existing []EncodedDisclosure) (*SdClaimElement, []EncodedDisclosure, error) {
	disclosure, err := EncodeDisclosure(content)
	if err != nil {
		return nil, nil, err
	}

	hash, err := HashEncodedDisclosure(iana.SHA256, disclosure)
	if err != nil {
		return nil, nil, err
	}

	all := append(existing, disclosure)
	return &SdClaimElement{
		Digest:      hash,
		Disclosures: all,
	}, all, nil
}

func marshalEmbedded(key string, v any, disclosures []EncodedDisclosure) (*EmbeddedClaimElement, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &EmbeddedClaimElement{
		Key:         key,
		Value:       raw,
		Disclosures: disclosures,
	}, nil
}

type Null struct{}

type LeafClaimDataType interface {
	~string | ~int | ~bool | Null | ~int64
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

// ClaimElement is an element in the claim tree of an sdjwt.
// It can be used to serialize the claims and create selectively disclosable parts
type ClaimElement struct {
	Type                   ClaimType
	Key                    string
	Value                  any
	SubClaims              []*ClaimElement
	SelectivelyDisclosable bool
}

func (e *ClaimElement) encode(mode encodeMode) (SerializedClaim, error) {
	switch e.Type {
	case Claim_Array:
		return e.encodeArray(mode)
	case Claim_Object:
		return e.encodeObject(mode)
	case Claim_String, Claim_Int, Claim_Bool, Claim_Null:
		return e.encodeLeaf(mode)
	default:
		return nil, fmt.Errorf("unsupported claim type: '%v' (%v, %v, %v)",
			e.Type, e.Key, e.Value, e.SelectivelyDisclosable)
	}
}

func (e *ClaimElement) encodeLeaf(mode encodeMode) (SerializedClaim, error) {
	if e.SelectivelyDisclosable {

		var content DisclosureContent
		if mode == encodeFullClaim {
			d, err := NewDisclosureContent(e.Key, e.Value)
			if err != nil {
				return nil, err
			}
			content = d
		} else {
			d, err := NewArrayItemDisclosureContent(e.Value)
			if err != nil {
				return nil, err
			}
			content = d
		}

		sd, _, err := sdElementFromDisclosure(content, nil)
		return sd, err

	}

	return marshalEmbedded(e.Key, e.Value, nil)
}

func (e *ClaimElement) encodeObject(mode encodeMode) (SerializedClaim, error) {
	result := map[string]any{}
	var sd []HashedDisclosure
	disclosures := []EncodedDisclosure{}

	for _, c := range e.SubClaims {
		subMode := encodeFullClaim
		subClaim, err := c.encode(subMode)
		if err != nil {
			return nil, fmt.Errorf("failed to encode: %w", err)
		}

		switch sc := subClaim.(type) {
		case *SdClaimElement:
			sd = append(sd, sc.Digest)
			disclosures = append(disclosures, sc.Disclosures...)
		case *EmbeddedClaimElement:
			result[sc.Key] = json.RawMessage(sc.Value)
			disclosures = append(disclosures, sc.Disclosures...)
		default:
			return nil, fmt.Errorf("unexpected claim type %T", subClaim)
		}
	}

	if len(sd) > 0 {
		result[SdKey] = sd
	}

	if e.SelectivelyDisclosable {
		d, err := NewDisclosureContent(e.Key, result)
		if err != nil {
			return nil, err
		}

		sdElem, all, err := sdElementFromDisclosure(d, disclosures)
		if err != nil {
			return nil, err
		}
		sdElem.Disclosures = all
		return sdElem, nil
	}

	// value-only callers with ignore key anyway
	return marshalEmbedded(e.Key, result, disclosures)
}

func (e *ClaimElement) encodeArray(mode encodeMode) (SerializedClaim, error) {
	result := []any{}
	var disclosures []EncodedDisclosure

	for _, c := range e.SubClaims {
		subClaim, err := c.encode(encodeValueOnly)
		if err != nil {
			return nil, fmt.Errorf("failed to encode: %w", err)
		}

		switch sc := subClaim.(type) {
		case *SdClaimElement:
			result = append(result, map[string]HashedDisclosure{"...": sc.Digest})
			disclosures = append(disclosures, sc.Disclosures...)
		case *EmbeddedClaimElement:
			result = append(result, json.RawMessage(sc.Value))
			disclosures = append(disclosures, sc.Disclosures...)
		default:
			return nil, fmt.Errorf("unexpected claim element type %T", subClaim)
		}
	}

	if e.SelectivelyDisclosable {
		d, err := NewDisclosureContent(e.Key, result)
		if err != nil {
			return nil, err
		}
		sdElem, all, err := sdElementFromDisclosure(d, disclosures)
		if err != nil {
			return nil, err
		}
		sdElem.Disclosures = all
		return sdElem, nil
	}

	return marshalEmbedded(e.Key, result, disclosures)
}

// Builder builds a plain SD-JWT (draft-ietf-oauth-selective-disclosure-jwt):
// it enforces only the SD-JWT-core rule that `_sd_alg`, when provided, is a
// supported hashing algorithm (defaulting to sha-256). It has no opinion on
// `vct`, `iss`, or the `typ` header — callers set those explicitly via
// WithTyp, or leave them out entirely.
type Builder struct {
	claims          []*ClaimElement
	issuerCertChain []string
	typ             string
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

func HolderKeyClaim(key jwk.Key) (*ClaimElement, error) {
	x := CnfField{
		Jwk: &key,
	}
	j, err := json.Marshal(x)
	if err != nil {
		return nil, err
	}
	var y map[string]any
	err = json.Unmarshal(j, &y)
	if err != nil {
		return nil, fmt.Errorf("trying to unmarshal %v, but got error: %w", j, err)
	}
	return JsonToClaimTree(ConfirmationKey, y)
}

func JsonToClaimTree(key string, json map[string]any) (*ClaimElement, error) {
	subClaims := []*ClaimElement{}
	for k, v := range json {
		var newClaim *ClaimElement
		switch value := v.(type) {
		case map[string]any:
			sub, err := JsonToClaimTree(k, value)
			if err != nil {
				return nil, err
			}
			newClaim = sub
		case int:
			newClaim = Claim(k, value)
		case string:
			newClaim = Claim(k, value)
		case bool:
			newClaim = Claim(k, value)
		default:
			return nil, fmt.Errorf("failed to create sub claim")
		}
		subClaims = append(subClaims, newClaim)
	}
	return Object(key, subClaims...), nil
}

func (b *Builder) WithPayload(claims ...*ClaimElement) *Builder {
	b.claims = claims
	return b
}

func (b *Builder) WithIssuerCertificateChain(certChain []string) *Builder {
	b.issuerCertChain = certChain
	return b
}

// WithTyp sets the JWT `typ` header. SD-JWT core has no opinion on its
// value; if unset, the header is omitted.
func (b *Builder) WithTyp(typ string) *Builder {
	b.typ = typ
	return b
}

func (b *Builder) Build(jwtCreator JwtCreator) (SdJwt, error) {
	var sdAlg iana.HashingAlgorithm
	for _, c := range b.claims {
		if c.Key == SdAlgKey {
			alg, ok := c.Value.(iana.HashingAlgorithm)
			if !ok {
				return "", fmt.Errorf("provided '%v' claim not a string: %v", SdAlgKey, c.Value)
			}
			sdAlg = alg
		}
	}

	rootNode := &ClaimElement{
		Type:                   Claim_Object,
		SubClaims:              b.claims,
		SelectivelyDisclosable: false,
	}

	// SD-JWT spec Section 4.1.1: default to sha-256 if _sd_alg is absent.
	if sdAlg == "" {
		sdAlg = iana.SHA256
	}
	if sdAlg != iana.SHA256 {
		return "", fmt.Errorf("'%s' value not supported: %v", SdAlgKey, sdAlg)
	}

	claims, err := rootNode.encode(encodeFullClaim)
	if err != nil {
		return "", fmt.Errorf("failed to encode root node: %w", err)
	}

	claimsJson, ok := claims.(*EmbeddedClaimElement)
	if !ok {
		return "", fmt.Errorf("root node is not of type EmbeddedClaimElement")
	}

	header := map[string]any{
		"x5c": b.issuerCertChain,
	}
	if b.typ != "" {
		header["typ"] = b.typ
	}

	result, err := jwtCreator.CreateSignedJwt(header, string(claimsJson.Value))

	if err != nil {
		return "", fmt.Errorf("failed to create issuer signed payload: %w", err)
	}

	return Create(IssuerSignedJwt(result), claimsJson.Disclosures), nil
}

func NewBuilder() *Builder {
	return &Builder{}
}
