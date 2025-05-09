package sdjwtvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/privacybydesign/irmago/eudi/utils"
)

type JwtVerifier interface {
	Verify(jwt string, key any) (payload []byte, err error)
}

type JwxJwtVerifier struct{}

func NewJwxJwtVerifier() *JwxJwtVerifier {
	return &JwxJwtVerifier{}
}

func (v *JwxJwtVerifier) Verify(jwt string, keyAny any) (payload []byte, err error) {
	keyJson, err := json.Marshal(keyAny)
	if err != nil {
		return []byte{}, err
	}
	key, err := jwk.ParseKey(keyJson)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to parse key (%v) from json: %v", keyAny, err)
	}

	return jws.Verify([]byte(jwt), jws.WithKey(jwa.ES256(), key))
}

type Clock interface {
	Now() int64
}

type SystemClock struct{}

func NewSystemClock() *SystemClock {
	return &SystemClock{}
}

func (c *SystemClock) Now() int64 {
	return time.Now().Unix()
}

type VerificationContext struct {
	IssuerMetadataFetcher IssuerMetadataFetcher
	Clock                 Clock
	JwtVerifier           JwtVerifier
}

// VerifiedSdJwtVc is the decoded representation of an SD-JWT VC for the verifier
type VerifiedSdJwtVc struct {
	IssuedSignedJwtPayload IssuerSignedJwtPayload
	Disclosures            []DisclosureContent
	KeyBindingJwt          *KeyBindingJwtPayload
}

func ParseAndVerifySdJwtVc(context VerificationContext, sdjwtvc SdJwtVc) (VerifiedSdJwtVc, error) {
	issuerSignedJwt, disclosures, keyBindingJwt, err := SplitSdJwtVc(sdjwtvc)
	if err != nil {
		return VerifiedSdJwtVc{}, err
	}

	issuerSignedJwtPayload, err := parseAndVerifyIssuerSignedJwt(context, issuerSignedJwt, disclosures)

	if err != nil {
		return VerifiedSdJwtVc{}, err
	}

	var kbJwtPayload *KeyBindingJwtPayload = nil
	if keyBindingJwt != nil {
		keyBindingJwtPayload, err := parseAndVerifyKeyBindingJwt(
			context,
			issuerSignedJwt,
			disclosures,
			issuerSignedJwtPayload,
			*keyBindingJwt,
		)
		if err != nil {
			return VerifiedSdJwtVc{}, err
		}
		kbJwtPayload = &keyBindingJwtPayload
	}

	decodedDisclosures, err := DecodeDisclosures(disclosures)

	if err != nil {
		return VerifiedSdJwtVc{}, fmt.Errorf("failed to decode disclosures: %v", err)
	}

	err = verifyTime(context, issuerSignedJwtPayload, kbJwtPayload)
	if err != nil {
		return VerifiedSdJwtVc{}, err
	}

	return VerifiedSdJwtVc{
		IssuedSignedJwtPayload: issuerSignedJwtPayload,
		KeyBindingJwt:          kbJwtPayload,
		Disclosures:            decodedDisclosures,
	}, nil
}

func verifyTime(context VerificationContext, issuerSignedJwtPayload IssuerSignedJwtPayload, kbjwtPayload *KeyBindingJwtPayload) error {
	now := context.Clock.Now()
	iat := issuerSignedJwtPayload.IssuedAt
	exp := issuerSignedJwtPayload.Expiry
	nbf := issuerSignedJwtPayload.NotBefore

	if nbf != 0 && now < nbf {
		return fmt.Errorf("verification before nbf: now: %v < nbf: %v", now, nbf)
	}

	if now < iat {
		return fmt.Errorf("verification before issued at: %v < %v", now, iat)
	}

	if exp != 0 && now > exp {
		return fmt.Errorf("verification after expiry of issuer signed jwt: %v > %v", now, exp)
	}

	if kbjwtPayload != nil {
		kbiat := kbjwtPayload.IssuedAt
		if now < kbiat {
			return fmt.Errorf("verification before issued at of kbjwt: %v < %v", now, iat)
		}
	}

	return nil
}

func parseAndVerifyKeyBindingJwt(
	context VerificationContext,
	issuerSignedJwt IssuerSignedJwt,
	disclosures []EncodedDisclosure,
	issuerSignedJwtPayload IssuerSignedJwtPayload,
	kbjwt KeyBindingJwt,
) (KeyBindingJwtPayload, error) {
	header, _, err := decodeJwtWithoutCheckingSignature(string(kbjwt))

	if err != nil {
		return KeyBindingJwtPayload{}, err
	}

	err = verifyKeyBindingJwtHeader(header)
	if err != nil {
		return KeyBindingJwtPayload{}, err
	}

	holderKey := issuerSignedJwtPayload.Confirm.Jwk
	payloadJson, err := context.JwtVerifier.Verify(string(kbjwt), holderKey)

	if err != nil {
		return KeyBindingJwtPayload{}, fmt.Errorf("invalid kbjwt signature: %v (holder key: %v)", err, holderKey)
	}

	var payload KeyBindingJwtPayload
	err = json.Unmarshal(payloadJson, &payload)
	if err != nil {
		return KeyBindingJwtPayload{}, err
	}

	sdJwtVcWithoutKbJwt := CreateSdJwtVc(issuerSignedJwt, disclosures)
	hash, err := CreateHash(issuerSignedJwtPayload.SdAlg, string(sdJwtVcWithoutKbJwt))
	if err != nil {
		return KeyBindingJwtPayload{}, err
	}

	if payload.IssuerSignedJwtHash != hash {
		return KeyBindingJwtPayload{}, fmt.Errorf("issuer signed jwt hash doesn't equal sd_hash found in kbjwt")
	}

	if payload.Nonce != "nonce" {
		return KeyBindingJwtPayload{},
			fmt.Errorf("kbjwt 'nonce' field was expected to contain 'nonce', but contained '%s' instead", payload.Nonce)
	}

	now := context.Clock.Now()

	if payload.IssuedAt >= now {
		return KeyBindingJwtPayload{}, fmt.Errorf("iat value (%v) was after current time (%v)", payload.IssuedAt, now)
	}

	return KeyBindingJwtPayload{}, nil
}

func parseSdField(value any) ([]HashedDisclosure, error) {
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
			return []HashedDisclosure{}, fmt.Errorf("failed to convert any to string (%v)", s)
		}
		result = append(result, HashedDisclosure(sStr))
	}
	return result, nil
}

func parseConfirmField(value any) (CnfField, error) {
	anyMap, ok := value.(map[string]any)
	if !ok {
		return CnfField{}, fmt.Errorf("failed to parse as anymap: %v", value)
	}
	key, ok := anyMap["jwk"]
	if !ok {
		return CnfField{}, fmt.Errorf("cnf map doesn't contain a `jwk` field (%v)", anyMap)
	}
	anyMap, ok = key.(map[string]any)
	if !ok {
		return CnfField{}, fmt.Errorf("jwk field doens't contain an any map: %v", key)
	}
	return CnfField{Jwk: anyMap}, nil
}

func parseAndVerifyIssuerSignedJwt(context VerificationContext, jwt IssuerSignedJwt, disclosures []EncodedDisclosure) (IssuerSignedJwtPayload, error) {
	header, claims, err := decodeJwtWithoutCheckingSignature(string(jwt))
	if err != nil {
		return IssuerSignedJwtPayload{}, err
	}

	err = verifyIssuerSignedJwtHeader(header)
	if err != nil {
		return IssuerSignedJwtPayload{}, err
	}

	sd, err := utils.ExtractOptionalWith(claims, Key_Sd, parseSdField)
	if err != nil {
		return IssuerSignedJwtPayload{}, err
	}

	vct, err := utils.ExtractRequired[string](claims, Key_VerifiableCredentialType)
	if err != nil {
		return IssuerSignedJwtPayload{}, err
	}

	confirm, err := utils.ExtractOptionalWith(claims, Key_Confirmationkey, parseConfirmField)
	if err != nil {
		return IssuerSignedJwtPayload{}, fmt.Errorf("failed to parse %s field: %v", Key_Confirmationkey, err)
	}

	status := utils.ExtractOptional[string](claims, Key_Status)
	subject := utils.ExtractOptional[string](claims, Key_Subject)
	expiry := int64(utils.ExtractOptional[float64](claims, Key_ExpiryTime))
	issuedAt := int64(utils.ExtractOptional[float64](claims, Key_IssuedAt))
	issuer := utils.ExtractOptional[string](claims, Key_Issuer)
	sdAlg := utils.ExtractOptional[string](claims, Key_SdAlg)
	notBefore := int64(utils.ExtractOptional[float64](claims, Key_NotBefore))

	payload := IssuerSignedJwtPayload{
		Subject:                  subject,
		VerifiableCredentialType: vct,
		Expiry:                   expiry,
		IssuedAt:                 issuedAt,
		Issuer:                   issuer,
		Sd:                       sd,
		SdAlg:                    HashingAlgorithm(sdAlg),
		Confirm:                  confirm,
		Status:                   status,
		NotBefore:                notBefore,
	}

	if issuer != "" {
		if !strings.HasPrefix(issuer, "https://") {
			return IssuerSignedJwtPayload{}, fmt.Errorf("iss field should be https if it's included but is now %s", issuer)
		}
		err = verifyIssuerSignature(context, jwt, payload.Issuer)
		if err != nil {
			return IssuerSignedJwtPayload{}, err
		}
	}

	err = verifyPayloadContainsAllDisclosureHashes(payload, disclosures)
	if err != nil {
		return IssuerSignedJwtPayload{}, err
	}

	return payload, nil
}

func verifyPayloadContainsAllDisclosureHashes(payload IssuerSignedJwtPayload, disclosures []EncodedDisclosure) error {
	for _, disc := range disclosures {
		hash, err := HashEncodedDisclosure(payload.SdAlg, disc)

		if err != nil {
			return fmt.Errorf("failed to hash disclosure: %v", err)
		}

		if !Contains(payload.Sd, hash) {
			return fmt.Errorf("sd field doesn't contain %s (for %s)", hash, disc)
		}
	}
	return nil
}

func Contains[T comparable](slice []T, value T) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

func verifyIssuerSignature(context VerificationContext, issuerJwt IssuerSignedJwt, issuerUrl string) error {
	metadata, err := context.IssuerMetadataFetcher.FetchIssuerMetadata(issuerUrl)

	if err != nil {
		return err
	}

	if metadata.Issuer != issuerUrl {
		return fmt.Errorf("issuer url doens't match the one found in issuer metadata: jwt: %s != metadata: %s", issuerUrl, metadata.Issuer)
	}

	for _, key := range metadata.Jwks {
		_, err := context.JwtVerifier.Verify(string(issuerJwt), key)

		// no err, so valid signature
		if err == nil {
			return nil
		}
	}
	return errors.New("no valid issuer signature")
}

func verifyKeyBindingJwtHeader(header map[string]any) error {
	if typ := header["typ"]; typ != KbJwtTyp {
		return fmt.Errorf("key binding jwt header is expected to have 'typ' of '%s', but has %s (header: %v)", KbJwtTyp, typ, header)
	}
	return nil
}

func verifyIssuerSignedJwtHeader(header map[string]any) error {
	typ := header["typ"]
	if typ != SdJwtVcTyp && typ != SdJwtVcTyp_Legacy {
		return fmt.Errorf("issuer signed jwt header should have 'typ' of either %s or %s, but has %s", SdJwtVcTyp, SdJwtVcTyp_Legacy, typ)
	}
	return nil
}

type IssuerMetadata struct {
	// The issuer identifier, MUST be identical to the `iss` field in the issuer signed jwt
	Issuer string

	// Jwks pub keys of the issuer
	Jwks []any
}

type IssuerMetadataFetcher interface {
	FetchIssuerMetadata(url string) (IssuerMetadata, error)
}

type HttpIssuerMetadataFetcher struct{}

func NewHttpIssuerMetadataFetcher() *HttpIssuerMetadataFetcher {
	return &HttpIssuerMetadataFetcher{}
}

func (f *HttpIssuerMetadataFetcher) FetchIssuerMetadata(url string) (IssuerMetadata, error) {
	if !strings.HasPrefix(url, "https://") {
		return IssuerMetadata{}, fmt.Errorf("issuer url needs to be https (%s)", url)
	}
	urlWithWellknown := fmt.Sprintf("%s/.well-known/jwt-vc-issuer", url)
	response, err := http.Get(urlWithWellknown)

	if err != nil {
		return IssuerMetadata{}, err
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)

	if err != nil {
		return IssuerMetadata{}, err
	}

	type specIssuerMetadata struct {
		Issuer  string         `json:"issuer"`
		Jwks    map[string]any `json:"jwks,omitempty"`
		JwksUri string         `json:"jwks_uri,omitempty"`
	}
	var result specIssuerMetadata
	err = json.Unmarshal(body, &result)

	if err != nil {
		return IssuerMetadata{}, err
	}

	jwks, ok := result.Jwks["keys"].([]any)
	if !ok {
		return IssuerMetadata{}, fmt.Errorf("jwks key is required, but not found in %v", result)
	}

	return IssuerMetadata{
		Issuer: result.Issuer,
		Jwks:   jwks,
	}, nil
}

// Splits the sdjwt at the ~ characters and returns the individual components.
// The IssuerSignedJwt is guaranteed to contain a value (if there's no error).
// The EncodedDisclosure list could be empty if there are no dislcosures.
// The KbJwt may be nil if there's no key binding jwt.
func SplitSdJwtVc(sdjwtvc SdJwtVc) (IssuerSignedJwt, []EncodedDisclosure, *KeyBindingJwt, error) {
	components := strings.Split(string(sdjwtvc), "~")
	numComponents := len(components)
	if numComponents == 0 {
		return err("invalid sdjwtvc: %s", sdjwtvc)
	}

	// if it doesn't end with a ~, there must be a kbjwt
	hasKbJwt := !strings.HasSuffix(string(sdjwtvc), "~")

	encDiscEndIndex := len(components)
	var kbJwt *KeyBindingJwt = nil

	if hasKbJwt {
		if numComponents < 2 {
			return err("sdjwtvc expected to have kbjwt (since it doesn't end with ~), but has no kbjwt")
		}

		tmp := KeyBindingJwt(components[numComponents-1])
		kbJwt = &tmp
		encDiscEndIndex = len(components) - 1
	}

	issuer := IssuerSignedJwt(components[0])

	encdiscs := []EncodedDisclosure{}
	for _, d := range components[1:encDiscEndIndex] {
		if d != "" {
			encdiscs = append(encdiscs, EncodedDisclosure(d))
		}
	}

	return issuer, encdiscs, kbJwt, nil
}

func err(message string, args ...any) (IssuerSignedJwt, []EncodedDisclosure, *KeyBindingJwt, error) {
	return "", []EncodedDisclosure{}, nil, fmt.Errorf(message, args...)
}

func decodeJwtWithoutCheckingSignature(jwtString string) (header map[string]any, claims map[string]any, err error) {
	parser := jwt.NewParser()
	var claimsResult jwt.MapClaims
	token, _, err := parser.ParseUnverified(jwtString, &claimsResult)
	return token.Header, claimsResult, err
}
