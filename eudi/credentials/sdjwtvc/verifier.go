package sdjwtvc

import (
	"crypto/x509"
	"encoding/base64"
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

// VerificationContext contains some options and configuration for verifying SD-JWT VCs.
type VerificationContext struct {
	// Used to fetch the issuer metadata found at the `iss` field.
	// If this field is set to nil, it will skip verification using the metadata.
	IssuerMetadataFetcher IssuerMetadataFetcher

	// Used to obtain the current time in order to verify things like
	// the `iat` and `nbf` fields.
	Clock Clock

	// Used to verify both JWT components of an SD-JWT VC (issuer signed jwt and kbjwt).
	JwtVerifier JwtVerifier

	// Whether the `iss` field should be allowed to contain non-https link.
	// According to the spec this is never allowed, but for testing purposes it can come in handy.
	AllowNonHttpsIssuer bool

	// All trusted certificates and settings for verifying the `x5c` header field of the
	// issuer signed jwt when when provided.
	// When this field is nil it will ignore the `x5c` field in the jwt.
	X509VerificationOptions *x509.VerifyOptions
}

// VerifiedSdJwtVc is the decoded & verified representation of an SD-JWT VC.
// You should only obtain one by calling `ParseAndVerifySdJwtVc()` and not make one yourself.
type VerifiedSdJwtVc struct {
	IssuerSignedJwtPayload IssuerSignedJwtPayload
	Disclosures            []DisclosureContent
	KeyBindingJwt          *KeyBindingJwtPayload
}

func CreateDefaultVerificationContext() VerificationContext {
	return VerificationContext{
		IssuerMetadataFetcher: NewHttpIssuerMetadataFetcher(),
		Clock:                 NewSystemClock(),
		JwtVerifier:           NewJwxJwtVerifier(),
	}
}

// ParseAndVerifySdJwtVc is used to verify an SD-JWT VC using the verification options passed via
// the context parameter.
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
		IssuerSignedJwtPayload: issuerSignedJwtPayload,
		KeyBindingJwt:          kbJwtPayload,
		Disclosures:            decodedDisclosures,
	}, nil
}

// SplitSdJwtVc splits the sdjwt at the ~ characters and returns the individual components.
// The IssuerSignedJwt is guaranteed to contain a value (if there's no error).
// The EncodedDisclosure list could be empty if there are no dislcosures.
// The KbJwt may be nil if there's no key binding jwt.
// This function will do no verification whatsoever.
func SplitSdJwtVc(sdjwtvc SdJwtVc) (IssuerSignedJwt, []EncodedDisclosure, *KeyBindingJwt, error) {
	if sdjwtvc == "" {
		return err("sdjwtvc is an empty string")
	}
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
			return err("sdjwtvc expected to have kbjwt (since it doesn't end with ~), but has no kbjwt ('%v')", sdjwtvc)
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

// CreateX509VerifyOptionsFromCertChain creates x509.VerifyOptions that can be added
// to the `VerificationContext` as the trusted certificate chain.
func CreateX509VerifyOptionsFromCertChain(pemChainData []byte) (*x509.VerifyOptions, error) {
	certs, err := ParsePemCertificateChain(pemChainData)
	if err != nil {
		return nil, err
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(certs[0])

	intermediatePool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediatePool.AddCert(cert)
	}

	certVerifyOpts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	return &certVerifyOpts, nil
}

// ========================================================================

type JwtVerifier interface {
	Verify(jwt string, key any) (payload []byte, err error)
}

type JwxJwtVerifier struct{}

func NewJwxJwtVerifier() *JwxJwtVerifier {
	return &JwxJwtVerifier{}
}

func (v *JwxJwtVerifier) Verify(jwt string, keyAny any) (payload []byte, err error) {
	return jws.Verify([]byte(jwt), jws.WithKey(jwa.ES256(), keyAny))
}

// ========================================================================

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

type StaticClock struct {
	CurrentTime int64
}

func (c *StaticClock) Now() int64 {
	return c.CurrentTime
}

// ========================================================================

type IssuerMetadataFetcher interface {
	FetchIssuerMetadata(url string) (IssuerMetadata, error)
}

type HttpIssuerMetadataFetcher struct{}

func NewHttpIssuerMetadataFetcher() *HttpIssuerMetadataFetcher {
	return &HttpIssuerMetadataFetcher{}
}

func (f *HttpIssuerMetadataFetcher) FetchIssuerMetadata(url string) (IssuerMetadata, error) {
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
		Issuer  string          `json:"issuer"`
		Jwks    json.RawMessage `json:"jwks,omitempty"`
		JwksUri string          `json:"jwks_uri,omitempty"`
	}
	var result specIssuerMetadata
	err = json.Unmarshal(body, &result)

	if err != nil {
		return IssuerMetadata{}, err
	}

	jwks, err := jwk.Parse(result.Jwks)
	if err != nil {
		return IssuerMetadata{}, err
	}

	return IssuerMetadata{
		Issuer: result.Issuer,
		Jwks:   jwks,
	}, nil
}

// ========================================================================

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
	keyAny, ok := anyMap["jwk"]
	if !ok {
		return CnfField{}, errors.New("failed to get jwk field from cnf field")
	}
	keyJson, err := json.Marshal(keyAny)
	if err != nil {
		return CnfField{}, err
	}
	key, err := jwk.ParseKey(keyJson)
	if err != nil {
		return CnfField{}, fmt.Errorf("failed to parse key (%v) from json: %v", value, err)
	}
	return CnfField{Jwk: key}, nil
}

func parseAndVerifyIssuerSignedJwt(context VerificationContext, jwt IssuerSignedJwt, disclosures []EncodedDisclosure) (IssuerSignedJwtPayload, error) {
	header, claims, err := decodeJwtWithoutCheckingSignature(string(jwt))
	if err != nil {
		return IssuerSignedJwtPayload{}, err
	}

	err = verifyIssuerSignedJwtTyp(header)
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

	issuer, err := utils.ExtractRequired[string](claims, Key_Issuer)
	if err != nil {
		return IssuerSignedJwtPayload{}, fmt.Errorf("failed to parse %s field: %v", Key_Issuer, err)
	}

	status := utils.ExtractOptional[string](claims, Key_Status)
	subject := utils.ExtractOptional[string](claims, Key_Subject)
	expiry := int64(utils.ExtractOptional[float64](claims, Key_ExpiryTime))
	issuedAt := int64(utils.ExtractOptional[float64](claims, Key_IssuedAt))
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

	if !strings.HasPrefix(issuer, "https://") && !context.AllowNonHttpsIssuer {
		return IssuerSignedJwtPayload{}, fmt.Errorf("iss field should be https if it's included but is now %s", issuer)
	}

	if x509Chain, ok := header[Key_X5c]; ok && context.X509VerificationOptions != nil {
		err = verifyIssuerSignatureUsingX509Chain(context, x509Chain, jwt, payload.Issuer)
	}
	if context.IssuerMetadataFetcher != nil {
		err = verifyIssuerSignatureUsingMetadata(context, jwt, payload.Issuer)
	}
	if err != nil {
		return IssuerSignedJwtPayload{}, err
	}

	err = verifyPayloadContainsAllDisclosureHashes(payload, disclosures)
	if err != nil {
		return IssuerSignedJwtPayload{}, err
	}

	return payload, nil
}

func verifyIssuerSignatureUsingX509Chain(context VerificationContext, x509Chain any, jwt IssuerSignedJwt, issuerUrl string) error {
	certs, ok := x509Chain.([]any)
	if !ok {
		return fmt.Errorf("failed to convert '%s' to []any (%v)", Key_X5c, x509Chain)
	}

	if len(certs) == 0 {
		return fmt.Errorf("'%s' is not expected to be empty, but is", Key_X5c)
	}

	endEntityString, ok := certs[0].(string)
	if !ok {
		return fmt.Errorf("failed to convert end-entity to string: %v", certs[0])
	}

	der, err := base64.StdEncoding.DecodeString(endEntityString)
	if err != nil {
		return fmt.Errorf("failed to decode end-entity base64 encoded der: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}

	_, err = parsedCert.Verify(*context.X509VerificationOptions)
	if err != nil {
		return fmt.Errorf("failed to verify x5c end-entity certificate against trusted chains")
	}

	hostNameFound := false
	hostNamesCert := []string{}

	for _, uri := range parsedCert.URIs {
		hostNamesCert = append(hostNamesCert, uri.String())
		if uri.String() == issuerUrl {
			hostNameFound = true
		}
	}

	if !hostNameFound {
		return fmt.Errorf("host name from '%s' (%s) not found in the certificate (%v)", Key_Issuer, issuerUrl, hostNamesCert)
	}

	_, err = context.JwtVerifier.Verify(string(jwt), parsedCert.PublicKey)
	return err
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

func verifyIssuerSignatureUsingMetadata(context VerificationContext, issuerJwt IssuerSignedJwt, issuerUrl string) error {
	metadata, err := context.IssuerMetadataFetcher.FetchIssuerMetadata(issuerUrl)

	if err != nil {
		return err
	}

	if metadata.Issuer != issuerUrl {
		return fmt.Errorf("issuer url doens't match the one found in issuer metadata: jwt: %s != metadata: %s", issuerUrl, metadata.Issuer)
	}

	numKeys := metadata.Jwks.Len()
	if numKeys == 0 {
		return fmt.Errorf("metadata doesn't contain any keys")
	}

	for i := range numKeys {
		key, ok := metadata.Jwks.Key(i)
		if !ok {
			continue
		}
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

func verifyIssuerSignedJwtTyp(header map[string]any) error {
	typ := header["typ"]
	if typ != SdJwtVcTyp && typ != SdJwtVcTyp_Legacy {
		return fmt.Errorf("issuer signed jwt header should have 'typ' of either %s or %s, but has %s", SdJwtVcTyp, SdJwtVcTyp_Legacy, typ)
	}
	return nil
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
