package sdjwtvc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	jwtOld "github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/utils"
)

const ClockSkewInSeconds = 180

// SdJwtVcVerificationContext contains some options and configuration for verifying SD-JWT VCs.
type SdJwtVcVerificationContext struct {
	eudi_jwt.VerificationContext

	// Used to obtain the current time in order to verify things like
	// the `iat` and `nbf` fields.
	Clock jwt.Clock

	// Used to verify both JWT components of an SD-JWT VC (issuer signed jwt and kbjwt).
	JwtVerifier JwtVerifier

	// Whether the `iss` field should be allowed to contain non-https link.
	// According to the spec this is never allowed, but for testing purposes it can come in handy.
	AllowNonHttpsIssuer bool
}

// VerifiedSdJwtVc is the decoded & verified representation of an SD-JWT VC.
// You should only obtain one by calling `ParseAndVerifySdJwtVc()` and not make one yourself.
type VerifiedSdJwtVc struct {
	IssuerSignedJwtPayload IssuerSignedJwtPayload
	Disclosures            []DisclosureContent
	KeyBindingJwt          *KeyBindingJwtPayload
}

func CreateDefaultVerificationContext(trustedChain []byte) SdJwtVcVerificationContext {
	opts, err := utils.CreateX509VerifyOptionsFromCertChain(trustedChain)
	if err != nil {
		panic(fmt.Errorf("failed to create X509 verification options: %v", err))
	}
	return SdJwtVcVerificationContext{
		VerificationContext: eudi_jwt.VerificationContext{
			X509VerificationOptionsTemplate: *opts,
		},
		Clock:       NewSystemClock(),
		JwtVerifier: NewJwxJwtVerifier(),
	}
}

// ParseAndVerifySdJwtVc is used to verify an SD-JWT VC using the verification options passed via the context parameter.
func ParseAndVerifySdJwtVc(context SdJwtVcVerificationContext, sdjwtvc SdJwtVc) (VerifiedSdJwtVc, error) {
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

type SystemClock struct{}

func NewSystemClock() jwt.Clock {
	return &SystemClock{}
}

func (c *SystemClock) Now() time.Time {
	return time.Now()
}

type StaticClock struct {
	CurrentTime int64
}

func (c *StaticClock) Now() time.Time {
	return time.Unix(c.CurrentTime, 0)
}

// ========================================================================

func verifyTime(context SdJwtVcVerificationContext, issuerSignedJwtPayload IssuerSignedJwtPayload, kbjwtPayload *KeyBindingJwtPayload) error {
	now := context.Clock.Now().Unix()
	minSkewNow := now - ClockSkewInSeconds
	maxSkewNow := now + ClockSkewInSeconds

	iat := issuerSignedJwtPayload.IssuedAt
	exp := issuerSignedJwtPayload.Expiry
	nbf := issuerSignedJwtPayload.NotBefore

	if nbf != 0 && maxSkewNow < nbf {
		return fmt.Errorf("verification before nbf: now: %v + skew: %v < nbf: %v", now, ClockSkewInSeconds, nbf)
	}

	if maxSkewNow < iat {
		return fmt.Errorf("verification before issued at: %v + skew: %v < %v", now, ClockSkewInSeconds, iat)
	}

	if exp != 0 && minSkewNow > exp {
		return fmt.Errorf("verification after expiry of issuer signed jwt: %v - skew: %v > %v", now, ClockSkewInSeconds, exp)
	}

	if kbjwtPayload != nil {
		kbiat := kbjwtPayload.IssuedAt
		if maxSkewNow < kbiat {
			return fmt.Errorf("verification before issued at of kbjwt: %v + skew %v < %v", now, ClockSkewInSeconds, kbiat)
		}
	}

	return nil
}

func parseAndVerifyKeyBindingJwt(
	context SdJwtVcVerificationContext,
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
	maxSkewNow := now.Unix() + ClockSkewInSeconds

	if payload.IssuedAt >= maxSkewNow {
		return KeyBindingJwtPayload{}, fmt.Errorf("kbjwt iat value (%v) was after current time (%v)", payload.IssuedAt, now)
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

func parseAndVerifyIssuerSignedJwt(context SdJwtVcVerificationContext, signedJwt IssuerSignedJwt, disclosures []EncodedDisclosure) (IssuerSignedJwtPayload, error) {
	token, cert, err := decodeJwt([]byte(signedJwt), context)
	if err != nil {
		return IssuerSignedJwtPayload{}, err
	}

	// Get required fields
	iss, issPresent := token.Issuer()
	if !issPresent {
		return IssuerSignedJwtPayload{}, errors.New("missing iss field")
	}

	// Use the `iss` claim to verify the issuer signed JWT
	err = context.VerificationContext.VerifyCertificate(cert, nil, &iss)
	if err != nil {
		return IssuerSignedJwtPayload{}, fmt.Errorf("failed to verify certificate: %v", err)
	}

	var vct string
	err = token.Get(Key_VerifiableCredentialType, &vct)
	if err != nil {
		return IssuerSignedJwtPayload{}, errors.New("missing vct field")
	}

	// Get optional fields
	sub, _ := token.Subject()
	exp, _ := token.Expiration()
	iat, _ := token.IssuedAt()
	nbf, _ := token.NotBefore()

	sdAlg := utils.GetOptional[string](token, Key_SdAlg)
	status := utils.GetOptional[string](token, Key_Status)

	var sdRaw, cnfRaw any

	var sd []HashedDisclosure
	err = token.Get(Key_Sd, &sdRaw)
	if err == nil {
		sd, err = parseSdField(sdRaw)
		if err != nil {
			return IssuerSignedJwtPayload{}, fmt.Errorf("failed to parse sd field: %v", err)
		}
	}

	var cnf CnfField
	err = token.Get(Key_Confirmationkey, &cnfRaw)
	if err == nil {
		cnf, err = parseConfirmField(cnfRaw)
		if err != nil {
			return IssuerSignedJwtPayload{}, fmt.Errorf("failed to parse cnf field: %v", err)
		}
	}

	// Apply custom verifications
	if issPresent && !strings.HasPrefix(iss, "https://") && !context.AllowNonHttpsIssuer {
		return IssuerSignedJwtPayload{}, fmt.Errorf("iss field should be https if it's included but is now %s", iss)
	}

	// TODO: create Yivi Issuer Requestor from cert data
	if cert == nil {
		return IssuerSignedJwtPayload{}, errors.New("missing x509 certificate")
	}

	// Construct payload
	payload := IssuerSignedJwtPayload{
		Subject:                  sub,
		Expiry:                   exp.Unix(),
		IssuedAt:                 iat.Unix(),
		NotBefore:                nbf.Unix(),
		Issuer:                   iss,
		VerifiableCredentialType: vct,
		Sd:                       sd,
		SdAlg:                    HashingAlgorithm(sdAlg),
		Confirm:                  cnf,
		Status:                   status,
	}

	// Verify disclosures
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

func verifyKeyBindingJwtHeader(header map[string]any) error {
	if typ := header["typ"]; typ != KbJwtTyp {
		return fmt.Errorf("key binding jwt header is expected to have 'typ' of '%s', but has %s (header: %v)", KbJwtTyp, typ, header)
	}
	return nil
}

func err(message string, args ...any) (IssuerSignedJwt, []EncodedDisclosure, *KeyBindingJwt, error) {
	return "", []EncodedDisclosure{}, nil, fmt.Errorf(message, args...)
}

func decodeJwtWithoutCheckingSignature(jwtString string) (header map[string]any, claims map[string]any, err error) {
	parser := jwtOld.NewParser()
	var claimsResult jwtOld.MapClaims
	token, _, err := parser.ParseUnverified(jwtString, &claimsResult)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT: %v", err)
	}
	return token.Header, claimsResult, err
}

// TODO: export cert data for Yivi Requestor
// Note: if found, the decodeJwt returns the certificate with which the JWTs signature can be validated.
// The cert itself however is NOT yet verified (against CRLs and other checks).
func decodeJwt(signedJwt []byte, verificationContext SdJwtVcVerificationContext) (jwt.Token, *x509.Certificate, error) {
	keyProvider := &SdJwtKeyProvider{
		X509KeyProvider: eudi_jwt.X509KeyProvider{},
	}

	// Create a context for the JWS verification where we can retrieve the requestor info back
	token, err := jwt.Parse(signedJwt,
		jwt.WithKeyProvider(keyProvider),
		jwt.WithClock(verificationContext.Clock),
		jwt.WithAcceptableSkew(ClockSkewInSeconds*time.Second),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT: %v", err)
	}

	return token, keyProvider.X509KeyProvider.GetCert(), nil
}

type SdJwtKeyProvider struct {
	eudi_jwt.X509KeyProvider
}

func (p *SdJwtKeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	// Validate 'typ' header first
	if typ, ok := sig.ProtectedHeaders().Type(); !ok || !slices.Contains([]string{SdJwtVcTyp, SdJwtVcTyp_Legacy}, typ) {
		return fmt.Errorf("invalid 'typ' header: %v", typ)
	}

	return p.X509KeyProvider.FetchKeys(ctx, sink, sig, msg)
}
