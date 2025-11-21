package sdjwtvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	jwtOld "github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/scheme"
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
}

// VerifiedSdJwtVc is the decoded & verified representation of an SD-JWT VC.
// You should only obtain one by calling `ParseAndVerifySdJwtVc()` and not make one yourself.
type VerifiedSdJwtVc struct {
	IssuerSignedJwtPayload IssuerSignedJwtPayload
	Disclosures            []DisclosureContent
	KeyBindingJwt          *KeyBindingJwtPayload
}

type ProcessedSdJwtPayload map[string]any

func CreateDefaultVerificationContext(trustedChain []byte) SdJwtVcVerificationContext {
	opts, err := utils.CreateX509VerifyOptionsFromCertChain(trustedChain)
	if err != nil {
		panic(fmt.Errorf("failed to create X509 verification options: %v", err))
	}
	return SdJwtVcVerificationContext{
		VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: *opts,
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

	issuerSignedJwtPayload, requestorInfo, decodedDisclosures, err := parseAndVerifyIssuerSignedJwt(context, issuerSignedJwt, disclosures)

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

	err = verifyTime(context, issuerSignedJwtPayload, kbJwtPayload)
	if err != nil {
		return VerifiedSdJwtVc{}, err
	}

	// Verify the credential is allowed to be issued by the requestor
	disclosureKeys := slices.Collect(DisclosureContents(decodedDisclosures).Keys())
	err = requestorInfo.AttestationProvider.VerifySdJwtIssuance(issuerSignedJwtPayload.VerifiableCredentialType, disclosureKeys)
	if err != nil {
		return VerifiedSdJwtVc{}, fmt.Errorf("failed to verify SD-JWT issuance: %v", err)
	}

	// Valid SD-JWT
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
			return []HashedDisclosure{}, fmt.Errorf("failed to convert value in _sd array to string (%v)", s)
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

func parseAndVerifyIssuerSignedJwt(context SdJwtVcVerificationContext, signedJwt IssuerSignedJwt, disclosures []EncodedDisclosure) (
	IssuerSignedJwtPayload,
	*scheme.AttestationProviderRequestor,
	[]DisclosureContent,
	error,
) {
	token, requestorInfo, err := decodeJwtAndVerifyFromX5cHeader([]byte(signedJwt), context)
	if err != nil {
		return IssuerSignedJwtPayload{}, nil, nil, err
	}

	var vct string
	err = token.Get(Key_VerifiableCredentialType, &vct)
	if err != nil {
		return IssuerSignedJwtPayload{}, nil, nil, errors.New("missing vct field")
	}

	// Get optional fields
	sub, _ := token.Subject()
	exp, _ := token.Expiration()
	iat, _ := token.IssuedAt()
	nbf, _ := token.NotBefore()
	iss, _ := token.Issuer()

	sdAlg := utils.GetOptional[string](token, Key_SdAlg)
	status := utils.GetOptional[string](token, Key_Status)

	var sdRaw, cnfRaw any

	var sd []HashedDisclosure
	err = token.Get(Key_Sd, &sdRaw)
	if err == nil {
		sd, err = parseSdField(sdRaw)
		if err != nil {
			return IssuerSignedJwtPayload{}, nil, nil, fmt.Errorf("failed to parse sd field: %v", err)
		}
	}

	var cnf CnfField
	err = token.Get(Key_Confirmationkey, &cnfRaw)
	if err == nil {
		cnf, err = parseConfirmField(cnfRaw)
		if err != nil {
			return IssuerSignedJwtPayload{}, nil, nil, fmt.Errorf("failed to parse cnf field: %v", err)
		}
	}

	// Verify and process disclosures
	// Get structured SD-JWT claims, which we can check for embedded disclosure digests
	issuerSignedJwtClaims, err := extractClaimsAndDisclosuresDigestsFromToken(token)
	if err != nil {
		return IssuerSignedJwtPayload{}, nil, nil, fmt.Errorf("failed to extract claims from token: %v", err)
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

	// Parse and verify disclosures
	// TODO: store ProcessedSdJwtPayload somewhere if needed
	_, decodedDisclosures, err := verifyAndProcessDisclosures(payload.SdAlg, &issuerSignedJwtClaims, disclosures)
	if err != nil {
		return IssuerSignedJwtPayload{}, nil, nil, err
	}

	return payload, requestorInfo, decodedDisclosures, nil
}

func extractClaimsAndDisclosuresDigestsFromToken(token jwt.Token) (map[string]any, error) {
	defaultSdJwtClaims := []string{
		jwt.SubjectKey,
		jwt.ExpirationKey,
		jwt.IssuedAtKey,
		jwt.NotBeforeKey,
		jwt.IssuerKey,
		Key_VerifiableCredentialType,
		Key_SdAlg,
		Key_Confirmationkey,
		Key_Status,
	}
	issuerSignedJwtClaims := map[string]any{}
	for _, key := range token.Keys() {
		if slices.Contains(defaultSdJwtClaims, key) {
			continue
		}

		var value any
		if err := token.Get(key, &value); err != nil {
			return nil, fmt.Errorf("failed to get extra claim %s: %v", key, err)
		}

		issuerSignedJwtClaims[key] = value
	}
	return issuerSignedJwtClaims, nil
}

func verifyAndProcessDisclosures(sdAlg HashingAlgorithm,
	issuerSignedJwtClaims *map[string]any,
	disclosures []EncodedDisclosure,
) (ProcessedSdJwtPayload, []DisclosureContent, error) {
	// Step 1: decode all disclosures and calculate their digests
	decodedDisclosures := make(map[HashedDisclosure]DisclosureContent, len(disclosures))
	for _, disc := range disclosures {
		decodedDisclosure, err := DecodeDisclosure(disc)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode disclosure: %v", err)
		}

		digest, err := HashEncodedDisclosure(sdAlg, disc)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to hash disclosure: %v", err)
		}

		decodedDisclosures[digest] = decodedDisclosure
	}

	// Step 2: Identify all embedded digests in the Issuer-Signed JWT recursively and replace them with the actual disclosure values
	err := processEmbeddedDisclosures(issuerSignedJwtClaims, decodedDisclosures)
	if err != nil {
		return nil, nil, err
	}

	if issuerSignedJwtClaims == nil {
		issuerSignedJwtClaims = &map[string]any{}
	}

	return ProcessedSdJwtPayload(*issuerSignedJwtClaims), slices.Collect(maps.Values(decodedDisclosures)), nil
}

func processEmbeddedDisclosures(claims *map[string]any, decodedDisclosures map[HashedDisclosure]DisclosureContent) error {
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
				// Check if the value is a disclosure (format should be {"...":"<digest>"}) or not, and if so, verify the array element disclosure exists
				if valMap, ok := arrayElemValue.(map[string]any); ok {
					if arrayElemDisclosureDigestVal, ok := valMap[Key_Ellipsis]; ok {
						// It's an embedded disclosure digest...
						arrayElemDisclosureDigestStr, ok := arrayElemDisclosureDigestVal.(string)
						if !ok {
							return fmt.Errorf("array element, which should be an embedded disclosure digest, is not a valid digest: %v", arrayElemDisclosureDigestStr)
						}

						disclosureDigest := HashedDisclosure(arrayElemDisclosureDigestStr)
						if embeddedDisclosure, ok := decodedDisclosures[disclosureDigest]; ok {
							// Check for array element validity (i.e. should be in format ["...": "<digest>"])
							if !embeddedDisclosure.isArrayElement {
								return fmt.Errorf("embedded disclosure %s is expected to be an array element, but is not", embeddedDisclosure.Key)
							}
							// Otherwise, replace the array element with the actual value from the disclosure
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

func processSdClaim(claims *map[string]any, decodedDisclosures map[HashedDisclosure]DisclosureContent) error {
	// Only process if there are any claims
	if claims == nil {
		return nil
	}

	// Check if there's an _sd field at this level
	sdValue, ok := (*claims)[Key_Sd]
	if !ok {
		return nil
	}

	// Found disclosure digests at this level.. replace with disclosure values
	sdDigests, err := parseSdField(sdValue)
	if err != nil {
		return fmt.Errorf("failed to parse digests for claim %q: %v", Key_Sd, err)
	}

	for _, sdDigest := range sdDigests {
		// Disclosure cannot be found for digest; ignore the digest
		if embeddedDisclosure, ok := decodedDisclosures[sdDigest]; ok {
			if embeddedDisclosure.isArrayElement {
				return fmt.Errorf("embedded disclosure %s appears to be an array element, which is not expected here", embeddedDisclosure.Key)
			}
			if embeddedDisclosure.Key == Key_Sd {
				return fmt.Errorf("embedded disclosure %s has an `_sd` field, which is not allowed", embeddedDisclosure.Key)
			}
			if embeddedDisclosure.Key == Key_Ellipsis {
				return fmt.Errorf("embedded disclosure %s has an `...` field, which is not allowed", embeddedDisclosure.Key)
			}
			if _, ok := (*claims)[embeddedDisclosure.Key]; ok {
				return fmt.Errorf("embedded disclosure key %q already exists at this level", embeddedDisclosure.Key)
			}

			(*claims)[embeddedDisclosure.Key] = embeddedDisclosure.Value
		}
	}

	// Delete the _sd field after processing
	delete(*claims, Key_Sd)

	return nil
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

// Decode the JWT into a token, verify the signature with the X.509 certificate in the header and verify the certificate is trusted (both against root/intermediate certs and CRLs).
// Function returns the token and the requestor info from the certificate.
func decodeJwtAndVerifyFromX5cHeader(signedJwt []byte, verificationContext SdJwtVcVerificationContext) (jwt.Token, *scheme.AttestationProviderRequestor, error) {
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

	// Get requestor info from cert
	cert := keyProvider.X509KeyProvider.GetCert()
	err = eudi_jwt.VerifyCertificate(verificationContext.VerificationContext, cert, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify certificate: %v", err)
	}

	// Verify the SD-JWT against the credentials the issuer is authorized to issue
	requestorInfo, err := utils.GetRequestorInfoFromCertificate[scheme.AttestationProviderRequestor](cert)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get requestor info from certificate: %v", err)
	}

	return token, requestorInfo, nil
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
