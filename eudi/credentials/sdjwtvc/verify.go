package sdjwtvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	jwtOld "github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

// ============================ SD-JWT VC processing descriptions =====================================

const ClockSkewInSeconds = 180

// SdJwtVcVerificationContext contains some options and configuration for verifying SD-JWT VCs.
type SdJwtVcVerificationContext struct {
	eudi_jwt.X509VerificationContext

	// Used to obtain the current time in order to verify `iat` and `nbf` etc.
	Clock jwt.Clock

	// Used to verify both JWT components of an SD-JWT VC (issuer signed jwt and kbjwt).
	JwtVerifier JwtVerifier

	VerifyVerifiableCredentialTypeInRequestorInfo bool

	MissingDisclosuresPolicy MissingDisclosuresPolicy
}

func CreateDefaultVerificationContext(trustedChain []byte) SdJwtVcVerificationContext {
	opts, err := utils.CreateX509VerifyOptionsFromCertChain(trustedChain)
	if err != nil {
		panic(fmt.Errorf("failed to create X509 verification options: %v", err))
	}
	return SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: *opts,
		},
		Clock:       NewSystemClock(),
		JwtVerifier: NewJwxJwtVerifier(),
	}
}

type ProcessedSdJwtPayload map[string]any

func (v *HolderSdJwt) GetRawSdJwtVc() SdJwtVc {
	return SdJwtVc(v.IssuerSignedJwt)
}

// ============================= Base SD-JWT VC processing =====================================

// sdJwtVcProcessor is the base processor, used to process and verify an SD-JWT VC for both holder and verifier.
type sdJwtVcProcessor struct {
	verificationContext SdJwtVcVerificationContext
}

// keyBindingProcessor is an interface for processing and verifying the key binding JWT of an SD-JWT VC.
// Implementations differ for holder and verifier processing.
type keyBindingProcessor interface {
	ProcessAndVerifyKeyBindingJwt(kbjwt *KeyBindingJwt, rawSdJwtVc SdJwtVc, holder *HolderSdJwt) (*KeyBindingJwtPayload, error)
}

func NewSdJwtVcProcessor(verificationContext SdJwtVcVerificationContext) sdJwtVcProcessor {
	return sdJwtVcProcessor{
		verificationContext: verificationContext,
	}
}

// ProcessAndVerifySdJwtVc implements chapter 7.1 of the SD-JWT VC specification.
func (v *sdJwtVcProcessor) ProcessAndVerifySdJwtVc(sdjwtvc SdJwtVcKb, keyBindingProcessor keyBindingProcessor) (*HolderSdJwt, error) {
	issuerSignedJwt, disclosures, rawSdJwtVc, rawKbJwt, err := splitSdJwtVcKb(sdjwtvc)
	if err != nil {
		return nil, err
	}

	holder, requestorInfo, err := v.parseAndVerifyIssuerSignedJwt(issuerSignedJwt, disclosures)
	if err != nil {
		return nil, err
	}
	// ignore
	_ = requestorInfo

	kbJwtPayload, err := keyBindingProcessor.ProcessAndVerifyKeyBindingJwt(rawKbJwt, rawSdJwtVc, holder)
	if err != nil {
		return nil, err
	}

	holder.KeyBindingJwt = kbJwtPayload

	// Verify the credential is allowed to be issued by the requestor
	// TODO: temporarily disable verification of the VCT against what is allowed in the requestor certificate
	// until we can issue SD-JWT VCs that fit our scheme
	// if v.verificationContext.VerifyVerifiableCredentialTypeInRequestorInfo {
	// 	disclosureKeys := slices.Collect(DisclosureContents(decodedDisclosures).Keys())
	// 	err = requestorInfo.AttestationProvider.VerifySdJwtIssuance(issuerSignedJwtPayload.VerifiableCredentialType, disclosureKeys)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to verify SD-JWT issuance: %v", err)
	// 	}
	// }

	// Valid SD-JWT, optionally with valid key binding JWT, depending on the key binding processor used

	return holder, nil
}

func (v *sdJwtVcProcessor) parseAndVerifyIssuerSignedJwt(signedJwt IssuerSignedJwt, disclosures []EncodedDisclosure) (
	*HolderSdJwt,
	*scheme.AttestationProviderRequestor,
	error,
) {
	token, requestorInfo, err := v.decodeJwtAndVerifyFromX5cHeader([]byte(signedJwt))
	if err != nil {
		return nil, nil, err
	}

	result := &HolderSdJwt{}

	claims := map[string]any{}
	for _, key := range token.Keys() {
		switch key {
		case Key_Issuer,
			Key_Audience,
			Key_Confirmationkey,
			Key_VerifiableCredentialType,
			Key_IssuedAt,
			Key_SdAlg,
			Key_NotBefore,
			Key_Status,
			Key_ExpiryTime:
			continue
		default:
			var value any
			err := token.Get(key, &value)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get %v from token: %w", key, err)
			}
			claims[key] = value
		}
	}

	disclosureLookup, err := createDisclosureLookupTable(iana.SHA256, disclosures)
	if err != nil {
		return nil, nil, err
	}

	result.Claims, err = parseClaims(v.verificationContext.MissingDisclosuresPolicy, claims, disclosureLookup)
	if err != nil {
		return nil, nil, err
	}

	var vct string
	err = token.Get(Key_VerifiableCredentialType, &vct)
	if err != nil {
		return nil, nil, errors.New("missing vct field")
	}

	// Get optional fields
	result.Subject, _ = token.Subject()
	result.Expiry = utils.GetOptional[int64](token, Key_ExpiryTime)
	result.IssuedAt = utils.GetOptional[int64](token, Key_IssuedAt)
	result.NotBefore = utils.GetOptional[int64](token, Key_NotBefore)

	iss, issPresent := token.Issuer()

	result.Issuer = iss
	result.Status = utils.GetOptional[string](token, Key_Status)

	if !issPresent {
		return nil, nil, errors.New("missing iss field")
	}

	// Check if the hashing algorithm was specified and supported, or use SHA-256 as default if the claim is not present
	result.SdAlg = iana.SHA256
	if token.Has(Key_SdAlg) {
		if h := utils.GetOptional[string](token, Key_SdAlg); iana.IsSupportedHashingAlgorithm(iana.HashingAlgorithm(h)) {
			result.SdAlg = iana.HashingAlgorithm(h)
		} else {
			return nil, nil, fmt.Errorf("unsupported _sd_alg: %s", h)
		}
	}

	var cnfRaw any
	err = token.Get(Key_Confirmationkey, &cnfRaw)

	if err == nil {
		result.Confirm, err = parseConfirmField(cnfRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse cnf field: %v", err)
		}
	}

	// Verify times
	err = v.verifyTimeFields(result)
	if err != nil {
		return nil, nil, err
	}

	result.IssuerSignedJwt = signedJwt
	result.Disclosures = disclosureLookup

	return result, requestorInfo, nil
}

func (v *sdJwtVcProcessor) verifyTimeFields(issuerSignedJwtPayload *HolderSdJwt) error {
	now := v.verificationContext.Clock.Now().Unix()
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

	return nil
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

func parseConfirmField(value any) (*CnfField, error) {
	anyMap, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("failed to parse as anymap: %v", value)
	}
	keyAny, ok := anyMap["jwk"]
	if !ok {
		return nil, errors.New("failed to get jwk field from cnf field")
	}
	keyJson, err := json.Marshal(keyAny)
	if err != nil {
		return nil, err
	}
	key, err := jwk.ParseKey(keyJson)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key (%v) from json: %v", value, err)
	}
	return &CnfField{Jwk: key}, nil
}

func verifyAndProcessDisclosures(sdAlg iana.HashingAlgorithm,
	issuerSignedJwtClaims *map[string]any,
	disclosures []EncodedDisclosure,
) (ProcessedSdJwtPayload, []*DisclosureContent, error) {
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
	delete(*issuerSignedJwtClaims, Key_SdAlg)

	return ProcessedSdJwtPayload(*issuerSignedJwtClaims), decodedDisclosures, nil
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
							if embeddedDisclosure.IsTouched() {
								return fmt.Errorf("digest %s has been referenced multiple time in the SD-JWT", disclosureDigest)
							}
							if !embeddedDisclosure.IsArrayElement() {
								return fmt.Errorf("embedded disclosure %s is expected to be an array element, but is not", embeddedDisclosure.Key)
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
			if embeddedDisclosure.IsTouched() {
				return fmt.Errorf("digest %s has been referenced multiple time in the SD-JWT", sdDigest)
			}
			if embeddedDisclosure.IsArrayElement() {
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

			embeddedDisclosure.Touch()
			(*claims)[embeddedDisclosure.Key] = embeddedDisclosure.Value
		}
	}

	// Delete the _sd field after processing
	delete(*claims, Key_Sd)

	return nil
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

// Decode the JWT into a token, verify the signature with the X.509 certificate in the header and verify the certificate is trusted (both against root/intermediate certs and CRLs).
// Function returns the token and the requestor info from the certificate.
func (v *sdJwtVcProcessor) decodeJwtAndVerifyFromX5cHeader(signedJwt []byte) (jwt.Token, *scheme.AttestationProviderRequestor, error) {
	keyProvider := &SdJwtKeyProvider{
		X509KeyProvider: eudi_jwt.X509KeyProvider{},
	}

	// Create a context for the verification where we can retrieve the requestor info back
	token, err := jwt.Parse(signedJwt,
		jwt.WithKeyProvider(keyProvider),
		jwt.WithClock(v.verificationContext.Clock),
		jwt.WithAcceptableSkew(ClockSkewInSeconds*time.Second),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT: %v", err)
	}

	// Get requestor info from cert
	cert := keyProvider.X509KeyProvider.GetCert()
	err = eudi_jwt.VerifyCertificate(v.verificationContext.X509VerificationContext, cert, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify certificate: %v", err)
	}

	// Verify the SD-JWT against the credentials the issuer is authorized to issue
	// TODO: temporarily disable verification of the VCT against what is allowed in the requestor certificate
	// until we can issue SD-JWT VCs that fit our scheme
	if v.verificationContext.VerifyVerifiableCredentialTypeInRequestorInfo {
		requestorInfo, err := utils.GetRequestorInfoFromCertificate[scheme.AttestationProviderRequestor](cert)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get requestor info from certificate: %v", err)
		}
		return token, requestorInfo, nil
	}

	return token, nil, nil
}

// ============================= Verifier processing =====================================

type VerifierVerificationProcessor struct {
	sdJwtVcProcessor
	verifierKeyBindingProcessor verifierKeyBindingProcessor
}

type verifierKeyBindingProcessor struct {
	keyBindingRequired  bool
	verificationContext SdJwtVcVerificationContext
}

func NewVerifierVerificationProcessor(keyBindingRequired bool, verificationContext SdJwtVcVerificationContext) *VerifierVerificationProcessor {
	return &VerifierVerificationProcessor{
		sdJwtVcProcessor:            NewSdJwtVcProcessor(verificationContext),
		verifierKeyBindingProcessor: NewVerifierKeyBindingProcessor(keyBindingRequired, verificationContext),
	}
}

func NewVerifierKeyBindingProcessor(keyBindingRequired bool, verificationContext SdJwtVcVerificationContext) verifierKeyBindingProcessor {
	return verifierKeyBindingProcessor{
		keyBindingRequired:  keyBindingRequired,
		verificationContext: verificationContext,
	}
}

// ParseAndVerifySdJwtVc is used to verify an SD-JWT VC using the verification options passed via the context parameter.
func (v *VerifierVerificationProcessor) ParseAndVerifySdJwtVc(sdjwtvc SdJwtVcKb) (*HolderSdJwt, error) {
	return v.sdJwtVcProcessor.ProcessAndVerifySdJwtVc(sdjwtvc, &v.verifierKeyBindingProcessor)
}

func (v *verifierKeyBindingProcessor) ProcessAndVerifyKeyBindingJwt(kbjwt *KeyBindingJwt, rawSdJwtVc SdJwtVc, issuerSignedJwtPayload *HolderSdJwt) (*KeyBindingJwtPayload, error) {
	if v.keyBindingRequired && kbjwt == nil {
		return nil, errors.New("key binding jwt is required, but not present in sdjwtvc")
	} else if kbjwt == nil {
		return nil, nil
	}

	keyBindingJwtPayload, err := v.parseAndVerifyKeyBindingJwt(
		rawSdJwtVc,
		issuerSignedJwtPayload,
		*kbjwt,
	)
	if err != nil {
		return nil, err
	}
	return keyBindingJwtPayload, nil
}

// TODO: check against chapter 7.3 of the SD-JWT VC specification.
func (v *verifierKeyBindingProcessor) parseAndVerifyKeyBindingJwt(
	sdJwtVc SdJwtVc,
	issuerSignedJwtPayload *HolderSdJwt,
	kbjwt KeyBindingJwt,
) (*KeyBindingJwtPayload, error) {
	header, _, err := decodeJwtWithoutCheckingSignature(string(kbjwt))
	if err != nil {
		return nil, err
	}

	if issuerSignedJwtPayload.Confirm == nil || issuerSignedJwtPayload.Confirm.Jwk == nil {
		return nil, errors.New("issuer signed jwt is missing holder key (cnf) required to verify kbjwt signature")
	}

	holderKey := issuerSignedJwtPayload.Confirm.Jwk
	payloadJson, err := v.verificationContext.JwtVerifier.Verify(string(kbjwt), holderKey)

	if err != nil {
		return nil, fmt.Errorf("invalid kbjwt signature: %v (holder key: %v)", err, holderKey)
	}

	if typ := header["typ"]; typ != KbJwtTyp {
		return nil, fmt.Errorf("key binding jwt header is expected to have 'typ' of '%s', but has %s (header: %v)", KbJwtTyp, typ, header)
	}

	var payload KeyBindingJwtPayload
	err = json.Unmarshal(payloadJson, &payload)
	if err != nil {
		return nil, err
	}

	hash, err := CreateUrlEncodedHash(issuerSignedJwtPayload.SdAlg, string(sdJwtVc))
	if err != nil {
		return nil, err
	}

	if payload.IssuerSignedJwtHash == "" {
		return nil, errors.New("issuer signed jwt hash missing in kbjwt")
	}
	if payload.IssuerSignedJwtHash != hash {
		return nil, fmt.Errorf("issuer signed jwt hash doesn't equal sd_hash found in kbjwt")
	}

	if payload.Nonce != "nonce" {
		return nil, fmt.Errorf("kbjwt 'nonce' field was expected to contain 'nonce', but contained '%s' instead", payload.Nonce)
	}

	now := v.verificationContext.Clock.Now()
	maxSkewNow := now.Unix() + ClockSkewInSeconds

	if payload.IssuedAt >= maxSkewNow {
		return nil, fmt.Errorf("kbjwt iat value (%v) was after current time (%v)", payload.IssuedAt, now)
	}

	return &payload, nil
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

// ============================= Holder processing =====================================

type HolderVerificationProcessor struct {
	sdJwtVcProcessor
}

func NewHolderVerificationProcessor(verificationContext SdJwtVcVerificationContext) *HolderVerificationProcessor {
	return &HolderVerificationProcessor{
		sdJwtVcProcessor: NewSdJwtVcProcessor(verificationContext),
	}
}

type holderVerifierKeyBindingProcessor struct{}

func (p *holderVerifierKeyBindingProcessor) ProcessAndVerifyKeyBindingJwt(kbjwt *KeyBindingJwt, rawSdJwtVc SdJwtVc, issuerSignedJwtPayload *HolderSdJwt) (*KeyBindingJwtPayload, error) {
	if kbjwt != nil {
		return nil, fmt.Errorf("key binding jwt found in SD-JWT, but holder should not receive one from the issuer")
	}
	return nil, nil
}

// ParseAndVerifySdJwtVc is used to verify an SD-JWT VC using the verification options passed via the context parameter.
func (v *HolderVerificationProcessor) ParseAndVerifySdJwtVc(sdjwtvc SdJwtVcKb) (*HolderSdJwt, error) {
	return v.sdJwtVcProcessor.ProcessAndVerifySdJwtVc(sdjwtvc, &holderVerifierKeyBindingProcessor{})
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
