package sdjwtvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	jwtOld "github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

// ============================ SD-JWT VC processing descriptions =====================================

type VerifiedSdJwtVc struct {
	IssuerSignedJwtPayload IssuerSignedJwtPayload
	Disclosures            []DisclosureContent
	ProcessedSdJwtPayload  ProcessedSdJwtPayload

	KeyBindingJwt *KeyBindingJwtPayload

	rawSdJwtVc SdJwtVc
}

const ClockSkewInSeconds = 180

// timeToUnixOrZero returns 0 if t is the zero time (i.e. the claim was missing),
// otherwise returns t.Unix(). This prevents time.Time{}.Unix() (-62135596800)
// from being treated as a real timestamp.
func timeToUnixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// SdJwtVcVerificationContext contains some options and configuration for verifying SD-JWT VCs.
type SdJwtVcVerificationContext struct {
	eudi_jwt.X509VerificationContext

	// Used to obtain the current time in order to verify `iat` and `nbf` etc.
	Clock jwt.Clock

	// Used to verify both JWT components of an SD-JWT VC (issuer signed jwt and kbjwt).
	JwtVerifier JwtVerifier

	VerifyVerifiableCredentialTypeInRequestorInfo bool

	// ExpectedNonce is the nonce from the OpenID4VP authorization request that the KB-JWT nonce
	// must match. This prevents replay attacks by ensuring the presentation was created for this
	// specific request.
	ExpectedNonce string

	// StatusChecker, when set, runs an IETF OAuth Token Status List
	// check after the SD-JWT VC verification succeeds: if the
	// payload carries a `status.status_list` reference, the verifier
	// fetches/verifies the referenced Status List Token and rejects
	// the credential unless the indexed bit reads StatusValid.
	// Nil disables the check.
	StatusChecker *statuslist.Checker

	// ExpectedAudience is the audience from the OpenID4VP authorization request that the KB-JWT aud
	// must match.
	ExpectedAudience string
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
		Clock:       eudi_jwt.NewSystemClock(),
		JwtVerifier: NewJwxJwtVerifier(),
	}
}

type ProcessedSdJwtPayload map[string]any

// MarshalJSON ensures that the JSON encoding of the ProcessedSdJwtPayload is deterministic by sorting map keys, which is necessary for consistent hashing of the payload.
// In order to calculate the hash consistently, the entire payload structure has to be sorted.
// Fortunately, ProcessedSdJwtPayload is built up from map[string]any structures (where any is either a scalar value, a map, or an array), which we can sort by marshalling to JSON, which already sorts map keys.
func (p *ProcessedSdJwtPayload) MarshalJSON() ([]byte, error) {
	p.Sort()
	return json.Marshal(map[string]any(*p))
}

// Sort sorts the ProcessedSdJwtPayload in place, by sorting all arrays by their values (when the array is of a scalar type).
// This ensures that the JSON encoding of the payload is deterministic, which is necessary for consistent hashing of the payload.
// As the map is keyed, it cannot be sorted itself, but this is handled by the JSON marshalling.
func (p *ProcessedSdJwtPayload) Sort() {
	for _, v := range *p {
		rt := reflect.TypeOf(v)
		switch rt.Kind() {
		case reflect.Map:
			m, ok := v.(ProcessedSdJwtPayload)
			if ok {
				m.Sort()
			} else {
				panic(fmt.Errorf("unexpected map type in ProcessedSdJwtPayload: %v", rt))
			}
		case reflect.Slice, reflect.Array:
			kind := rt.Elem().Kind()
			switch kind {
			case reflect.Float32:
				slices.Sort(v.([]float32))
			case reflect.Float64:
				slices.Sort(v.([]float64))
			case reflect.Uint8:
				slices.Sort(v.([]uint8))
			case reflect.Uint16:
				slices.Sort(v.([]uint16))
			case reflect.Uint32:
				slices.Sort(v.([]uint32))
			case reflect.Uint64:
				slices.Sort(v.([]uint64))
			case reflect.Uint:
				slices.Sort(v.([]uint))
			case reflect.Int8:
				slices.Sort(v.([]int8))
			case reflect.Int16:
				slices.Sort(v.([]int16))
			case reflect.Int32:
				slices.Sort(v.([]int32))
			case reflect.Int64:
				slices.Sort(v.([]int64))
			case reflect.Int:
				slices.Sort(v.([]int))
			case reflect.String:
				slices.Sort(v.([]string))
			}
		}
	}
}

func (v *VerifiedSdJwtVc) GetRawSdJwtVc() SdJwtVc {
	return v.rawSdJwtVc
}

// ============================= Base SD-JWT VC processing =====================================

// sdJwtVcProcessor is the base processor, used to process and verify an SD-JWT VC for both holder and verifier.
type sdJwtVcProcessor struct {
	verificationContext SdJwtVcVerificationContext
	allowInsecureDidWeb bool
}

// keyBindingProcessor is an interface for processing and verifying the key binding JWT of an SD-JWT VC.
// Implementations differ for holder and verifier processing.
type keyBindingProcessor interface {
	ProcessAndVerifyKeyBindingJwt(
		kbjwt *KeyBindingJwt,
		rawSdJwtVc SdJwtVc,
		holder *IssuerSignedJwtPayload,
	) (*KeyBindingJwtPayload, error)
}

func NewSdJwtVcProcessor(verificationContext SdJwtVcVerificationContext) sdJwtVcProcessor {
	return sdJwtVcProcessor{
		verificationContext: verificationContext,
	}
}

// runStatusListCheck consults the configured StatusChecker (if any)
// for the credential's status reference. Returns nil when no checker
// is configured or when the credential has no status_list reference;
// otherwise returns nil only when the indexed bit reads StatusValid.
//
// Status-fetch / verify / decode errors and any non-Valid status are
// returned to the caller, which will reject the credential. The
// behaviour is fail-closed.
func (v *sdJwtVcProcessor) runStatusListCheck(payload *IssuerSignedJwtPayload) error {
	if v.verificationContext.StatusChecker == nil {
		return nil
	}
	if payload.Status == nil || payload.Status.StatusList == nil {
		return nil
	}
	// context.Background is deliberate: there is no session/request context to
	// thread here — every caller up to irmaclient manufactures its own
	// Background, and this runs post-grant while the holder waits on the result.
	// Both network steps are bounded without a caller context: the status-list
	// GET by the checker's FetchTimeout, and did:web signing-key resolution by
	// the didweb resolver's own timeout. Threading a cancellable context down
	// ~60 ParseAndVerifySdJwtVc call sites would only buy cancel-on-dismiss.
	ctx := context.Background()
	status, err := v.verificationContext.StatusChecker.Check(ctx, *payload.Status.StatusList, payload.Issuer)
	if err != nil {
		return fmt.Errorf("status list check failed: %w", err)
	}
	if status != statuslist.StatusValid {
		return fmt.Errorf("credential status is %s, not valid", status)
	}
	return nil
}

// ProcessAndVerifySdJwtVc implements chapter 7.1 of the SD-JWT VC specification.
func (v *sdJwtVcProcessor) ProcessAndVerifySdJwtVc(
	sdjwtvc SdJwtVcKb,
	keyBindingProcessor keyBindingProcessor,
) (*VerifiedSdJwtVc, error) {
	issuerSignedJwt, disclosures, rawSdJwtVc, rawKbJwt, err := splitSdJwtVcKb(sdjwtvc)
	if err != nil {
		return nil, err
	}

	issuerSignedJwtPayload, requestorInfo, decodedDisclosures, processedSdJwtPayload, err := v.parseAndVerifyIssuerSignedJwt(issuerSignedJwt, disclosures)
	if err != nil {
		return nil, err
	}
	// ignore
	_ = requestorInfo

	kbJwtPayload, err := keyBindingProcessor.ProcessAndVerifyKeyBindingJwt(rawKbJwt, rawSdJwtVc, issuerSignedJwtPayload)
	if err != nil {
		return nil, err
	}

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

	// Token Status List check (draft-ietf-oauth-status-list-15). Skip
	// silently when no checker is configured or the credential carries
	// no status_list reference.
	if err := v.runStatusListCheck(issuerSignedJwtPayload); err != nil {
		return nil, err
	}

	// Valid SD-JWT, optionally with valid key binding JWT, depending on the key binding processor used
	return &VerifiedSdJwtVc{
		IssuerSignedJwtPayload: *issuerSignedJwtPayload,
		Disclosures:            decodedDisclosures,
		KeyBindingJwt:          kbJwtPayload,
		rawSdJwtVc:             rawSdJwtVc,
		ProcessedSdJwtPayload:  *processedSdJwtPayload,
	}, nil
}

func (v *sdJwtVcProcessor) parseAndVerifyIssuerSignedJwt(signedJwt IssuerSignedJwt, disclosures []EncodedDisclosure) (
	*IssuerSignedJwtPayload,
	*scheme.AttestationProviderRequestor,
	[]DisclosureContent,
	*ProcessedSdJwtPayload,
	error,
) {
	token, requestorInfo, err := v.decodeJwtAndVerifyFromX5cHeader([]byte(signedJwt))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var vct string
	err = token.Get(Key_VerifiableCredentialType, &vct)
	if err != nil {
		return nil, nil, nil, nil, errors.New("missing vct field")
	}

	// Get optional fields
	sub, _ := token.Subject()
	exp, expPresent := token.Expiration()
	iat, iatPresent := token.IssuedAt()
	nbf, nbfPresent := token.NotBefore()
	iss, issPresent := token.Issuer()

	if !issPresent {
		return nil, nil, nil, nil, errors.New("missing iss field")
	}

	// Check if the hashing algorithm was specified and supported, or use SHA-256 as default if the claim is not present
	sdAlg := iana.SHA256
	if token.Has(Key_SdAlg) {
		if h := utils.GetOptional[string](token, Key_SdAlg); iana.IsSupportedHashingAlgorithm(iana.HashingAlgorithm(h)) {
			sdAlg = iana.HashingAlgorithm(h)
		} else {
			return nil, nil, nil, nil, fmt.Errorf("unsupported _sd_alg: %s", h)
		}
	}

	var sdRaw, cnfRaw any

	var sd []HashedDisclosure
	err = token.Get(Key_Sd, &sdRaw)
	if err == nil {
		sd, err = parseSdField(sdRaw)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to parse sd field: %v", err)
		}
	}

	var cnf *CnfField
	err = token.Get(Key_Confirmationkey, &cnfRaw)
	if err == nil {
		cnf, err = parseConfirmField(cnfRaw)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to parse cnf field: %v", err)
		}
	}

	// Optional Token Status List reference (draft-ietf-oauth-status-list-15 §5.1).
	var status *statuslist.StatusClaim
	if token.Has(Key_Status) {
		status, err = parseStatusClaim(token)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to parse status claim: %v", err)
		}
	}

	// Verify and process disclosures
	// Get structured SD-JWT claims, which we can check for embedded disclosure digests
	issuerSignedJwtClaims, err := extractClaimsAndDisclosuresDigestsFromToken(token)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to extract claims from token: %v", err)
	}

	// Construct payload — use 0 for missing time claims instead of time.Time{}.Unix()
	payload := &IssuerSignedJwtPayload{
		Subject:                  sub,
		Issuer:                   iss,
		VerifiableCredentialType: vct,
		Sd:                       sd,
		SdAlg:                    iana.HashingAlgorithm(sdAlg),
		Confirm:                  cnf,
		Status:                   status,
	}

	if expPresent {
		expInt := timeToUnixOrZero(exp)
		payload.Expiry = &expInt
	}

	if iatPresent {
		iatInt := timeToUnixOrZero(iat)
		payload.IssuedAt = &iatInt
	}

	if nbfPresent {
		nbfInt := timeToUnixOrZero(nbf)
		payload.NotBefore = &nbfInt
	}

	// Verify times
	err = v.verifyTimeFields(payload)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Parse and verify disclosures
	processedSdJwtPayload, decodedDisclosures, err := verifyAndProcessDisclosures(payload.SdAlg, &issuerSignedJwtClaims, disclosures)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Convert pointer to disclosures to values for return  (TODO: optimize to avoid this copy?)
	decodedDisclosuresValues := make([]DisclosureContent, len(decodedDisclosures))
	for i, discPtr := range decodedDisclosures {
		decodedDisclosuresValues[i] = *discPtr
	}

	return payload, requestorInfo, decodedDisclosuresValues, &processedSdJwtPayload, nil
}

func (v *sdJwtVcProcessor) verifyTimeFields(issuerSignedJwtPayload *IssuerSignedJwtPayload) error {
	now := v.verificationContext.Clock.Now().Unix()
	minSkewNow := now - ClockSkewInSeconds
	maxSkewNow := now + ClockSkewInSeconds

	iat := issuerSignedJwtPayload.IssuedAt
	exp := issuerSignedJwtPayload.Expiry
	nbf := issuerSignedJwtPayload.NotBefore

	if nbf != nil && maxSkewNow < *nbf {
		return fmt.Errorf("verification before nbf: now: %v + skew: %v < nbf: %v", now, ClockSkewInSeconds, *nbf)
	}

	if iat != nil && maxSkewNow < *iat {
		return fmt.Errorf("verification before issued at: %v + skew: %v < %v", now, ClockSkewInSeconds, *iat)
	}

	if exp != nil && minSkewNow > *exp {
		return fmt.Errorf("verification after expiry of issuer signed jwt: %v - skew: %v > %v", now, ClockSkewInSeconds, *exp)
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

	// We support jwk and kid (with did:jwk method) confirmations.
	jwkAny, ok := anyMap["jwk"]
	if ok {
		jwkJson, err := json.Marshal(jwkAny)
		if err != nil {
			return nil, err
		}
		key, err := jwk.ParseKey(jwkJson)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key (%v) from json: %v", value, err)
		}
		return &CnfField{Jwk: &key}, nil
	}
	kidAny, ok := anyMap["kid"]
	if ok {
		kidStr, ok := kidAny.(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse kid field as string: %v", kidAny)
		}
		return &CnfField{Kid: &kidStr}, nil
	}

	return nil, fmt.Errorf("failed to parse cnf field: unsupported confirmation method, expected jwk or did:jwk: %v", value)
}

// parseStatusClaim reads the `status` claim from a verified jwt.Token
// into the structured form expected by the Token Status List
// pipeline. Only the `status_list` member is parsed in v1; other
// sibling members defined by future specs are silently ignored.
func parseStatusClaim(token jwt.Token) (*statuslist.StatusClaim, error) {
	var raw map[string]any
	if err := token.Get(Key_Status, &raw); err != nil {
		return nil, fmt.Errorf("status claim is not an object: %v", err)
	}
	slRaw, ok := raw["status_list"]
	if !ok {
		// status object present without a status_list member is a
		// well-formed extension point; treat as "no status list
		// reference on this credential".
		return &statuslist.StatusClaim{}, nil
	}
	slMap, ok := slRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("status_list is not an object: %T", slRaw)
	}
	idxRaw, ok := slMap["idx"]
	if !ok {
		return nil, fmt.Errorf("status_list.idx missing")
	}
	uriRaw, ok := slMap["uri"]
	if !ok {
		return nil, fmt.Errorf("status_list.uri missing")
	}
	uri, ok := uriRaw.(string)
	if !ok {
		return nil, fmt.Errorf("status_list.uri is not a string: %T", uriRaw)
	}
	var idx uint64
	switch n := idxRaw.(type) {
	case float64:
		if n < 0 {
			return nil, fmt.Errorf("status_list.idx is negative: %v", n)
		}
		idx = uint64(n)
	case int:
		if n < 0 {
			return nil, fmt.Errorf("status_list.idx is negative: %v", n)
		}
		idx = uint64(n)
	case int64:
		if n < 0 {
			return nil, fmt.Errorf("status_list.idx is negative: %v", n)
		}
		idx = uint64(n)
	case uint64:
		idx = n
	default:
		return nil, fmt.Errorf("status_list.idx is not a number: %T", idxRaw)
	}
	return &statuslist.StatusClaim{StatusList: &statuslist.Reference{Index: idx, URI: uri}}, nil
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
				// Check if the value is a disclosure (format should be {"...":"<digest>"}) or not, and if so,
				// verify the array element disclosure exists
				if valMap, ok := arrayElemValue.(map[string]any); ok {
					if arrayElemDisclosureDigestVal, ok := valMap[Key_Ellipsis]; ok {
						// It's an embedded disclosure digest...
						arrayElemDisclosureDigestStr, ok := arrayElemDisclosureDigestVal.(string)
						if !ok {
							return fmt.Errorf(
								"array element, which should be an embedded disclosure digest, is not a valid digest: %v",
								arrayElemDisclosureDigestStr,
							)
						}

						disclosureDigest := HashedDisclosure(arrayElemDisclosureDigestStr)
						if embeddedDisclosure, ok := decodedDisclosures[disclosureDigest]; ok {
							// Check for array element validity (i.e. should be in format ["...": "<digest>"])
							if embeddedDisclosure.IsTouched() {
								return fmt.Errorf(
									"digest %s has been referenced multiple time in the SD-JWT",
									disclosureDigest,
								)
							}
							if !embeddedDisclosure.IsArrayElement() {
								return fmt.Errorf(
									"embedded disclosure %s is expected to be an array element, but is not",
									embeddedDisclosure.Key,
								)
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
	issuerSignedJwtClaims := map[string]any{}
	for _, key := range token.Keys() {
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
func (v *sdJwtVcProcessor) decodeJwtAndVerifyFromX5cHeader(
	signedJwt []byte,
) (jwt.Token, *scheme.AttestationProviderRequestor, error) {
	keyProvider := NewSdJwtVcKeyProvider(v.allowInsecureDidWeb)

	// Create a context for the verification where we can retrieve the requestor info back
	token, err := jwt.Parse(signedJwt,
		jwt.WithKeyProvider(keyProvider),
		jwt.WithClock(v.verificationContext.Clock),
		jwt.WithAcceptableSkew(ClockSkewInSeconds*time.Second),
		jwt.WithVerify(true),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT: %v", err)
	}

	// If the key provider used was a X509KeyProvider, we can get the certificate and verify it against the trusted roots/intermediates and CRLs.
	if x509KeyProvider, ok := keyProvider.InnerKeyProvider.(*eudi_jwt.X509KeyProvider); ok {
		cert := x509KeyProvider.GetCert()
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
	}

	return token, nil, nil
}

func CheckKeyBindingConfirmationUniqueness(verifiedSdJwtVcs []*VerifiedSdJwtVc) error {
	for _, verifiedSdJwtVc := range verifiedSdJwtVcs {
		cnf := verifiedSdJwtVc.IssuerSignedJwtPayload.Confirm
		if cnf == nil {
			continue
		}

		duplicateCryptographicKey := slices.ContainsFunc(verifiedSdJwtVcs, func(otherSdJwtVc *VerifiedSdJwtVc) bool {
			return otherSdJwtVc != verifiedSdJwtVc &&
				otherSdJwtVc.IssuerSignedJwtPayload.Confirm != nil &&
				((cnf.Jwk != nil && otherSdJwtVc.IssuerSignedJwtPayload.Confirm.Jwk != nil && jwk.Equal(*otherSdJwtVc.IssuerSignedJwtPayload.Confirm.Jwk, *cnf.Jwk)) ||
					(cnf.Kid != nil && otherSdJwtVc.IssuerSignedJwtPayload.Confirm.Kid != nil && *otherSdJwtVc.IssuerSignedJwtPayload.Confirm.Kid == *cnf.Kid))
		})

		if duplicateCryptographicKey {
			return fmt.Errorf(
				"duplicate cryptographic key binding confirmation found for SD-JWT with vct %q",
				verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType,
			)
		}
	}

	return nil
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
func (v *VerifierVerificationProcessor) ParseAndVerifySdJwtVc(sdjwtvc SdJwtVcKb) (*VerifiedSdJwtVc, error) {
	return v.sdJwtVcProcessor.ProcessAndVerifySdJwtVc(sdjwtvc, &v.verifierKeyBindingProcessor)
}

func (v *verifierKeyBindingProcessor) ProcessAndVerifyKeyBindingJwt(
	kbjwt *KeyBindingJwt,
	rawSdJwtVc SdJwtVc,
	issuerSignedJwtPayload *IssuerSignedJwtPayload,
) (*KeyBindingJwtPayload, error) {
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
	issuerSignedJwtPayload *IssuerSignedJwtPayload,
	kbjwt KeyBindingJwt,
) (*KeyBindingJwtPayload, error) {
	header, _, err := decodeJwtWithoutCheckingSignature(string(kbjwt))
	if err != nil {
		return nil, err
	}

	// TODO: support kid-based key binding confirmation by resolving the did:jwk from the kid and using the resolved key to verify the KB-JWT signature?
	if issuerSignedJwtPayload.Confirm == nil || issuerSignedJwtPayload.Confirm.Jwk == nil {
		return nil, errors.New("issuer signed jwt is missing holder key (cnf) required to verify kbjwt signature")
	}

	var sigAlg jwa.SignatureAlgorithm
	if alg, ok := header["alg"]; ok {
		if algStr, ok := alg.(string); ok {
			s, found := jwa.LookupSignatureAlgorithm(algStr)
			if !found {
				return nil, fmt.Errorf("unsupported signing algorithm in kbjwt header: %s", algStr)
			}
			sigAlg = s
		} else {
			return nil, fmt.Errorf("unsupported signing algorithm in kbjwt header: %s", alg)
		}
	} else {
		return nil, fmt.Errorf("key binding jwt header is expected to have 'alg' of 'ES256', but has %s (header: %v)", header["alg"], header)
	}

	holderKey := issuerSignedJwtPayload.Confirm.Jwk
	payloadJson, err := v.verificationContext.JwtVerifier.Verify(string(kbjwt), *holderKey, sigAlg)

	if err != nil {
		return nil, fmt.Errorf("invalid kbjwt signature: %v (holder key: %v)", err, holderKey)
	}

	if typ := header["typ"]; typ != KbJwtTyp {
		return nil, fmt.Errorf(
			"key binding jwt header is expected to have 'typ' of '%s', but has %s (header: %v)",
			KbJwtTyp,
			typ,
			header,
		)
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

	if payload.Nonce != v.verificationContext.ExpectedNonce {
		return nil, fmt.Errorf("kbjwt 'nonce' field was expected to contain '%s', but contained '%s' instead", v.verificationContext.ExpectedNonce, payload.Nonce)
	}

	if payload.Audience != v.verificationContext.ExpectedAudience {
		return nil, fmt.Errorf("kbjwt 'aud' field was expected to contain '%s', but contained '%s' instead", v.verificationContext.ExpectedAudience, payload.Audience)
	}

	now := v.verificationContext.Clock.Now()
	maxSkewNow := now.Unix() + ClockSkewInSeconds

	if payload.IssuedAt == 0 {
		return nil, fmt.Errorf("kbjwt is missing iat field, which is required to prevent replay attacks")
	}
	if payload.IssuedAt > maxSkewNow {
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

// SetAllowInsecureDidWeb enables resolving did:web DIDs over HTTP instead of HTTPS.
// This should only be called when developer mode is enabled.
func (v *HolderVerificationProcessor) SetAllowInsecureDidWeb(allow bool) {
	v.allowInsecureDidWeb = allow
}

type holderVerifierKeyBindingProcessor struct{}

func (p *holderVerifierKeyBindingProcessor) ProcessAndVerifyKeyBindingJwt(kbjwt *KeyBindingJwt, rawSdJwtVc SdJwtVc, issuerSignedJwtPayload *IssuerSignedJwtPayload) (*KeyBindingJwtPayload, error) {
	if kbjwt != nil {
		return nil, fmt.Errorf("key binding jwt found in SD-JWT, but holder should not receive one from the issuer")
	}
	return nil, nil
}

// ParseAndVerifySdJwtVc is used to verify an SD-JWT VC using the verification options passed via the context parameter.
func (v *HolderVerificationProcessor) ParseAndVerifySdJwtVc(sdjwtvc SdJwtVcKb) (*VerifiedSdJwtVc, error) {
	return v.sdJwtVcProcessor.ProcessAndVerifySdJwtVc(sdjwtvc, &holderVerifierKeyBindingProcessor{})
}

// ========================================================================

type JwtVerifier interface {
	Verify(jwt string, key any, sigAlg jwa.SignatureAlgorithm) (payload []byte, err error)
}

type JwxJwtVerifier struct{}

func NewJwxJwtVerifier() *JwxJwtVerifier {
	return &JwxJwtVerifier{}
}

func (v *JwxJwtVerifier) Verify(jwtString string, keyAny any, sigAlg jwa.SignatureAlgorithm) (payload []byte, err error) {
	return jws.Verify([]byte(jwtString), jws.WithKey(sigAlg, keyAny))
}
