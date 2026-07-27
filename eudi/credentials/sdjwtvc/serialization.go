package sdjwtvc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	jwtOld "github.com/golang-jwt/jwt/v4"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

// IssuerSignedJwt is the issued signed jwt as a string (so only the section of the sd-jwt vc up to and NOT including the first ~)
type IssuerSignedJwt string

// SdJwtVc represents an encoded sd-jwt vc as a string, be it with or without disclosures, without a key binding jwt
type SdJwtVc string

// SdJwtVcKb represents an encoded sd-jwt vc as a string, be it with or without disclosures, potentially with a key binding jwt (which needs to be determined by processing)
type SdJwtVcKb string

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

func AddKeyBindingJwtToSdJwtVc(sdjwtvc SdJwtVc, kbjwt KeyBindingJwt) SdJwtVcKb {
	return SdJwtVcKb(fmt.Sprintf("%s%s", sdjwtvc, kbjwt))
}

func CreateTestSdJwtVc() (SdJwtVc, error) {
	holderKey, err := readHolderPublicJwk()
	if err != nil {
		return "", err
	}
	holderKeyClaim, err := HolderKeyClaim(holderKey)
	if err != nil {
		return "", err
	}

	return NewSdJwtBuilder().
		WithPayload(
			Claim(Key_Subject, "6c5c0a49-b589-431d-bae7-219122a9ec2c"),
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://openid4vc.staging.yivi.app"),
			holderKeyClaim,
			Claim(Key_VerifiableCredentialType, "pbdf.sidn-pbdf.email"),
			Claim(Key_ExpiryTime, 1835689661),
			Claim(Key_IssuedAt, 1516239022),
			SdClaim("family_name", "Yivi"),
			SdClaim("location", "Utrecht"),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
}

// splitSdJwtVc splits the sdjwt at the ~ characters and returns the individual components.
// The IssuerSignedJwt is guaranteed to contain a value (if there's no error).
// The EncodedDisclosure list could be empty if there are no disclosures.
// The KbJwt may be nil if there's no key binding jwt.
// This function will do no verification whatsoever.
func splitSdJwtVcKb(sdJwtVcKb SdJwtVcKb) (issuerSignedJwt IssuerSignedJwt, encodedDisclosures []EncodedDisclosure, rawSdJwtVc SdJwtVc, rawKbJwt *KeyBindingJwt, err error) {
	if sdJwtVcKb == "" {
		return "", []EncodedDisclosure{}, "", nil, fmt.Errorf("sdJwtVcKb is an empty string")
	}

	// if it doesn't end with a ~, there must be a kbjwt
	hasKbJwt := !strings.HasSuffix(string(sdJwtVcKb), "~")
	if !hasKbJwt {
		// Delegate to the non-kbjwt version
		rawSdJwtVc = SdJwtVc(sdJwtVcKb)
		issuerSignedJwt, encodedDisclosures, err = splitSdJwtVc(rawSdJwtVc)
		return
	}

	// Key-Binding JWT present; get SD-JWT VC slice separate from the Key-Binding JWT
	lastTildeChar := strings.LastIndex(string(sdJwtVcKb), "~")

	rawSdJwtVc = SdJwtVc(sdJwtVcKb[:lastTildeChar+1])
	issuerSignedJwt, encodedDisclosures, err = splitSdJwtVc(rawSdJwtVc)

	// Only return a kbjwt if we could successfully split the sdjwtvc (otherwise the SD-JWT VC part is invalid and the KB-JWT is also invalid anyway)
	if err == nil {
		tmpKbJwt := KeyBindingJwt(sdJwtVcKb[lastTildeChar+1:])
		rawKbJwt = &tmpKbJwt
	}

	return
}

func splitSdJwtVc(sdJwtVc SdJwtVc) (IssuerSignedJwt, []EncodedDisclosure, error) {
	trimmedSdJwtVc := strings.TrimSuffix(string(sdJwtVc), "~")
	components := strings.Split(trimmedSdJwtVc, "~")

	numComponents := len(components)
	if numComponents == 0 {
		return "", []EncodedDisclosure{}, fmt.Errorf("invalid sdJwtVc: %s", sdJwtVc)
	}

	issuerSignedJwt := IssuerSignedJwt(components[0])
	encodedDisclosures := make([]EncodedDisclosure, numComponents-1)

	for i, d := range components[1:numComponents] {
		encodedDisclosures[i] = EncodedDisclosure(d)
	}

	return issuerSignedJwt, encodedDisclosures, nil
}

// DecodeJwtPayload extracts and decodes the payload of the issuer-signed JWT
// from an SD-JWT VC. The disclosures and KB-JWT suffix are stripped first.
func DecodeJwtPayload(sdJwt SdJwtVc) (map[string]any, error) {
	issJwt, _, err := splitSdJwtVc(sdJwt)
	if err != nil {
		return nil, err
	}
	return decodeJwtPayloadFromJwt(issJwt)
}

func decodeJwtPayloadFromJwt(jwt IssuerSignedJwt) (map[string]any, error) {
	parts := strings.Split(string(jwt), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to base64url-decode JWT payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload JSON: %v", err)
	}
	return payload, nil
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
