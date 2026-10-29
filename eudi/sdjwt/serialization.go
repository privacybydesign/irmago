package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	jwtOld "github.com/golang-jwt/jwt/v4"
)

// IssuerSignedJwt is the issued signed jwt as a string (so only the section of the sd-jwt up to and NOT including the first ~)
type IssuerSignedJwt string

// SdJwt represents an encoded SD-JWT as a string, be it with or without disclosures, without a key binding jwt
type SdJwt string

// SdJwtKb represents an encoded SD-JWT as a string, be it with or without disclosures, potentially with a key binding jwt (which needs to be determined by processing)
type SdJwtKb string

// disclosureSeparator is the ~ that terminates every SD-JWT component
const disclosureSeparator = '~'

// Create joins the issuer-signed JWT and every disclosure, each terminated by
// a ~, in one allocation.
func Create(issJwt IssuerSignedJwt, disclosures []EncodedDisclosure) SdJwt {
	size := len(issJwt) + 1
	for _, d := range disclosures {
		size += len(d) + 1
	}

	var sb strings.Builder
	sb.Grow(size)
	sb.WriteString(string(issJwt))
	sb.WriteByte(disclosureSeparator)
	for _, d := range disclosures {
		sb.WriteString(string(d))
		sb.WriteByte(disclosureSeparator)
	}
	return SdJwt(sb.String())
}

func CreateWithDisclosureContents(issJwt IssuerSignedJwt, disclosures []DisclosureContent) (SdJwt, error) {
	encoded := make([]EncodedDisclosure, len(disclosures))
	for i, d := range disclosures {
		encD, err := EncodeDisclosure(d)
		if err != nil {
			return "", err
		}
		encoded[i] = encD
	}
	return Create(issJwt, encoded), nil
}

func AddKeyBindingJwt(sdJwt SdJwt, kbjwt KeyBindingJwt) SdJwtKb {
	return SdJwtKb(string(sdJwt) + string(kbjwt))
}

// Split splits the sdjwt at the ~ characters and returns the individual components.
// The IssuerSignedJwt is guaranteed to contain a value (if there's no error).
// The EncodedDisclosure list could be empty if there are no disclosures.
// This function will do no verification whatsoever.
func Split(sdJwt SdJwt) (IssuerSignedJwt, []EncodedDisclosure, error) {
	trimmedSdJwt := strings.TrimSuffix(string(sdJwt), "~")
	components := strings.Split(trimmedSdJwt, "~")

	numComponents := len(components)
	if numComponents == 0 {
		return "", []EncodedDisclosure{}, fmt.Errorf("invalid sdJwt: %s", sdJwt)
	}

	issuerSignedJwt := IssuerSignedJwt(components[0])
	encodedDisclosures := make([]EncodedDisclosure, numComponents-1)

	for i, d := range components[1:numComponents] {
		encodedDisclosures[i] = EncodedDisclosure(d)
	}

	return issuerSignedJwt, encodedDisclosures, nil
}

// SplitKb splits the sdjwt at the ~ characters and returns the individual components.
// The IssuerSignedJwt is guaranteed to contain a value (if there's no error).
// The EncodedDisclosure list could be empty if there are no disclosures.
// The KbJwt may be nil if there's no key binding jwt.
// This function will do no verification whatsoever.
func SplitKb(sdJwtKb SdJwtKb) (issuerSignedJwt IssuerSignedJwt, encodedDisclosures []EncodedDisclosure, rawSdJwt SdJwt, rawKbJwt *KeyBindingJwt, err error) {
	if sdJwtKb == "" {
		return "", []EncodedDisclosure{}, "", nil, fmt.Errorf("sdJwtKb is an empty string")
	}

	// if it doesn't end with a ~, there must be a kbjwt
	hasKbJwt := !strings.HasSuffix(string(sdJwtKb), "~")
	if !hasKbJwt {
		// Delegate to the non-kbjwt version
		rawSdJwt = SdJwt(sdJwtKb)
		issuerSignedJwt, encodedDisclosures, err = Split(rawSdJwt)
		return
	}

	// Key-Binding JWT present; get SD-JWT slice separate from the Key-Binding JWT
	lastTildeChar := strings.LastIndex(string(sdJwtKb), "~")

	rawSdJwt = SdJwt(sdJwtKb[:lastTildeChar+1])
	issuerSignedJwt, encodedDisclosures, err = Split(rawSdJwt)

	// Only return a kbjwt if we could successfully split the sdjwt (otherwise the SD-JWT part is invalid and the KB-JWT is also invalid anyway)
	if err == nil {
		tmpKbJwt := KeyBindingJwt(sdJwtKb[lastTildeChar+1:])
		rawKbJwt = &tmpKbJwt
	}

	return
}

// DecodeJwtPayload extracts and decodes the payload of the issuer-signed JWT
// from an SD-JWT. The disclosures and KB-JWT suffix are stripped first.
func DecodeJwtPayload(sdJwt SdJwt) (map[string]any, error) {
	issJwt, _, err := Split(sdJwt)
	if err != nil {
		return nil, err
	}
	return decodePayloadFromJwt(issJwt)
}

func decodePayloadFromJwt(jwt IssuerSignedJwt) (map[string]any, error) {
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

// DecodeJwtWithoutCheckingSignature parses a JWT's header and claims without
// verifying its signature. Used where the caller needs to inspect a claim
// (e.g. to determine which key to verify with) before verification is possible.
func DecodeJwtWithoutCheckingSignature(jwtString string) (header map[string]any, claims map[string]any, err error) {
	parser := jwtOld.NewParser()
	var claimsResult jwtOld.MapClaims
	token, _, err := parser.ParseUnverified(jwtString, &claimsResult)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT: %v", err)
	}
	return token.Header, claimsResult, err
}
