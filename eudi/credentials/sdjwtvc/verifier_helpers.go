package sdjwtvc

import (
	"fmt"
	"strings"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// NewSdJwtVcKeyProvider returns a JwtKeyProvider configured for the SD-JWT VC
// 'typ' values defined by the spec (current and legacy).
func NewSdJwtVcKeyProvider(allowInsecure bool) *eudi_jwt.JwtKeyProvider {
	return eudi_jwt.NewJwtKeyProvider([]string{SdJwtVcTyp, SdJwtVcTyp_Legacy}, allowInsecure)
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
