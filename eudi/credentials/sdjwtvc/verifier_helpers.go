package sdjwtvc

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jws"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

type SdJwtKeyProvider struct {
	innerKeyProvider jws.KeyProvider
	allowInsecure    bool
}

// FetchKeys fetches the keys for verifying the SD-JWT VC issuer signed jwt, but not before validating the 'typ' header.
// This is the only way to validate the 'typ' header against multiple possible values.
func (p *SdJwtKeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	// Validate 'typ' header first
	if typ, ok := sig.ProtectedHeaders().Type(); !ok || !slices.Contains([]string{JwtTyp, SdJwtVcTyp, SdJwtVcTyp_Legacy}, typ) {
		return fmt.Errorf("invalid 'typ' header: %v", typ)
	}

	// Basic header validation passed, now select the key reference. x5c and kid are
	// mutually exclusive: if both were accepted, a kid would overwrite an x5c here while
	// the X.509 trust/CRL check downstream (gated on the *X509KeyProvider type) is silently
	// skipped, letting a forged credential be verified against the kid-resolved key.
	x5c, x5cPresent := sig.ProtectedHeaders().X509CertChain()
	x5cPresent = x5cPresent && x5c != nil

	kid, kidPresent := sig.ProtectedHeaders().KeyID()
	kidPresent = kidPresent && kid != ""

	switch {
	case x5cPresent && kidPresent:
		return fmt.Errorf("ambiguous key reference: both 'x5c' and 'kid' headers are present")
	case x5cPresent:
		p.innerKeyProvider = eudi_jwt.NewX509KeyProvider(x5c)
	case kidPresent:
		p.innerKeyProvider = eudi_jwt.NewKidKeyProvider(kid, p.allowInsecure)
	default:
		return fmt.Errorf("no supported key reference header (x5c or kid) present in the signature")
	}

	return p.innerKeyProvider.FetchKeys(ctx, sink, sig, msg)
}

// splitSdJwtVc splits the sdjwt at the ~ characters and returns the individual components.
// The IssuerSignedJwt is guaranteed to contain a value (if there's no error).
// The EncodedDisclosure list could be empty if there are no disclosures.
// The KbJwt may be nil if there's no key binding jwt.
// This function will do no verification whatsoever.
func splitSdJwtVcKb(sdJwtVcKb SdJwtVcKb) (IssuerSignedJwt, []EncodedDisclosure, SdJwtVc, *KeyBindingJwt, error) {
	if sdJwtVcKb == "" {
		return "", []EncodedDisclosure{}, "", nil, fmt.Errorf("sdJwtVcKb is an empty string")
	}

	rawSdJwtKb := string(sdJwtVcKb)

	if !strings.Contains(rawSdJwtKb, "~") {
		// No ~ character at all, so the entire string is the issuer signed JWT and there are no disclosures or kbjwt
		return IssuerSignedJwt(sdJwtVcKb), []EncodedDisclosure{}, SdJwtVc(sdJwtVcKb), nil, nil
	}

	// if the credential ends with a ~, there is no kbjwt
	hasKbJwt := !strings.HasSuffix(rawSdJwtKb, "~")
	if hasKbJwt {
		// Key-Binding JWT present; get SD-JWT VC slice separate from the Key-Binding JWT
		lastTildeChar := strings.LastIndex(rawSdJwtKb, "~")

		rawSdJwtVc := SdJwtVc(sdJwtVcKb[:lastTildeChar+1])
		issuerSignedJwt, encodedDisclosures, err := splitSdJwtVc(rawSdJwtVc)

		// Only return a kbjwt if we could successfully split the sdjwtvc (otherwise the SD-JWT VC part is invalid and the KB-JWT is also invalid anyway)
		kbJwt := (*KeyBindingJwt)(nil)
		if err == nil {
			tmpKbJwt := KeyBindingJwt(sdJwtVcKb[lastTildeChar+1:])
			kbJwt = &tmpKbJwt
		}

		return issuerSignedJwt, encodedDisclosures, rawSdJwtVc, kbJwt, err
	}

	// SD-JWT (with or without disclosures, seperated by a ~)
	rawSdJwtVc := SdJwtVc(sdJwtVcKb)
	issuerSignedJwt, encodedDisclosures, err := splitSdJwtVc(rawSdJwtVc)
	return issuerSignedJwt, encodedDisclosures, rawSdJwtVc, nil, err
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
