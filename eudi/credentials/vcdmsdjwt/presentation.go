package vcdmsdjwt

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// PresentationTyp is the JWS typ of a JOSE-secured Verifiable Presentation
// (VC-JOSE-COSE §3.1.2).
const PresentationTyp = "vp+jwt"

// EnvelopedCredentialDataUrlPrefix prefixes the SD-JWT in the id of an
// EnvelopedVerifiableCredential (VCDM 2.0 §4.13.1, VC-JOSE-COSE §3.2).
const EnvelopedCredentialDataUrlPrefix = "data:application/vc+sd-jwt,"

// Present turns an SD-JWT-secured VCDM credential, holding only the selected
// disclosures, into what the wallet sends the verifier. With holder binding
// that is a Verifiable Presentation signed with the holder key
// (CreateEnvelopedPresentation). Without it, the credential itself is sent
// without a presentation around it, as OpenID4VP 1.0 Appendix B.1 requires for
// W3C credentials: the SD-JWT, with no KB-JWT.
func Present(selected sdjwt.SdJwt, keyBinder sdjwt.KeyBinder, requireHolderBinding bool, nonce string, audience string) (string, error) {
	if !requireHolderBinding {
		return string(selected), nil
	}
	return CreateEnvelopedPresentation(selected, keyBinder, nonce, audience)
}

// CreateEnvelopedPresentation wraps an SD-JWT-secured VCDM credential, holding
// only the selected disclosures, in a VCDM 2.0 Verifiable Presentation that
// envelopes it as an EnvelopedVerifiableCredential.
//
// The presentation is signed with the holder key from the credential's cnf,
// and that signature, over aud and nonce, is the holder proof: the enveloped
// SD-JWT carries no KB-JWT. The holder public key goes in the jwk header so a
// verifier can check the signature without resolving anything.
func CreateEnvelopedPresentation(selected sdjwt.SdJwt, keyBinder sdjwt.KeyBinder, nonce string, audience string) (string, error) {
	claims := map[string]any{
		vcdm.ContextKey: []string{vcdm.ContextV2},
		vcdm.TypeKey:    []string{"VerifiablePresentation"},
		"verifiableCredential": []any{
			map[string]any{
				vcdm.ContextKey: []string{vcdm.ContextV2},
				vcdm.TypeKey:    "EnvelopedVerifiableCredential",
				"id":            EnvelopedCredentialDataUrlPrefix + string(selected),
			},
		},
		jwt.AudienceKey: audience,
		"nonce":         nonce,
		jwt.IssuedAtKey: time.Now().Unix(),
	}

	_, holderKey, err := sdjwt.ExtractHashingAlgorithmAndHolderPubKey(selected)
	if err != nil {
		return "", fmt.Errorf("failed to get holder key of presented credential: %w", err)
	}

	header := map[string]any{
		"typ": PresentationTyp,
		"cty": "vp",
		"jwk": holderKey,
	}
	presentation, err := keyBinder.CreateHolderSignedJwt(holderKey, header, claims)
	if err != nil {
		return "", fmt.Errorf("failed to sign verifiable presentation: %w", err)
	}
	return presentation, nil
}
