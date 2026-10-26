package vcdmsdjwt

import (
	"encoding/base64"
	"encoding/json"
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

// VCDM 2.0 type of a Verifiable Presentation and of a credential enveloped in
// one (VCDM 2.0 §4.13.1), and the JWS alg of an unsecured JWT (RFC 7519 §6).
const (
	typeVerifiablePresentation        = "VerifiablePresentation"
	typeEnvelopedVerifiableCredential = "EnvelopedVerifiableCredential"
	algUnsecured                      = "none"
)

// CreateEnvelopedPresentation wraps an SD-JWT-secured VCDM credential, holding
// only the selected disclosures, in a VCDM 2.0 Verifiable Presentation that
// envelopes it as an EnvelopedVerifiableCredential.
//
// When holder binding is required the presentation is signed with the holder
// key from the credential's cnf, and that signature, over aud and nonce, is the
// holder proof: the enveloped SD-JWT carries no KB-JWT. The holder public key
// goes in the jwk header so a verifier can check the signature without
// resolving anything. Without holder binding the presentation is unsecured
// (alg none), as there is no key to sign it with.
func CreateEnvelopedPresentation(selected sdjwt.SdJwt, keyBinder sdjwt.KeyBinder, requireHolderBinding bool, nonce string, audience string) (string, error) {
	claims := map[string]any{
		vcdm.ContextKey: []string{vcdm.ContextV2},
		vcdm.TypeKey:    []string{typeVerifiablePresentation},
		"verifiableCredential": []any{
			map[string]any{
				vcdm.ContextKey: []string{vcdm.ContextV2},
				vcdm.TypeKey:    typeEnvelopedVerifiableCredential,
				"id":            EnvelopedCredentialDataUrlPrefix + string(selected),
			},
		},
		jwt.AudienceKey: audience,
		"nonce":         nonce,
		jwt.IssuedAtKey: time.Now().Unix(),
	}

	if !requireHolderBinding {
		return createUnsecuredJwt(claims)
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

// createUnsecuredJwt serializes claims as an unsecured JWT (RFC 7519 §6).
// Assembled by hand rather than with jwx, which would turn the aud string into
// an array and so give the two presentation forms different aud shapes.
func createUnsecuredJwt(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": algUnsecured, "typ": PresentationTyp})
	if err != nil {
		return "", fmt.Errorf("failed to serialize verifiable presentation header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to serialize verifiable presentation: %w", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + ".", nil
}
