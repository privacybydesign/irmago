package vcdmsdjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
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
// one (VCDM 2.0 §4.13.1).
const (
	typeVerifiablePresentation        = "VerifiablePresentation"
	typeEnvelopedVerifiableCredential = "EnvelopedVerifiableCredential"
)

// CreateEnvelopedPresentation wraps an SD-JWT-secured VCDM credential, holding
// only the selected disclosures, in a VCDM 2.0 Verifiable Presentation that
// envelopes it as an EnvelopedVerifiableCredential.
//
// The presentation is signed with the holder key from the credential's cnf,
// and that signature, over aud and nonce, is the holder proof: the enveloped
// SD-JWT carries no KB-JWT. The holder public key goes in the jwk header so a
// verifier can check the signature without resolving anything.
func CreateEnvelopedPresentation(selected sdjwt.SdJwt, keyBinder sdjwt.KeyBinder, nonce string, audience string) (string, error) {
	_, holderKey, err := sdjwt.ExtractHashingAlgorithmAndHolderPubKey(selected)
	if err != nil {
		return "", fmt.Errorf("failed to get holder key of presented credential: %w", err)
	}

	header, claims := envelopedPresentation(selected, holderKey, nonce, audience)
	presentation, err := keyBinder.CreateHolderSignedJwt(holderKey, header, claims)
	if err != nil {
		return "", fmt.Errorf("failed to sign verifiable presentation: %w", err)
	}
	return presentation, nil
}

// EnvelopedPresentationSigningInput returns the JWS signing input of the
// presentation CreateEnvelopedPresentation makes
// ("base64url(header).base64url(payload)"), for a signer outside this package
// to sign with alg. holderKey is the holder key from the credential's cnf, and
// issuedAt the time of the signature.
func EnvelopedPresentationSigningInput(selected sdjwt.SdJwt, holderKey jwk.Key, alg string, nonce string, audience string, issuedAt int64) ([]byte, error) {
	header, claims := envelopedPresentation(selected, holderKey, nonce, audience)
	header["alg"] = alg
	claims[jwt.IssuedAtKey] = issuedAt

	headerJson, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal presentation header: %w", err)
	}
	claimsJson, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal presentation claims: %w", err)
	}
	enc := base64.RawURLEncoding
	return []byte(enc.EncodeToString(headerJson) + "." + enc.EncodeToString(claimsJson)), nil
}

// envelopedPresentation is the header and claims of the presentation, but for
// the alg and iat the signer sets.
func envelopedPresentation(selected sdjwt.SdJwt, holderKey jwk.Key, nonce string, audience string) (header map[string]any, claims map[string]any) {
	claims = map[string]any{
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
	}
	header = map[string]any{
		"typ": PresentationTyp,
		"cty": "vp",
		"jwk": holderKey,
	}
	return header, claims
}
