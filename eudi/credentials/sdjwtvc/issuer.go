package sdjwtvc

import (
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// SdJwtVcBuilder builds an SD-JWT VC (draft-ietf-oauth-sd-jwt-vc) on top of
// the generic SD-JWT sdjwt.Builder: it additionally requires a `vct` claim,
// requires `iss` (when provided) to be a valid https:// URL, and sets the
// `typ` header to SdJwtVcTyp.
type SdJwtVcBuilder struct {
	claims          []*sdjwt.ClaimElement
	issuerCertChain []string
}

func NewSdJwtVcBuilder() *SdJwtVcBuilder {
	return &SdJwtVcBuilder{}
}

func (b *SdJwtVcBuilder) WithPayload(claims ...*sdjwt.ClaimElement) *SdJwtVcBuilder {
	b.claims = claims
	return b
}

func (b *SdJwtVcBuilder) WithIssuerCertificateChain(certChain []string) *SdJwtVcBuilder {
	b.issuerCertChain = certChain
	return b
}

func (b *SdJwtVcBuilder) Build(jwtCreator sdjwt.JwtCreator) (SdJwtVc, error) {
	vctClaimFound := false
	for _, c := range b.claims {
		switch c.Key {
		case VerifiableCredentialTypeKey:
			vctClaimFound = true
		case jwt.IssuerKey:
			url, ok := c.Value.(string)
			if !ok {
				return "", fmt.Errorf("issuer url (iss) is provided but is not a string")
			}

			if !strings.HasPrefix(url, "https://") {
				return "", fmt.Errorf("issuer url (iss) is required to be a valid https link when provided (but was '%s')", url)
			}
		}
	}
	if !vctClaimFound {
		return "", fmt.Errorf("'vct' claim required but not found")
	}

	result, err := sdjwt.NewBuilder().
		WithPayload(b.claims...).
		WithIssuerCertificateChain(b.issuerCertChain).
		WithTyp(SdJwtVcTyp).
		Build(jwtCreator)
	if err != nil {
		return "", err
	}
	return SdJwtVc(result), nil
}
