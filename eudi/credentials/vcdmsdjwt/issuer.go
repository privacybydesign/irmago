package vcdmsdjwt

import (
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// SdJwtVcdmBuilder builds an SD-JWT-secured VCDM credential (VC-JOSE-COSE §3.2)
// on top of the generic sdjwt.Builder. It sits parallel to
// sdjwtvc.SdJwtVcBuilder: where that builder requires a `vct` claim and sets the
// `typ` header to `dc+sd-jwt`, this one requires the VCDM markers (`@context`
// and `type`) in the payload and sets `typ` to MediaTypeVcSdJwt (`vc+sd-jwt`).
//
// Like the SD-JWT VC builder, the check here is deliberately light — it enforces
// only that the two discriminating VCDM claims are present, not full structural
// conformance. Full VCDM validation (vcdm.Document.Validate) runs on the
// verifier side, on the decoded/disclosed document, after proof verification.
type SdJwtVcdmBuilder struct {
	claims          []*sdjwt.ClaimElement
	issuerCertChain []string
}

func NewSdJwtVcdmBuilder() *SdJwtVcdmBuilder {
	return &SdJwtVcdmBuilder{}
}

// WithPayload sets the VCDM document as an sdjwt claim tree. Selective
// disclosure is expressed within the tree (e.g. sdjwt.SdClaim leaves inside the
// `credentialSubject` object).
func (b *SdJwtVcdmBuilder) WithPayload(claims ...*sdjwt.ClaimElement) *SdJwtVcdmBuilder {
	b.claims = claims
	return b
}

func (b *SdJwtVcdmBuilder) WithIssuerCertificateChain(certChain []string) *SdJwtVcdmBuilder {
	b.issuerCertChain = certChain
	return b
}

func (b *SdJwtVcdmBuilder) Build(jwtCreator sdjwt.JwtCreator) (SdJwtVcdm, error) {
	contextFound, typeFound := false, false
	for _, c := range b.claims {
		switch c.Key {
		case vcdm.ContextKey:
			contextFound = true
		case vcdm.TypeKey:
			typeFound = true
		}
	}
	if !contextFound {
		return "", fmt.Errorf("%q claim required for an SD-JWT-secured VCDM credential but not found", vcdm.ContextKey)
	}
	if !typeFound {
		return "", fmt.Errorf("%q claim required for an SD-JWT-secured VCDM credential but not found", vcdm.TypeKey)
	}

	result, err := sdjwt.NewBuilder().
		WithPayload(b.claims...).
		WithIssuerCertificateChain(b.issuerCertChain).
		WithTyp(MediaTypeVcSdJwt).
		Build(jwtCreator)
	if err != nil {
		return "", err
	}
	return SdJwtVcdm(result), nil
}
