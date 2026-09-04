package services

import (
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// sdJwtVcCredentialFormatParser is the dc+sd-jwt implementation of
// CredentialFormatParser. Its ParseAndVerify body is a byte-for-byte
// relocation of what used to be inline in openid4vci/session.go's
// obtainCredential — no behavioral change.
type sdJwtVcCredentialFormatParser struct {
	holderVerifier *sdjwtvc.HolderVerificationProcessor
}

// NewSdJwtVcCredentialFormatParser creates a CredentialFormatParser for
// dc+sd-jwt credentials, verifying with the given holder verification
// processor.
func NewSdJwtVcCredentialFormatParser(holderVerifier *sdjwtvc.HolderVerificationProcessor) CredentialFormatParser {
	return &sdJwtVcCredentialFormatParser{holderVerifier: holderVerifier}
}

func (p *sdJwtVcCredentialFormatParser) ParseAndVerify(raw, _ string, _ bool) (*ParsedCredential, error) {
	verified, err := p.holderVerifier.ParseAndVerifySdJwtVc(sdjwtvc.SdJwtVcKb(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to verify credential: %v", err)
	}

	jwtPayload := verified.IssuerSignedJwtPayload
	return &ParsedCredential{
		Format:                   models.CredentialFormatSdJwtVc,
		VerifiableCredentialType: jwtPayload.VerifiableCredentialType,
		// verified.IssuerIdentifier rather than jwtPayload.Issuer: `iss` is
		// OPTIONAL in SD-JWT VC, and the verifier falls back to the subject of the
		// x5c end-entity certificate when it is absent (SD-JWT VC §2.2.2.3).
		// Reading the claim directly would store an empty issuer for a credential
		// that has a perfectly good verified identity.
		IssuerIdentifier:   verified.IssuerIdentifier,
		RawCredentialBytes: []byte(verified.GetRawSdJwtVc()),
		IssuedAt:           jwtPayload.IssuedAt,
		ExpiresAt:          jwtPayload.Expiry,
		NotBefore:          jwtPayload.NotBefore,
		SdJwtVc:            verified,
	}, nil
}

func (p *sdJwtVcCredentialFormatParser) CheckBatchUniqueness(batch []*ParsedCredential) error {
	vcs := make([]*sdjwtvc.VerifiedSdJwtVc, len(batch))
	for i, pc := range batch {
		vcs[i] = pc.SdJwtVc
	}
	return sdjwtvc.CheckKeyBindingConfirmationUniqueness(vcs)
}
