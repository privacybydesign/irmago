package services

import (
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// sdJwtVcdmCredentialFormatParser is the vc+sd-jwt implementation of
// CredentialFormatParser: SD-JWT-secured W3C VCDM 2.0 (VC-JOSE-COSE §3.2).
type sdJwtVcdmCredentialFormatParser struct {
	holderVerifier *vcdmsdjwt.HolderVerificationProcessor
}

// NewSdJwtVcdmCredentialFormatParser creates a CredentialFormatParser for
// SD-JWT-secured VCDM credentials, verifying with the given holder
// verification processor.
func NewSdJwtVcdmCredentialFormatParser(holderVerifier *vcdmsdjwt.HolderVerificationProcessor) CredentialFormatParser {
	return &sdJwtVcdmCredentialFormatParser{holderVerifier: holderVerifier}
}

func (p *sdJwtVcdmCredentialFormatParser) ParseAndVerify(raw, _ string, _ bool) (*ParsedCredential, error) {
	verified, err := p.holderVerifier.ParseAndVerifySdJwtVcdm(vcdmsdjwt.SdJwtVcdmKb(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to verify credential: %v", err)
	}

	// The document's issuer is authoritative for VCDM (the JWT iss, when
	// present, was cross-checked against it during verification), and it cannot
	// be malformed here: Document.Validate ran during verification.
	issuerID, err := verified.Document.IssuerID()
	if err != nil {
		return nil, fmt.Errorf("failed to read VCDM issuer: %w", err)
	}

	issuedAt, expiresAt, notBefore := VcdmIssuanceValidity(verified)
	return &ParsedCredential{
		Format:                   models.CredentialFormatSdJwtVcdm,
		VerifiableCredentialType: verified.Document.TypeIdentity(),
		IssuerIdentifier:         issuerID,
		RawCredentialBytes:       []byte(verified.GetRawSdJwtVcdm()),
		IssuedAt:                 issuedAt,
		ExpiresAt:                expiresAt,
		NotBefore:                notBefore,
		SdJwtVcdm:                verified,
	}, nil
}

func (p *sdJwtVcdmCredentialFormatParser) CheckBatch(batch []*ParsedCredential) error {
	verified := make([]*vcdmsdjwt.VerifiedSdJwtVcdm, len(batch))
	for i, pc := range batch {
		if pc.SdJwtVcdm == nil {
			return fmt.Errorf("credential %d is not an SD-JWT-secured VCDM credential (format %q)", i, pc.Format)
		}
		verified[i] = pc.SdJwtVcdm
	}
	if err := vcdmsdjwt.CheckKeyBindingConfirmationUniqueness(verified); err != nil {
		return err
	}
	return requireIdenticalBatchInstances(batch, sdJwtVcdmBatchInstanceContent)
}
