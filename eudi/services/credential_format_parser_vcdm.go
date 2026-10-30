package services

import (
	"fmt"
	"net/http"
	"time"

	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// sdJwtVcdmCredentialFormatParser is the vc+sd-jwt implementation of
// CredentialFormatParser: SD-JWT-secured W3C VCDM 2.0 (VC-JOSE-COSE §3.2).
type sdJwtVcdmCredentialFormatParser struct {
	holderVerifier *vcdmsdjwt.HolderVerificationProcessor
	// contextClient fetches the JSON-LD contexts the credential's types are
	// expanded with (vcdm.ExpandTypes).
	contextClient *http.Client
}

// NewSdJwtVcdmCredentialFormatParser creates a CredentialFormatParser for
// SD-JWT-secured VCDM credentials, verifying with the given holder
// verification processor.
func NewSdJwtVcdmCredentialFormatParser(holderVerifier *vcdmsdjwt.HolderVerificationProcessor) CredentialFormatParser {
	return &sdJwtVcdmCredentialFormatParser{
		holderVerifier: holderVerifier,
		contextClient:  &http.Client{Timeout: 10 * time.Second},
	}
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
	for i, pc := range batch {
		if pc.SdJwtVcdm == nil {
			return fmt.Errorf("credential %d is not an SD-JWT-secured VCDM credential (format %q)", i, pc.Format)
		}
	}
	if err := requireUniqueHolderConfirmations(batch); err != nil {
		return err
	}
	if err := requireIdenticalBatchInstances(batch, sdJwtVcdmBatchInstanceContent); err != nil {
		return err
	}

	// A credential whose types cannot be expanded is refused, rather than
	// stored where no DCQL type_values query would find it. The instances are
	// copies of one credential with one @context, so the contexts are fetched
	// once for the batch.
	if len(batch) == 0 {
		return nil
	}
	types, err := vcdm.ExpandTypes(batch[0].SdJwtVcdm.Document, vcdm.NewContextLoader(p.contextClient))
	if err != nil {
		return fmt.Errorf("failed to expand the credential's types: %w", err)
	}
	for _, pc := range batch {
		pc.ExpandedTypes = types
	}
	return nil
}
