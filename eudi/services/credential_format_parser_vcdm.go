package services

import (
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
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

// sdJwtDataModelParser is the dc+sd-jwt CredentialFormatParser. The dc+sd-jwt
// format id names the securing mechanism, and in practice issuers use it for
// both SD-JWT data models (#678/#683), so it picks the verifier by the data
// model of the decoded payload: `@context` plus `type` is a W3C VCDM document
// and goes to the VCDM parser, anything else (a `vct`, or unrecognised
// structure) goes to the IETF SD-JWT VC parser, which enforces its own payload
// requirements.
//
// Detection reads unverified structure only to pick a verifier: each verifier
// re-checks the payload's data model after verifying the proof, so a
// mis-detected credential fails verification rather than being trusted. The
// returned ParsedCredential carries the format of the data model that verified,
// which is what the session stores it under.
type sdJwtDataModelParser struct {
	sdJwtVc CredentialFormatParser
	vcdm    CredentialFormatParser
}

// NewSdJwtDataModelParser returns the dc+sd-jwt parser that dispatches between
// the given SD-JWT VC and SD-JWT-secured VCDM parsers by payload data model.
func NewSdJwtDataModelParser(sdJwtVc, vcdm CredentialFormatParser) CredentialFormatParser {
	return &sdJwtDataModelParser{sdJwtVc: sdJwtVc, vcdm: vcdm}
}

func (p *sdJwtDataModelParser) ParseAndVerify(raw, credentialIssuer string, holderBindingKeyRequired bool) (*ParsedCredential, error) {
	payload, err := sdjwt.DecodeJwtPayload(sdjwt.SdJwt(raw))
	if err != nil {
		return nil, fmt.Errorf("could not decode credential for data-model dispatch: %v", err)
	}
	if vcdm.Detect(payload) == vcdm.DataModelVCDM {
		return p.vcdm.ParseAndVerify(raw, credentialIssuer, holderBindingKeyRequired)
	}
	return p.sdJwtVc.ParseAndVerify(raw, credentialIssuer, holderBindingKeyRequired)
}

// CheckBatch rejects a batch that mixes data models — its instances
// are instances of one logical credential — and otherwise applies the parsed data
// model's own check.
func (p *sdJwtDataModelParser) CheckBatch(batch []*ParsedCredential) error {
	if len(batch) == 0 {
		return nil
	}
	format := batch[0].Format
	for i, pc := range batch[1:] {
		if pc.Format != format {
			return fmt.Errorf("credential batch is heterogeneous: instance 0 is %s but instance %d is %s", format, i+1, pc.Format)
		}
	}
	if format == models.CredentialFormatSdJwtVcdm {
		return p.vcdm.CheckBatch(batch)
	}
	return p.sdJwtVc.CheckBatch(batch)
}
