package irmaclient

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
)

func createCredentialInfoAndVerifiedSdJwtVc(cred sdjwtvc.SdJwtVc, verificationContext sdjwtvc.VerificationContext) (*SdJwtVcMetadata, *sdjwtvc.VerifiedSdJwtVc, error) {
	decoded, err := sdjwtvc.ParseAndVerifySdJwtVc(verificationContext, cred)

	if err != nil {
		return nil, nil, err
	}

	attributes := map[string]any{}
	for _, d := range decoded.Disclosures {
		attributes[d.Key] = d.Value
	}

	hashContent, err := json.Marshal(attributes)
	if err != nil {
		return nil, nil, err
	}

	hash, err := sdjwtvc.CreateHash(sdjwtvc.HashAlg_Sha256, string(hashContent))
	if err != nil {
		return nil, nil, err
	}

	idComponents := strings.Split(decoded.IssuerSignedJwtPayload.VerifiableCredentialType, ".")
	if num := len(idComponents); num != 3 {
		return nil, nil, fmt.Errorf(
			"credential id expected to have exactly 3 components, separated by dots: %s",
			decoded.IssuerSignedJwtPayload.VerifiableCredentialType,
		)
	}

	info := SdJwtVcMetadata{
		Hash:           hash,
		CredentialType: decoded.IssuerSignedJwtPayload.VerifiableCredentialType,
		SignedOn: irma.Timestamp(
			time.Unix(decoded.IssuerSignedJwtPayload.IssuedAt, 0),
		),
		Expires: irma.Timestamp(
			time.Unix(decoded.IssuerSignedJwtPayload.Expiry, 0),
		),
		Attributes: attributes,
	}
	return &info, &decoded, nil
}
