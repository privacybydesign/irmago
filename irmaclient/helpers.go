package irmaclient

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
)

func createCredentialInfoAndVerifiedSdJwtVc(cred sdjwtvc.SdJwtVc, verificationContext sdjwtvc.VerificationContext) (*irma.CredentialInfo, *sdjwtvc.VerifiedSdJwtVc, error) {
	decoded, err := sdjwtvc.ParseAndVerifySdJwtVc(verificationContext, cred)

	if err != nil {
		return nil, nil, err
	}

	attributes := map[irma.AttributeTypeIdentifier]irma.TranslatedString{}
	for _, d := range decoded.Disclosures {
		strValue, ok := d.Value.(string)
		if !ok {
			return nil, nil, fmt.Errorf("failed to convert disclosure to string for attribute '%s'", d.Key)
		}
		schemeId := fmt.Sprintf("%s.%s", decoded.IssuerSignedJwtPayload.VerifiableCredentialType, d.Key)
		id := irma.NewAttributeTypeIdentifier(schemeId)
		attributes[id] = irma.TranslatedString{
			"":   strValue,
			"en": strValue,
			"nl": strValue,
		}
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
	info := irma.CredentialInfo{
		ID:              idComponents[2],
		IssuerID:        idComponents[1],
		SchemeManagerID: idComponents[0],
		SignedOn: irma.Timestamp(
			time.Unix(decoded.IssuerSignedJwtPayload.IssuedAt, 0),
		),
		Expires: irma.Timestamp(
			time.Unix(decoded.IssuerSignedJwtPayload.Expiry, 0),
		),
		Attributes:          attributes,
		Hash:                hash,
		Revoked:             false,
		RevocationSupported: false,
		CredentialFormats:   []string{"dc+sd-jwt"},
	}
	return &info, &decoded, nil
}
