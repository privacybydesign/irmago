package irmaclient

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
)

// CreateHashForSdJwtVc creates the hash used for SD-JWTs, it's kept this simple so it can also be constructed from
// an issuance request before the actual credential is issued
func CreateHashForSdJwtVc(credType string, attributes map[string]any) (string, error) {
	hashContent := credType

	sortedKeys := []string{}
	for key := range attributes {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		valueStr, err := json.Marshal(attributes[key])
		if err != nil {
			return "", err
		}
		hashContent += key + string(valueStr)
	}

	return sdjwtvc.CreateHash(sdjwtvc.HashAlg_Sha256, hashContent)
}

func createCredentialInfoAndVerifiedSdJwtVc(cred sdjwtvc.SdJwtVc, verificationContext sdjwtvc.VerificationContext) (*SdJwtVcMetadata, *sdjwtvc.VerifiedSdJwtVc, error) {
	decoded, err := sdjwtvc.ParseAndVerifySdJwtVc(verificationContext, cred)

	if err != nil {
		return nil, nil, err
	}

	attributes := map[string]any{}
	for _, d := range decoded.Disclosures {
		attributes[d.Key] = d.Value
	}

	hash, err := CreateHashForSdJwtVc(decoded.IssuerSignedJwtPayload.VerifiableCredentialType, attributes)
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
