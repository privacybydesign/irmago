package irmaclient

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/irma"
)

// CardHash is the Credential.Hash the wallet shows an IRMA credential under:
// a hash over its type and attribute values, the same for the idemix and the
// SD-JWT VC format of one dual issued credential.
func CardHash(info *irma.CredentialInfo) (string, error) {
	var hashContent strings.Builder
	hashContent.WriteString(info.Identifier().String())

	sortedKeys := []string{}
	for key, value := range info.Attributes {
		// Idemix lists an absent optional attribute with a nil value, while an
		// SD-JWT has no claim for it at all. Skip it so both formats of a dual
		// issued credential hash the same. A present "" is non-nil and still hashed.
		if len(value) == 0 {
			continue
		}
		sortedKeys = append(sortedKeys, key.String())
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		valueStr, err := json.Marshal(info.Attributes[irma.NewAttributeTypeIdentifier(key)])
		if err != nil {
			return "", err
		}
		hashContent.WriteString(key + string(valueStr))
	}

	return iana.CreateUrlEncodedHash(iana.SHA256, hashContent.String())
}

// CredentialInfo is the IRMA CredentialInfo of an SD-JWT VC batch issued over
// IRMA.
func (metadata SdJwtVcBatchMetadata) CredentialInfo() *irma.CredentialInfo {
	credIdSegments := strings.Split(metadata.CredentialType, ".")

	attrs := map[irma.AttributeTypeIdentifier]irma.TranslatedString{}
	for name, value := range metadata.Attributes {
		id := irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", metadata.CredentialType, name))
		valueStr := value.(string)
		translatedValue := irma.NewTranslatedString(&valueStr)
		attrs[id] = translatedValue
	}

	info := irma.CredentialInfo{
		ID:                  credIdSegments[2],
		IssuerID:            credIdSegments[1],
		SchemeManagerID:     credIdSegments[0],
		Attributes:          attrs,
		Hash:                metadata.Hash,
		Revoked:             false,
		RevocationSupported: false,
		CredentialFormat:    clientmodels.Format_SdJwtVc,
		InstanceCount:       &metadata.RemainingInstanceCount,
	}

	if metadata.SignedOn != nil {
		info.SignedOn = *metadata.SignedOn
	}
	if metadata.Expires != nil {
		info.Expires = *metadata.Expires
	}

	return &info
}
