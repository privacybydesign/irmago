package irmaclient

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"golang.org/x/text/language"
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

func createCredentialInfoAndVerifiedSdJwtVc(cred sdjwtvc.SdJwtVc, verificationContext sdjwtvc.SdJwtVcVerificationContext) (*SdJwtVcMetadata, *sdjwtvc.VerifiedSdJwtVc, error) {
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

func convertDisplayToTranslatedString[T openid4vci.Display | openid4vci.CredentialDisplay | openid4vci.CredentialIssuerDisplay](displays []T) irma.TranslatedString {
	if displays == nil {
		return nil
	}

	translations := openid4vci.DisplaysToTranslateableList(displays)

	result := irma.TranslatedString{}
	for _, display := range translations {
		lang, err := language.Parse(display.GetLocale())
		if err != nil {
			continue
		}

		base, _ := lang.Base()

		// TODO: this overwrites translations for the same base language (i.e. en-US would overwrite en-GB), because the app only handles base languages
		result[base.String()] = display.GetName()
	}

	return result
}

// verifyAndStoreSdJwts verifies the SD-JWTs and stores them in the SdJwtVcStorage.
// SD-JWTs that are batch-issued should all have the exact same credential info (issuer, id, signedOn, expires, etc.), otherwise they cannot be stored together correctly.
func verifyAndStoreSdJwts(sdjwts []sdjwtvc.SdJwtVc, sdJwtVcStorage SdJwtVcStorage, sdJwtVerificationContext sdjwtvc.SdJwtVcVerificationContext) error {
	// TODO: check if all SD-JWTs have a unique Key-Binding public key, if not, the SD-JWTs should be rejected

	type credentialTuple struct {
		credInfo         SdJwtVcMetadata
		sdjwtvcInstances []sdjwtvc.SdJwtVc
	}
	credentialsMap := make(map[string]*credentialTuple)

	for _, sdjwt := range sdjwts {
		// TODO: check if the SD-JWT adheres to the requested credentials (e.g. if the credential ID and attributes etc match) ?
		// If we don't check this, issuers might issue SD-JWTs that do not match the corresponding IRMA credential
		credInfo, _, err := createCredentialInfoAndVerifiedSdJwtVc(sdjwt, sdJwtVerificationContext)
		if err != nil {
			return err
		}

		// We use the credential info hash as the key to store the SD-JWTs in a map, NOT the credential info or credential ID.
		// Because it is possible that multiple credentials with same credential ID, but different data (e.g. different attributes or minor differences in signedOn/expires)
		// can be issued in a single request, we need to use the hash of the data itself to distinguish between them.
		key := credInfo.Hash
		if _, exists := credentialsMap[key]; !exists {
			credentialsMap[key] = &credentialTuple{
				credInfo:         *credInfo,
				sdjwtvcInstances: []sdjwtvc.SdJwtVc{sdjwt},
			}
		} else {
			credentialsMap[key].sdjwtvcInstances = append(credentialsMap[key].sdjwtvcInstances, sdjwt)
		}
	}

	// Now that we've grouped the SD-JWTs by their credential info hash, we can store them
	for _, v := range credentialsMap {
		batchInfo := SdJwtVcBatchMetadata{
			BatchSize:              uint(len(v.sdjwtvcInstances)),
			RemainingInstanceCount: uint(len(v.sdjwtvcInstances)),
			SignedOn:               v.credInfo.SignedOn,
			Expires:                v.credInfo.Expires,
			Attributes:             v.credInfo.Attributes,
			Hash:                   v.credInfo.Hash,
			CredentialType:         v.credInfo.CredentialType,
		}

		err := sdJwtVcStorage.StoreCredential(batchInfo, v.sdjwtvcInstances)
		if err != nil {
			return fmt.Errorf("failed to store sdjwtvc batch: %v", err)
		}
	}

	return nil
}
