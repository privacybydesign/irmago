package irmaclient

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/irma"
)

// CreateHashForSdJwtVc creates the hash used for SD-JWTs, it's kept this simple so it can also be constructed from
// an issuance request before the actual credential is issued
func CreateHashForSdJwtVc(credType string, attributes map[string]any) (string, error) {
	var hashContent strings.Builder
	hashContent.WriteString(credType)

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
		hashContent.WriteString(key + string(valueStr))
	}

	return sdjwtvc.CreateUrlEncodedHash(iana.SHA256, hashContent.String())
}

func createCredentialInfoAndVerifiedSdJwtVc(
	sdJwt sdjwtvc.SdJwtVcKb,
	holderVerifier *sdjwtvc.HolderVerificationProcessor,
	mode eudi.SdJwtVerificationMode,
) (*SdJwtVcMetadata, *sdjwtvc.VerifiedSdJwtVc, error) {
	verifiedSdJwtVc, err := holderVerifier.ParseAndVerifySdJwtVc(sdJwt)

	if err != nil {
		return nil, nil, err
	}

	attributes := map[string]any{}

	for key, value := range verifiedSdJwtVc.Claims.Object {
		if value.Type != sdjwtvc.Claim_String {
			//return nil, nil, fmt.Errorf("attribute value not a string: %v %v", key, value.Type)
			irma.Logger.Infof("attribute value not a string, skipping attribute: %v %v", key, value.Type)
			continue
		}
		valStr, ok := value.Value.(string)
		if !ok {
			return nil, nil, fmt.Errorf("attribute value not a string: %v", key)
		}
		attributes[key] = valStr
	}

	hash, err := CreateHashForSdJwtVc(verifiedSdJwtVc.VerifiableCredentialType, attributes)
	if err != nil {
		return nil, nil, err
	}

	if mode == eudi.StrictSdJwtVerificationMode {
		idComponents := strings.Split(verifiedSdJwtVc.VerifiableCredentialType, ".")
		if num := len(idComponents); num != 3 {
			return nil, nil, fmt.Errorf(
				"credential id expected to have exactly 3 components, separated by dots: %s",
				verifiedSdJwtVc.VerifiableCredentialType,
			)
		}
	}

	info := SdJwtVcMetadata{
		Hash:           hash,
		CredentialType: verifiedSdJwtVc.VerifiableCredentialType,
		SignedOn: irma.Timestamp(
			time.Unix(verifiedSdJwtVc.IssuedAt, 0),
		),
		Expires: irma.Timestamp(
			time.Unix(verifiedSdJwtVc.Expiry, 0),
		),
		Attributes: attributes,
	}

	return &info, verifiedSdJwtVc, nil
}

// VerifyAndStoreSdJwtVcKbs verifies the SD-JWTs and stores them in the SdJwtVcStorage.
// SD-JWTs that are batch-issued should all have the exact same credential info (issuer, id, signedOn, expires, etc.), otherwise they cannot be stored together correctly.
func VerifyAndStoreSdJwtVcKbs(sdJwtVcKbs []sdjwtvc.SdJwtVcKb, sdJwtVcStorage SdJwtVcStorage, holderVerifier *sdjwtvc.HolderVerificationProcessor, validateUniqueKeyBindingConfirmations bool, mode eudi.SdJwtVerificationMode) error {
	// TODO: this function should be private, but it's currently needed for both IRMA and OID4VCI. Once the storage is split between IRMA and OID4VCI, this function should be made private and moved to the appropriate package, and the OID4VCI code should not call the IRMA client code to store the SD-JWTs in the storage

	type credentialTuple struct {
		credInfo         SdJwtVcMetadata
		sdjwtvcInstances []sdjwtvc.SdJwtVc
	}

	credentialsMap := make(map[string]*credentialTuple)
	verifiedSdJwtVcs := make([]*sdjwtvc.VerifiedSdJwtVc, len(sdJwtVcKbs))

	for i, sdJwtVcKb := range sdJwtVcKbs {
		// TODO: check if the SD-JWT adheres to the requested credentials (e.g. if the credential ID and attributes etc match) ?
		// If we don't check this, issuers might issue SD-JWTs that do not match the corresponding IRMA credential
		credInfo, verifiedSdJwtVc, err := createCredentialInfoAndVerifiedSdJwtVc(sdJwtVcKb, holderVerifier, mode)
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
				sdjwtvcInstances: []sdjwtvc.SdJwtVc{verifiedSdJwtVc.GetRawSdJwtVc()},
			}
		} else {
			credentialsMap[key].sdjwtvcInstances = append(credentialsMap[key].sdjwtvcInstances, verifiedSdJwtVc.GetRawSdJwtVc())
		}

		verifiedSdJwtVcs[i] = verifiedSdJwtVc
	}

	// Check if every SD-JWT has a unique Key-Binding public key (cnf field)
	if validateUniqueKeyBindingConfirmations {
		err := sdjwtvc.CheckKeyBindingConfirmationUniqueness(verifiedSdJwtVcs)
		if err != nil {
			return fmt.Errorf("key binding confirmation uniqueness check failed: %v", err)
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
