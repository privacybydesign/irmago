package irmaclient

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/irma"
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

	return sdjwtvc.CreateUrlEncodedHash(iana.SHA256, hashContent)
}

func createCredentialInfoAndVerifiedSdJwtVc(sdJwt sdjwtvc.SdJwtVcKb, holderVerifier *sdjwtvc.HolderVerificationProcessor, mode eudi.SdJwtVerificationMode) (*SdJwtVcMetadata, *sdjwtvc.HolderSdJwt, error) {
	verifiedSdJwtVc, err := holderVerifier.ParseAndVerifySdJwtVc(sdJwt)

	if err != nil {
		return nil, nil, err
	}

	attributes := map[string]any{}
	for _, d := range verifiedSdJwtVc.Disclosures {
		attributes[d.Key] = d.Value
	}

	hash, err := CreateHashForSdJwtVc(verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType, attributes)
	if err != nil {
		return nil, nil, err
	}

	if mode == eudi.StrictSdJwtVerificationMode {
		idComponents := strings.Split(verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType, ".")
		if num := len(idComponents); num != 3 {
			return nil, nil, fmt.Errorf(
				"credential id expected to have exactly 3 components, separated by dots: %s",
				verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType,
			)
		}
	}

	info := SdJwtVcMetadata{
		Hash:           hash,
		CredentialType: verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType,
		SignedOn: irma.Timestamp(
			time.Unix(verifiedSdJwtVc.IssuerSignedJwtPayload.IssuedAt, 0),
		),
		Expires: irma.Timestamp(
			time.Unix(verifiedSdJwtVc.IssuerSignedJwtPayload.Expiry, 0),
		),
		Attributes: attributes,
	}
	return &info, &verifiedSdJwtVc, nil
}

func ToTranslateableList[T openid4vci.Display | openid4vci.CredentialDisplay | openid4vci.CredentialIssuerDisplay](displays []T) []openid4vci.Translateable {
	translations := make([]openid4vci.Translateable, len(displays))
	for i, display := range displays {
		translations[i] = any(display).(openid4vci.Translateable)
	}
	return translations
}

func convertDisplayToTranslatedString(displays []openid4vci.Translateable) irma.TranslatedString {
	result := irma.TranslatedString{}
	for _, display := range displays {
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
func verifyAndStoreSdJwtVcKbs(sdJwtVcKbs []sdjwtvc.SdJwtVcKb, sdJwtVcStorage SdJwtVcStorage, holderVerifier *sdjwtvc.HolderVerificationProcessor, validateUniqueKeyBindingConfirmations bool, mode eudi.SdJwtVerificationMode) error {
	// TODO: check if all SD-JWTs have a unique Key-Binding public key (cnf field), if not, the SD-JWTs should be rejected

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
		for _, verifiedSdJwtVc := range verifiedSdJwtVcs {
			cnf := verifiedSdJwtVc.IssuerSignedJwtPayload.Confirm
			if cnf != nil {
				duplicateCryptographicKey := slices.ContainsFunc(verifiedSdJwtVcs, func(otherSdJwtVc *sdjwtvc.VerifiedSdJwtVc) bool {
					return otherSdJwtVc != verifiedSdJwtVc &&
						otherSdJwtVc.IssuerSignedJwtPayload.Confirm != nil &&
						jwk.Equal(otherSdJwtVc.IssuerSignedJwtPayload.Confirm.Jwk, cnf.Jwk)
				})

				if duplicateCryptographicKey {
					return fmt.Errorf("duplicate cryptographic key binding confirmation found for SD-JWT with vct %q", verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType)
				}
			}
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

// isUniqueStrings checks if all strings in the slice are unique (case-sensitive or insensitive)
func isUniqueStrings(slice []string, caseInsensitive bool) bool {
	seen := make(map[string]bool)

	for _, str := range slice {
		// Normalize case if case-insensitive check is required
		key := str
		if caseInsensitive {
			key = strings.ToLower(str)
		}

		if seen[key] {
			return false // Duplicate found
		}
		seen[key] = true
	}
	return true
}
