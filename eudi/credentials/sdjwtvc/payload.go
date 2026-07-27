package sdjwtvc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

// IssuerSignedJwtPayload_ToJson converts the payload of the issuer signed jwt to json,
// taking into account some sdjwtvc specific rules
func IssuerSignedJwtPayload_ToJson(payload IssuerSignedJwtPayload) (string, error) {
	jsonValues := make(map[string]any)

	if !strings.HasPrefix(payload.Issuer, "https://") {
		return "", fmt.Errorf("issuer (`iss`) field is required to be an https link, but is %s", payload.Issuer)
	}

	if len(payload.Sd) != 0 {
		jsonValues[Key_Sd] = payload.Sd
	}

	if payload.SdAlg != "" {
		jsonValues[Key_SdAlg] = payload.SdAlg
	}

	if payload.Confirm != nil && payload.Confirm.Jwk != nil {
		jsonValues[Key_Confirmationkey] = payload.Confirm
	}

	if payload.Status != nil && payload.Status.StatusList != nil {
		jsonValues[Key_Status] = payload.Status
	}

	jsonValues[Key_VerifiableCredentialType] = payload.VerifiableCredentialType
	jsonValues[Key_ExpiryTime] = payload.Expiry
	jsonValues[Key_IssuedAt] = payload.IssuedAt
	jsonValues[Key_Subject] = payload.Subject
	jsonValues[Key_Issuer] = payload.Issuer

	jsonBytes, err := json.Marshal(jsonValues)
	return string(jsonBytes), err
}

// IssuerSignedJwtPayload is a representation of the payload of the issuer signed jwt part of an SD-JWT VC
type IssuerSignedJwtPayload struct {
	// OPTIONAL: The identifier of the Subject of the Verifiable Credential.
	// The Issuer MAY use it to provide the Subject identifier known by the Issuer.
	// There is no requirement for a binding to exist between sub and cnf claims
	Subject string

	// REQUIRED: the type of verifiable credential
	VerifiableCredentialType string

	// OPTIONAL. As defined in Section 4.1.1 of [RFC7519] this claim explicitly indicates the Issuer of the Verifiable Credential
	// when it is not conveyed by other means (e.g., the subject of the end-entity certificate of an x5c header)
	Issuer string

	// OPTIONAL: list of hashed -> base64url encoded disclosures
	// hashing algorithm is defined by `_sd_alg` field
	// is allowed to be omitted, and is not allowed to be empty (should be omitted in that case)
	Sd []HashedDisclosure

	// OPTIONAL: hashing algorithm to be used for the disclosure hashes in `_sd` and the hash over
	// the complete SD-JWT VC that can be found in the key binding JWT
	SdAlg iana.HashingAlgorithm

	// OPTIONAL: Public key (JWK or kid with did:jwk method) of the holder, which can be used to verify the key binding jwt
	Confirm *CnfField

	// OPTIONAL: The information on how to read the status of the verifiable credential
	// (draft-ietf-oauth-status-list-15 §5.1).
	Status *statuslist.StatusClaim

	// OPTIONAL: expiry time, must not be accepted after this moment
	Expiry *int64

	// OPTIONAL: time of issuance
	IssuedAt *int64

	// OPTIONAL: The time before which the verifiable credential MUST NOT be accepted before validating
	NotBefore *int64
}

// SdJwtVc_IssuerRepresentation is a representation of the SD-JWT VC that can be used by the issuer or holder to issue and disclose
type SdJwtVc_IssuerRepresentation struct {
	IssuerSignedJwt IssuerSignedJwt
	Disclosures     []DisclosureContent
}

func CreateIssuerSignedJwt(payload IssuerSignedJwtPayload, jwtCreator JwtCreator) (IssuerSignedJwt, error) {
	json, err := IssuerSignedJwtPayload_ToJson(payload)
	if err != nil {
		return "", err
	}

	customHeaders := map[string]any{
		"typ": SdJwtVcTyp,
	}
	jwt, err := jwtCreator.CreateSignedJwt(customHeaders, json)
	if err != nil {
		return "", err
	}
	return IssuerSignedJwt(jwt), nil
}
