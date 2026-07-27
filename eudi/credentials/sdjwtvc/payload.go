package sdjwtvc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
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
	RegisteredClaims

	// REQUIRED: the type of verifiable credential
	VerifiableCredentialType string

	// OPTIONAL: The information on how to read the status of the verifiable credential
	// (draft-ietf-oauth-status-list-15 §5.1).
	Status *statuslist.StatusClaim
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
