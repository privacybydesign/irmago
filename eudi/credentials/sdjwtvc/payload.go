package sdjwtvc

import (
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// IssuerSignedJwtPayload is a representation of the payload of the issuer signed jwt part of an SD-JWT VC
type IssuerSignedJwtPayload struct {
	sdjwt.RegisteredClaims

	// REQUIRED: the type of verifiable credential
	VerifiableCredentialType string

	// OPTIONAL: The information on how to read the status of the verifiable credential
	// (draft-ietf-oauth-status-list-15 §5.1).
	Status *statuslist.StatusClaim
}
