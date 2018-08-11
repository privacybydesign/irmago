package irmaserver

type Error struct {
	Type        ErrorType `json:"error"`
	Status      int       `json:"status"`
	Description string    `json:"description"`
}

type ErrorType string

var (
	ErrorMalformedIssuerRequest    Error = Error{Type: "MALFORMED_ISSUER_REQUEST", Status: 400, Description: "Malformed issuer request"}
	ErrorInvalidTimestamp          Error = Error{Type: "INVALID_TIMESTAMP", Status: 400, Description: "Timestamp was not an epoch boundary"}
	ErrorIssuingDisabled           Error = Error{Type: "ISSUING_DISABLED", Status: 403, Description: "This server does not support issuing"}
	ErrorMalformedVerifierRequest  Error = Error{Type: "MALFORMED_VERIFIER_REQUEST", Status: 400, Description: "Malformed verification request"}
	ErrorMalformedSignatureRequest Error = Error{Type: "MALFORMED_SIGNATURE_REQUEST", Status: 400, Description: "Malformed signature request"}
	ErrorInvalidProofs             Error = Error{Type: "INVALID_PROOFS", Status: 400, Description: "Invalid secret key commitments and/or disclosure proofs"}
	ErrorAttributesMissing         Error = Error{Type: "ATTRIBUTES_MISSING", Status: 400, Description: "Not all requested-for attributes were present"}
	ErrorAttributesExpired         Error = Error{Type: "ATTRIBUTES_EXPIRED", Status: 400, Description: "Disclosed attributes were expired"}
	ErrorUnexpectedRequest         Error = Error{Type: "UNEXPECTED_REQUEST", Status: 403, Description: "Unexpected request in this state"}
	ErrorUnknownPublicKey          Error = Error{Type: "UNKNOWN_PUBLIC_KEY", Status: 403, Description: "Attributes were not valid against a known public key"}
	ErrorKeyshareProofMissing      Error = Error{Type: "KEYSHARE_PROOF_MISSING", Status: 403, Description: "ProofP object from a keyshare server missing"}
	ErrorUnauthorized              Error = Error{Type: "UNAUTHORIZED", Status: 403, Description: "You are not authorized to issue or verify this attribute"}
	ErrorAttributesWrong           Error = Error{Type: "ATTRIBUTES_WRONG", Status: 400, Description: "Specified attribute(s) do not belong to this credential type or missing attributes"}
	ErrorSessionUnknown            Error = Error{Type: "SESSION_UNKNOWN", Status: 400, Description: "Unknown or expired session"}
	ErrorSessionTokenMalformed     Error = Error{Type: "SESSION_TOKEN_MALFORMED", Status: 400, Description: "Malformed session token"}
	ErrorMalformedInput            Error = Error{Type: "MALFORMED_INPUT", Status: 400, Description: "Input could not be parsed"}
	ErrorCannotIssue               Error = Error{Type: "CANNOT_ISSUE", Status: 500, Description: "Cannot issue this credential"}
	ErrorIssuanceFailed            Error = Error{Type: "ISSUANCE_FAILED", Status: 500, Description: "Failed to create credential(s)"}
	ErrorUnknown                   Error = Error{Type: "EXCEPTION", Status: 500, Description: "Encountered unexpected problem"}

	ErrorInvalidRequest  Error = Error{Type: "INVALID_REQUEST", Status: 400, Description: "Invalid HTTP request"}
	ErrorProtocolVersion Error = Error{Type: "PROTOCOL_VERSION", Status: 400, Description: "Protocol version negotiation failed"}
)
