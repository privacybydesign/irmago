package server

// Error represents an error that occurred during an IRMA sessions.
type Error struct {
	Type        ErrorType `json:"error"`
	Status      int       `json:"status"`
	Description string    `json:"description"`
}

type ErrorType string

// General errors
var (
	ErrorInvalidTimestamp          Error = Error{Type: "INVALID_TIMESTAMP", Status: 400, Description: "Timestamp was not an epoch boundary"}
	ErrorIssuingDisabled           Error = Error{Type: "ISSUING_DISABLED", Status: 403, Description: "This server does not support issuing"}
	ErrorMalformedVerifierRequest  Error = Error{Type: "MALFORMED_VERIFIER_REQUEST", Status: 400, Description: "Malformed verification request"}
	ErrorMalformedSignatureRequest Error = Error{Type: "MALFORMED_SIGNATURE_REQUEST", Status: 400, Description: "Malformed signature request"}
	ErrorMalformedIssuerRequest    Error = Error{Type: "MALFORMED_ISSUER_REQUEST", Status: 400, Description: "Malformed issuer request"}
	ErrorUnauthorized              Error = Error{Type: "UNAUTHORIZED", Status: 403, Description: "You are not authorized to issue or verify this attribute"}
	ErrorAttributesWrong           Error = Error{Type: "ATTRIBUTES_WRONG", Status: 400, Description: "Specified attribute(s) do not belong to this credential type or missing attributes"}
	ErrorCannotIssue               Error = Error{Type: "CANNOT_ISSUE", Status: 500, Description: "Cannot issue this credential"}

	ErrorIrmaUnauthorized     Error = Error{Type: "UNAUTHORIZED", Status: 403, Description: "You are not authorized to access the session"}
	ErrorPairingRequired      Error = Error{Type: "PAIRING_REQUIRED", Status: 403, Description: "Pairing is required first"}
	ErrorIssuanceFailed       Error = Error{Type: "ISSUANCE_FAILED", Status: 500, Description: "Failed to create credential(s)"}
	ErrorInvalidProofs        Error = Error{Type: "INVALID_PROOFS", Status: 400, Description: "Invalid secret key commitments and/or disclosure proofs"}
	ErrorAttributesMissing    Error = Error{Type: "ATTRIBUTES_MISSING", Status: 400, Description: "Not all requested-for attributes were present"}
	ErrorAttributesExpired    Error = Error{Type: "ATTRIBUTES_EXPIRED", Status: 400, Description: "Disclosed attributes were expired"}
	ErrorUnexpectedRequest    Error = Error{Type: "UNEXPECTED_REQUEST", Status: 403, Description: "Unexpected request in this state"}
	ErrorUnknownPublicKey     Error = Error{Type: "UNKNOWN_PUBLIC_KEY", Status: 403, Description: "Attributes were not valid against a known public key"}
	ErrorKeyshareProofMissing Error = Error{Type: "KEYSHARE_PROOF_MISSING", Status: 403, Description: "ProofP object from a keyshare server missing"}
	ErrorSessionUnknown       Error = Error{Type: "SESSION_UNKNOWN", Status: 400, Description: "Unknown or expired session"}
	ErrorMalformedInput       Error = Error{Type: "MALFORMED_INPUT", Status: 400, Description: "Input could not be parsed"}
	ErrorUnknown              Error = Error{Type: "EXCEPTION", Status: 500, Description: "Encountered unexpected problem"}
	ErrorNextSession          Error = Error{Type: "NEXT_SESSION", Status: 500, Description: "Error starting next session"}
	ErrorRevocation           Error = Error{Type: "REVOCATION", Status: 500, Description: "Revocation error"}
	ErrorUnknownRevocationKey Error = Error{Type: "UNKNOWN_REVOCATION_KEY", Status: 404, Description: "No issuance records correspond to the given revocationKey"}

	ErrorUnsupported     Error = Error{Type: "UNSUPPORTED", Status: 501, Description: "Unsupported by this server"}
	ErrorInvalidRequest  Error = Error{Type: "INVALID_REQUEST", Status: 400, Description: "Invalid HTTP request"}
	ErrorProtocolVersion Error = Error{Type: "PROTOCOL_VERSION", Status: 400, Description: "Protocol version negotiation failed"}
	ErrorInvalidToken    Error = Error{Type: "INVALID_TOKEN", Status: 403, Description: "Provided token is unknown or invalid"}
	ErrorInternal        Error = Error{Type: "INTERNAL_ERROR", Status: 500, Description: "Internal server error"}
	ErrorRevalidateEmail Error = Error{Type: "REVALIDATE_EMAIL", Status: 500, Description: "Invalid email address is scheduled for revalidation"}
)

// Keyshare errors
var (
	ErrorUserNotRegistered = Error{Type: "USER_NOT_REGISTERED", Status: 403, Description: "User is not yet fully registered"}
	ErrorInvalidJWT        = Error{Type: "UNAUTHORIZED", Status: 403, Description: "Invalid or expired jwt provided"}
	ErrorInvalidEmail      = Error{Type: "INVALID_EMAIL", Status: 400, Description: "Invalid email address"}
	ErrorTooManyRequests   = Error{Type: "TOO_MANY_REQUESTS", Status: 429, Description: "Too many requests"}
)
