package clientmodels

// Protocol identifies the protocol used for a session.
type Protocol string

const (
	Protocol_Irma       Protocol = "irma"
	Protocol_OpenID4VP  Protocol = "openid4vp"
	Protocol_OpenID4VCI Protocol = "openid4vci"
)

// LogType identifies the type of a log entry.
type LogType string

const (
	LogType_Disclosure        LogType = "disclosure"
	LogType_Issuance          LogType = "issuance"
	LogType_Signature         LogType = "signature"
	LogType_CredentialRemoval LogType = "removal"
)

// SessionWarning identifies a non-blocking warning about a session that the
// app can surface to the user. The app decides the user-facing wording.
type SessionWarning string

const (
	// The verifier's did:web domain is DNSSEC-signed, but validation failed:
	// DNS answers for the domain may have been tampered with, so the
	// connection to the verifier may not be trustworthy.
	SessionWarning_DidWebDnssecInvalid SessionWarning = "did_web_dnssec_invalid"
	// The verifier's did:web domain is not protected by DNSSEC.
	SessionWarning_DidWebDnssecMissing SessionWarning = "did_web_dnssec_missing"
)

// CredentialFormat identifies the format of a credential.
type CredentialFormat string

const (
	Format_SdJwtVc CredentialFormat = "dc+sd-jwt"
	Format_Idemix  CredentialFormat = "idemix"
)
