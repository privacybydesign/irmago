package clientmodels

// Protocol identifies the protocol used for a session.
type Protocol string

const (
	Protocol_Irma       Protocol = "irma"
	Protocol_OpenID4VP  Protocol = "openid4vp"
	Protocol_OpenID4VCI Protocol = "openid4vci"
	// Protocol_ISO18013_5 is a presentation carried by ISO/IEC 18013-5 itself —
	// a DeviceRequest in and a DeviceResponse out — rather than by OpenID4VP as
	// the transports above are. Today that means the Digital Credentials API's
	// org-iso-mdoc protocol; device retrieval over BLE would be the same value,
	// since what the app distinguishes here is the exchange and not its carrier.
	//
	// Unused until a session exists to report one. Kept because the name is a
	// property of the standard rather than of any implementation of it.
	Protocol_ISO18013_5 Protocol = "iso18013-5"
)

// LogType identifies the type of a log entry.
type LogType string

const (
	LogType_Disclosure        LogType = "disclosure"
	LogType_Issuance          LogType = "issuance"
	LogType_Signature         LogType = "signature"
	LogType_CredentialRemoval LogType = "removal"
)

// CredentialFormat identifies the format of a credential.
type CredentialFormat string

const (
	Format_SdJwtVc CredentialFormat = "dc+sd-jwt"
	Format_Idemix  CredentialFormat = "idemix"
	Format_MsoMdoc CredentialFormat = "mso_mdoc"
)
