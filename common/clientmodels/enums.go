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

// CredentialFormat identifies the format of a credential.
type CredentialFormat string

const (
	Format_SdJwtVc CredentialFormat = "dc+sd-jwt"
	Format_Idemix  CredentialFormat = "idemix"
	Format_Mdoc    CredentialFormat = "mso_mdoc"
)
