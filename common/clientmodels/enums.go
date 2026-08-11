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
//
// Adding a constant here is a breaking change for the Yivi app until irmamobile
// is updated to match. irmamobile mirrors this list as the Dart enum
// CredentialFormat (yivi_core/lib/src/models/log_entry.dart), and the decoders
// json_serializable generates for it take no unknownValue: an unlisted string
// throws out of fromJson and takes the whole event payload with it, not just
// the one field. So a format the app does not know is not a credential it skips,
// it is a screen that fails to build.
type CredentialFormat string

const (
	Format_SdJwtVc CredentialFormat = "dc+sd-jwt"
	Format_Idemix  CredentialFormat = "idemix"
	Format_MsoMdoc CredentialFormat = "mso_mdoc"
)
