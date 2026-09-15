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
