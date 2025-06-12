package credentials

type CredentialFormat string

const (
	Format_SdJwtVc        CredentialFormat = "dc+sd-jwt"
	Format_SdJwtVc_Legacy CredentialFormat = "vc+sd-jwt"
	Format_Yivi           CredentialFormat = "yivi"
)
