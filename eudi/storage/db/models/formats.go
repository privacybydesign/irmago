package models

// CredentialFormat represents the credential format identifier as defined in the OID4VCI spec.
type CredentialFormat string

const (
	CredentialFormatSdJwtVc CredentialFormat = "dc+sd-jwt"
	// CredentialFormatSdJwtVcdm is an SD-JWT-secured W3C VCDM 2.0 credential
	// (VC-JOSE-COSE §3.2). It has its own tables (VcdmBatch).
	CredentialFormatSdJwtVcdm CredentialFormat = "vc+sd-jwt"
	CredentialFormatMsoMdoc   CredentialFormat = "mso_mdoc"
)
