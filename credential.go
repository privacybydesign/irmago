package irmago

import "github.com/mhe/gabi"

// credential represents an IRMA credential, whose zeroth attribute
// is always the secret key and the first attribute the metadata attribute.
type credential struct {
	*gabi.Credential
	*MetadataAttribute
}

func newCredential(gabicred *gabi.Credential) (cred *credential) {
	cred = &credential{}
	cred.Credential = gabicred
	cred.MetadataAttribute = MetadataFromInt(gabicred.Attributes[1])
	cred.Pk = MetaStore.PublicKey(cred.CredentialType().IssuerIdentifier(), cred.KeyCounter())
	return
}
