package irmago

import "github.com/mhe/gabi"

// Credential represents an IRMA credential, whose zeroth attribute
// is always the secret key and the first attribute the metadata attribute.
type Credential struct {
	*gabi.Credential
	*MetadataAttribute
}

func newCredential(gabicred *gabi.Credential) (cred *Credential) {
	cred = &Credential{}
	cred.Credential = gabicred
	cred.MetadataAttribute = MetadataFromInt(gabicred.Attributes[1])
	return
}
