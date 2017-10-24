package irmaclient

import (
	"github.com/credentials/irmago"
	"github.com/mhe/gabi"
)

// credential represents an IRMA credential, whose zeroth attribute
// is always the secret key and the first attribute the metadata attribute.
type credential struct {
	*gabi.Credential
	*irmago.MetadataAttribute
	attrs *irmago.AttributeList
}

func newCredential(gabicred *gabi.Credential, store *irmago.ConfigurationStore) (*credential, error) {
	meta := irmago.MetadataFromInt(gabicred.Attributes[1], store)
	cred := &credential{
		Credential:        gabicred,
		MetadataAttribute: meta,
	}
	var err error
	cred.Pk, err = store.PublicKey(meta.CredentialType().IssuerIdentifier(), cred.KeyCounter())
	if err != nil {
		return nil, err
	}
	return cred, nil
}

func (cred *credential) AttributeList() *irmago.AttributeList {
	if cred.attrs == nil {
		cred.attrs = irmago.NewAttributeListFromInts(cred.Credential.Attributes[1:], cred.MetadataAttribute.Store)
	}
	return cred.attrs
}
