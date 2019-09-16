package irmaclient

import (
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/irmago"
)

// credential represents an IRMA credential, whose zeroth attribute
// is always the secret key and the first attribute the metadata attribute.
type credential struct {
	*gabi.Credential
	*irma.MetadataAttribute
	attrs *irma.AttributeList
}

func newCredential(gabicred *gabi.Credential, conf *irma.Configuration) (*credential, error) {
	meta := irma.MetadataFromInt(gabicred.Attributes[1], conf)
	cred := &credential{
		Credential:        gabicred,
		MetadataAttribute: meta,
	}

	if cred.CredentialType() == nil {
		// Unknown credtype, populate Pk field later
		return cred, nil
	}

	var err error
	cred.Pk, err = conf.PublicKey(meta.CredentialType().IssuerIdentifier(), cred.KeyCounter())
	if err != nil {
		return nil, err
	}
	return cred, nil
}

func (cred *credential) AttributeList() *irma.AttributeList {
	if cred.attrs == nil {
		cred.attrs = irma.NewAttributeListFromInts(cred.Credential.Attributes[1:], cred.MetadataAttribute.Conf)
	}
	return cred.attrs
}

func (cred *credential) PrepareNonrevocation(conf *irma.Configuration, request irma.SessionRequest) (bool, error) {
	// If the requestor wants us to include a nonrevocation proof,
	// it will have sent us the latest revocation update messages
	m := request.Base().RevocationUpdates
	credtype := cred.CredentialType().Identifier()
	if len(m) == 0 || len(m[credtype]) == 0 {
		return false, nil
	}

	revupdates := m[credtype]
	nonrev := len(revupdates) > 0
	if updated, err := conf.RevocationStorage.UpdateWitness(cred.NonRevocationWitness, revupdates, credtype.IssuerIdentifier()); err != nil {
		return false, err
	} else if updated {
		cred.DiscardRevocationCache()
	}

	// TODO (in both branches): attach our newer updates to response
	if nonrev && cred.NonRevocationWitness.Index >= revupdates[len(revupdates)-1].EndIndex {
		return nonrev, nil
	}

	// nonrevocation witness is still out of date after applying the updates from the request,
	// i.e. we were too far behind. Update from revocation server.
	revupdates, err := conf.RevocationStorage.RevocationGetUpdates(credtype, cred.NonRevocationWitness.Index+1)
	if err != nil {
		return nonrev, err
	}
	_, err = conf.RevocationStorage.UpdateWitness(cred.NonRevocationWitness, revupdates, credtype.IssuerIdentifier())
	return nonrev, err
}
