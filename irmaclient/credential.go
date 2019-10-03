package irmaclient

import (
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/revocation"
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

// NonrevPrepare attempts to update the credential's nonrevocation witness from
// 1) the session request, and then 2) the revocation server if our witness is too far out of date.
// Returns whether or not the credential's nonrevocation state was updated. If so the caller should
// persist the updated credential to storage.
func (cred *credential) NonrevPrepare(conf *irma.Configuration, request irma.SessionRequest) (bool, error) {
	credtype := cred.CredentialType().Identifier()
	if !request.Base().RequestsRevocation(credtype) {
		return false, nil
	}

	revupdates := request.Base().RevocationUpdates[credtype]
	updated, err := cred.NonrevApplyUpdates(revupdates, conf.RevocationStorage)
	if err != nil {
		return updated, err
	}

	// TODO (in both branches): attach our newer updates to response
	if cred.NonRevocationWitness.Index >= revupdates[len(revupdates)-1].EndIndex {
		return updated, nil
	}

	// nonrevocation witness is still out of date after applying the updates from the request,
	// i.e. we were too far behind. Update from revocation server.
	revupdates, err = conf.RevocationStorage.GetUpdates(credtype, cred.NonRevocationWitness.Index+1)
	if err != nil {
		return updated, err
	}
	return cred.NonrevApplyUpdates(revupdates, conf.RevocationStorage)
}

// NonrevApplyUpdates updates the credential's nonrevocation witness using the specified messages,
// if they all verify and if their indices are ahead and adjacent to that of our witness.
func (cred *credential) NonrevApplyUpdates(messages []*irma.RevocationRecord, rs *irma.RevocationStorage) (bool, error) {
	var err error
	var pk *revocation.PublicKey
	oldindex := cred.NonRevocationWitness.Index
	for _, msg := range messages {
		if pk, err = rs.PublicKey(cred.CredentialType().IssuerIdentifier(), msg.PublicKeyIndex); err != nil {
			return false, err
		}
		if err = cred.NonRevocationWitness.Update(pk, msg.Message); err != nil {
			return false, err
		}
	}

	return cred.NonRevocationWitness.Index != oldindex, cred.NonrevPrepareCache()
}
