package irmaclient

import (
	"errors"

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
	base := request.Base()
	if !base.RequestsRevocation(credtype) {
		return false, nil
	}

	if err := base.RevocationConsistent(); err != nil {
		return false, err
	}

	// first try to update witness by applying the revocation update messages attached to the session request
	keys := irma.RevocationKeys{Conf: conf}
	revupdates := base.RevocationUpdates[credtype]
	updated, err := cred.NonrevApplyUpdates(revupdates, keys)
	if err != nil {
		return updated, err
	}
	if cred.NonRevocationWitness.Accumulator.Index >= revupdates[len(revupdates)-1].EndIndex {
		return updated, nil
	}

	// nonrevocation witness is still out of date after applying the updates from the request:
	// we were too far behind. Update from revocation server.
	revupdates, err = irma.RevocationClient{Conf: conf}.FetchRevocationRecords(credtype, cred.NonRevocationWitness.Accumulator.Index+1)
	if err != nil {
		return updated, err
	}
	return cred.NonrevApplyUpdates(revupdates, keys)
}

// NonrevApplyUpdates updates the credential's nonrevocation witness using the specified messages,
// if they all verify and if their indices are ahead and adjacent to that of our witness.
func (cred *credential) NonrevApplyUpdates(messages []*irma.RevocationRecord, keys irma.RevocationKeys) (bool, error) {
	oldindex := cred.NonRevocationWitness.Accumulator.Index

	var err error
	var pk *revocation.PublicKey
	for _, record := range messages {
		if cred.CredentialType().IssuerIdentifier() != record.CredType.IssuerIdentifier() {
			return false, errors.New("cannot apply revocation record of other credential type")
		}
		if pk, err = keys.PublicKey(cred.CredentialType().IssuerIdentifier(), record.PublicKeyIndex); err != nil {
			return false, err
		}
		if err = cred.NonRevocationWitness.Update(pk, &record.Record); err != nil {
			return false, err
		}
	}

	return cred.NonRevocationWitness.Accumulator.Index != oldindex, nil
}
