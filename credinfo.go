package irma

import (
	"math/big"
	"strings"
	"time"
)

// CredentialInfo contains all information of an IRMA credential.
type CredentialInfo struct {
	ID               string                                       // e.g., "studentCard"
	CredentialTypeID CredentialTypeIdentifier                     // e.g., "irma-demo.RU.studentCard"
	IssuerID         IssuerIdentifier                             // e.g., "irma-demo.RU"
	SchemeManagerID  SchemeManagerIdentifier                      // e.g., "irma-demo"
	Index            int                                          // This is the Index-th credential instance of this type
	SignedOn         Timestamp                                    // Unix timestamp
	Expires          Timestamp                                    // Unix timestamp
	Attributes       map[AttributeTypeIdentifier]TranslatedString // Human-readable rendered attributes
	Logo             string                                       // Path to logo on storage
	Hash             string                                       // SHA256 hash over the attributes
}

// A CredentialInfoList is a list of credentials (implements sort.Interface).
type CredentialInfoList []*CredentialInfo

func NewCredentialInfo(ints []*big.Int, conf *Configuration) *CredentialInfo {
	meta := MetadataFromInt(ints[0], conf)
	credtype := meta.CredentialType()
	if credtype == nil {
		return nil
	}

	attrs := NewAttributeListFromInts(ints, conf)
	id := credtype.Identifier()
	issid := id.IssuerIdentifier()
	return &CredentialInfo{
		CredentialTypeID: NewCredentialTypeIdentifier(id.String()),
		ID:               id.Name(),
		IssuerID:         issid,
		SchemeManagerID:  issid.SchemeManagerIdentifier(),
		SignedOn:         Timestamp(meta.SigningDate()),
		Expires:          Timestamp(meta.Expiry()),
		Attributes:       attrs.Map(conf),
		Logo:             credtype.Logo(conf),
		Hash:             attrs.Hash(),
	}
}

func (ci CredentialInfo) GetCredentialType(conf *Configuration) *CredentialType {
	return conf.CredentialTypes[ci.CredentialTypeID]
}

// Returns true if credential is expired at moment of calling this function
func (ci CredentialInfo) IsExpired() bool {
	return ci.Expires.Before(Timestamp(time.Now()))
}

// Len implements sort.Interface.
func (cl CredentialInfoList) Len() int {
	return len(cl)
}

// Swap implements sort.Interface.
func (cl CredentialInfoList) Swap(i, j int) {
	cl[i], cl[j] = cl[j], cl[i]
}

// Less implements sort.Interface.
func (cl CredentialInfoList) Less(i, j int) bool {
	// TODO Decide on sorting, and if it depends on a irmago.TranslatedString, allow language choosing
	return strings.Compare(cl[i].ID, cl[j].ID) > 0
}
