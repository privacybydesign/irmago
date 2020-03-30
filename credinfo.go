package irma

import (
	"fmt"
	"strings"
	"time"

	"github.com/privacybydesign/gabi/big"
)

// CredentialInfo contains all information of an IRMA credential.
type CredentialInfo struct {
	ID              string                                       // e.g., "studentCard"
	IssuerID        string                                       // e.g., "RU"
	SchemeManagerID string                                       // e.g., "irma-demo"
	SignedOn        Timestamp                                    // Unix timestamp
	Expires         Timestamp                                    // Unix timestamp
	Attributes      map[AttributeTypeIdentifier]TranslatedString // Human-readable rendered attributes
	Hash            string                                       // SHA256 hash over the attributes
	Revoked         bool                                         // If the credential has been revoked
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
		ID:              id.Name(),
		IssuerID:        issid.Name(),
		SchemeManagerID: issid.SchemeManagerIdentifier().Name(),
		SignedOn:        Timestamp(meta.SigningDate()),
		Expires:         Timestamp(meta.Expiry()),
		Attributes:      attrs.Map(conf),
		Hash:            attrs.Hash(),
	}
}

func (ci CredentialInfo) GetCredentialType(conf *Configuration) *CredentialType {
	return conf.CredentialTypes[NewCredentialTypeIdentifier(fmt.Sprintf("%s.%s.%s", ci.SchemeManagerID, ci.IssuerID, ci.ID))]
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
