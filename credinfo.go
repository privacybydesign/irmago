package irma

import (
	"math/big"
	"strings"
)

// CredentialInfo contains all information of an IRMA credential.
type CredentialInfo struct {
	CredentialTypeID string             // e.g., "irma-demo.RU.studentCard"
	Name             string             // e.g., "studentCard"
	IssuerID         string             // e.g., "RU"
	SchemeManagerID  string             // e.g., "irma-demo"
	Index            int                // This is the Index-th credential instance of this type
	SignedOn         Timestamp          // Unix timestamp
	Expires          Timestamp          // Unix timestamp
	Attributes       []TranslatedString // Human-readable rendered attributes
	Logo             string             // Path to logo on storage
	Hash             string             // SHA256 hash over the attributes
}

// A CredentialInfoList is a list of credentials (implements sort.Interface).
type CredentialInfoList []*CredentialInfo

func NewCredentialInfo(ints []*big.Int, conf *Configuration) *CredentialInfo {
	meta := MetadataFromInt(ints[0], conf)
	credtype := meta.CredentialType()
	if credtype == nil {
		return nil
	}

	attrs := make([]TranslatedString, len(credtype.Attributes))
	for i := range credtype.Attributes {
		bi := ints[i+1]
		if meta.Version() >= 3 { // has optional attributes
			if bi.Bit(0) == 0 { // attribute does not exist
				continue
			}
			bi = bi.Rsh(bi, 1)
		}
		val := string(bi.Bytes())
		attrs[i] = TranslatedString(map[string]string{"en": val, "nl": val})
	}

	id := credtype.Identifier()
	issid := id.IssuerIdentifier()
	return &CredentialInfo{
		CredentialTypeID: id.String(),
		Name:             id.Name(),
		IssuerID:         issid.Name(),
		SchemeManagerID:  issid.SchemeManagerIdentifier().String(),
		SignedOn:         Timestamp(meta.SigningDate()),
		Expires:          Timestamp(meta.Expiry()),
		Attributes:       attrs,
		Logo:             credtype.Logo(conf),
		Hash:             NewAttributeListFromInts(ints, conf).Hash(),
	}
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
	return strings.Compare(cl[i].Name, cl[j].Name) > 0
}
