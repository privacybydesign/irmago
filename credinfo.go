package irma

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/credentials/irmago/internal/fs"
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

	attrs := make([]TranslatedString, len(credtype.Attributes))
	for i := range credtype.Attributes {
		val := string(ints[i+1].Bytes())
		attrs[i] = TranslatedString(map[string]string{"en": val, "nl": val})
	}

	path := fmt.Sprintf("%s/%s/%s/Issues/%s/logo.png", conf.path, credtype.SchemeManagerID, credtype.IssuerID, credtype.ID)
	exists, err := fs.PathExists(path)
	if err != nil {
		return nil
	}
	if !exists {
		path = ""
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
		Logo:             path,
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
