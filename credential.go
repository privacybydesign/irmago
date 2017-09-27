package irmago

import (
	"strings"

	"math/big"

	"github.com/mhe/gabi"
)

// credential represents an IRMA credential, whose zeroth attribute
// is always the secret key and the first attribute the metadata attribute.
type credential struct {
	*gabi.Credential
	*MetadataAttribute
}

// A Credential contains all information of an IRMA credential.
type Credential struct {
	ID            string             // e.g., "irma-demo.RU.studentCard"
	SignedOn      Timestamp          // Unix timestamp
	Expires       Timestamp          // Unix timestamp
	Type          *CredentialType    // Credential information from MetaStore
	Issuer        *Issuer            // Issuer information from MetaStore
	SchemeManager *SchemeManager     // Scheme manager information from MetaStore
	Attributes    []TranslatedString // Human-readable rendered attributes
	Logo          string             // Path to logo on storage
}

// A CredentialList is a list of credentials (implements sort.Interface).
type CredentialList []*Credential

func NewCredential(ints []*big.Int) *Credential {
	meta := MetadataFromInt(ints[0])
	credtype := meta.CredentialType()
	issid := credtype.IssuerIdentifier()

	attrs := make([]TranslatedString, len(credtype.Attributes))
	for i := range credtype.Attributes {
		val := string(ints[i+1].Bytes())
		attrs[i] = TranslatedString(map[string]string{"en": val, "nl": val})
	}

	return &Credential{
		ID:            credtype.Identifier().String(),
		SignedOn:      Timestamp(meta.SigningDate()),
		Expires:       Timestamp(meta.Expiry()),
		Type:          credtype,
		Issuer:        MetaStore.Issuers[issid],
		SchemeManager: MetaStore.SchemeManagers[issid.SchemeManagerIdentifier()],
		Attributes:    attrs,
		Logo:          "", // TODO
	}
}

func newCredential(gabicred *gabi.Credential) (cred *credential) {
	meta := MetadataFromInt(gabicred.Attributes[1])
	cred = &credential{
		Credential:        gabicred,
		MetadataAttribute: meta,
	}
	cred.Pk = MetaStore.PublicKey(meta.CredentialType().IssuerIdentifier(), cred.KeyCounter())
	return
}

// Len implements sort.Interface.
func (cl CredentialList) Len() int {
	return len(cl)
}

// Swap implements sort.Interface.
func (cl CredentialList) Swap(i, j int) {
	cl[i], cl[j] = cl[j], cl[i]
}

// Less implements sort.Interface.
func (cl CredentialList) Less(i, j int) bool {
	// TODO Decide on sorting, and if it depends on a TranslatedString, allow language choosing
	return strings.Compare(cl[i].Type.Name["en"], cl[j].Type.Name["en"]) > 0
}
