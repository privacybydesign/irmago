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

// CredentialInfo contains all information of an IRMA credential.
type CredentialInfo struct {
	ID            string             // e.g., "irma-demo.RU.studentCard"
	SignedOn      Timestamp          // Unix timestamp
	Expires       Timestamp          // Unix timestamp
	Type          *CredentialType    // Credential information from ConfigurationStore
	Issuer        *Issuer            // Issuer information from ConfigurationStore
	SchemeManager *SchemeManager     // Scheme manager information from ConfigurationStore
	Attributes    []TranslatedString // Human-readable rendered attributes
	Logo          string             // Path to logo on storage
}

// A CredentialInfoList is a list of credentials (implements sort.Interface).
type CredentialInfoList []*CredentialInfo

func NewCredentialInfo(ints []*big.Int, store *ConfigurationStore) *CredentialInfo {
	meta := MetadataFromInt(ints[0], store)
	credtype := meta.CredentialType()
	issid := credtype.IssuerIdentifier()

	attrs := make([]TranslatedString, len(credtype.Attributes))
	for i := range credtype.Attributes {
		val := string(ints[i+1].Bytes())
		attrs[i] = TranslatedString(map[string]string{"en": val, "nl": val})
	}

	return &CredentialInfo{
		ID:            credtype.Identifier().String(),
		SignedOn:      Timestamp(meta.SigningDate()),
		Expires:       Timestamp(meta.Expiry()),
		Type:          credtype,
		Issuer:        store.Issuers[issid],
		SchemeManager: store.SchemeManagers[issid.SchemeManagerIdentifier()],
		Attributes:    attrs,
		Logo:          "", // TODO
	}
}

func newCredential(gabicred *gabi.Credential, store *ConfigurationStore) (cred *credential) {
	meta := MetadataFromInt(gabicred.Attributes[1], store)
	cred = &credential{
		Credential:        gabicred,
		MetadataAttribute: meta,
	}
	cred.Pk = store.PublicKey(meta.CredentialType().IssuerIdentifier(), cred.KeyCounter())
	return
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
	// TODO Decide on sorting, and if it depends on a TranslatedString, allow language choosing
	return strings.Compare(cl[i].Type.Name["en"], cl[j].Type.Name["en"]) > 0
}
