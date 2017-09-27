package irmago

import (
	"strings"

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
