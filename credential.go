package irmago

import (
	"strings"

	"math/big"

	"fmt"

	"github.com/mhe/gabi"
)

// credential represents an IRMA credential, whose zeroth attribute
// is always the secret key and the first attribute the metadata attribute.
type credential struct {
	*gabi.Credential
	*MetadataAttribute
	attrs *AttributeList
}

// CredentialInfo contains all information of an IRMA credential.
type CredentialInfo struct {
	ID              string             // e.g., "irma-demo.RU.studentCard"
	Name            string             // e.g., "studentCard"
	IssuerID        string             // e.g., "RU"
	SchemeManagerID string             // e.g., "irma-demo"
	Index           int                // This is the Index-th credential instance of this type
	SignedOn        Timestamp          // Unix timestamp
	Expires         Timestamp          // Unix timestamp
	Attributes      []TranslatedString // Human-readable rendered attributes
	Logo            string             // Path to logo on storage
	Hash            string             // SHA256 hash over the attributes
}

// A CredentialInfoList is a list of credentials (implements sort.Interface).
type CredentialInfoList []*CredentialInfo

func NewCredentialInfo(ints []*big.Int, store *ConfigurationStore) *CredentialInfo {
	meta := MetadataFromInt(ints[0], store)
	credtype := meta.CredentialType()

	attrs := make([]TranslatedString, len(credtype.Attributes))
	for i := range credtype.Attributes {
		val := string(ints[i+1].Bytes())
		attrs[i] = TranslatedString(map[string]string{"en": val, "nl": val})
	}

	path := fmt.Sprintf("%s/%s/%s/Issues/%s/logo.png", store.path, credtype.SchemeManagerID, credtype.IssuerID, credtype.ID)
	exists, err := PathExists(path)
	if err != nil {
		return nil
	}
	if !exists {
		path = ""
	}

	return &CredentialInfo{
		ID:         credtype.Identifier().String(),
		SignedOn:   Timestamp(meta.SigningDate()),
		Expires:    Timestamp(meta.Expiry()),
		Attributes: attrs,
		Logo:       path,
		Hash:       NewAttributeListFromInts(ints, store).hash(),
	}
}

func newCredential(gabicred *gabi.Credential, store *ConfigurationStore) (*credential, error) {
	meta := MetadataFromInt(gabicred.Attributes[1], store)
	cred := &credential{
		Credential:        gabicred,
		MetadataAttribute: meta,
	}
	var err error
	cred.Pk, err = store.PublicKey(meta.CredentialType().IssuerIdentifier(), cred.KeyCounter())
	if err != nil {
		return nil, err
	}
	return cred, nil
}

func (cred *credential) AttributeList() *AttributeList {
	if cred.attrs == nil {
		cred.attrs = NewAttributeListFromInts(cred.Credential.Attributes[1:], cred.MetadataAttribute.store)
	}
	return cred.attrs
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
	return strings.Compare(cl[i].Name, cl[j].Name) > 0
}
