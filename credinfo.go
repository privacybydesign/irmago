package irma

import (
	"fmt"
	"strings"
	"time"
)

// CredentialInfo contains all information of an IRMA credential.
type CredentialInfo struct {
	ID                  string                                       // e.g., "studentCard"
	IssuerID            string                                       // e.g., "RU"
	SchemeManagerID     string                                       // e.g., "irma-demo"
	SignedOn            Timestamp                                    // Unix timestamp
	Expires             Timestamp                                    // Unix timestamp
	Attributes          map[AttributeTypeIdentifier]TranslatedString // Human-readable rendered attributes
	Hash                string                                       // SHA256 hash over the attributes
	Revoked             bool                                         // If the credential has been revoked
	RevocationSupported bool                                         // If the credential supports creating nonrevocation proofs
	CredentialFormat    string                                       // the credential format, e.g. "idemix" or "dc+sd-jwt"
}

// A CredentialInfoList is a list of credentials (implements sort.Interface).
type CredentialInfoList []*CredentialInfo

func (ci CredentialInfo) GetCredentialType(conf *Configuration) *CredentialType {
	return conf.CredentialTypes[ci.Identifier()]
}

// IsExpired returns true if credential is expired at moment of calling this function
func (ci CredentialInfo) IsExpired() bool {
	return ci.Expires.Before(Timestamp(time.Now()))
}

func (ci CredentialInfo) Identifier() CredentialTypeIdentifier {
	return NewCredentialTypeIdentifier(fmt.Sprintf("%s.%s.%s", ci.SchemeManagerID, ci.IssuerID, ci.ID))
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
