package irma

import (
	"math/big"
	"strings"
	"github.com/privacybydesign/irmago/internal/fs"
	"time"
)

// CredentialInfo contains all information of an IRMA credential.
type CredentialInfo struct {
	CredentialTypeID CredentialTypeIdentifier // e.g., "irma-demo.RU.studentCard"
	Name             string                   // e.g., "studentCard"
	IssuerID         IssuerIdentifier         // e.g., "RU"
	SchemeManagerID  SchemeManagerIdentifier  // e.g., "irma-demo"
	Index            int                      // This is the Index-th credential instance of this type
	SignedOn         Timestamp                // Unix timestamp
	Expires          Timestamp                // Unix timestamp
	Attributes       []TranslatedString       // Human-readable rendered attributes
	Logo             string                   // Path to logo on storage
	Hash             string                   // SHA256 hash over the attributes
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
		Name:             id.Name(),
		IssuerID:         NewIssuerIdentifier(issid.Name()),
		SchemeManagerID:  NewSchemeManagerIdentifier(issid.SchemeManagerIdentifier().String()),
		SignedOn:         Timestamp(meta.SigningDate()),
		Expires:          Timestamp(meta.Expiry()),
		Attributes:       attrs.Strings(),
		Logo:             credtype.Logo(conf),
		Hash:             attrs.Hash(),
	}
}

// Convert proof responses to Ints, adding nils for undislosed attributes
func convertProofResponsesToInts(aResponses map[int]*big.Int, aDisclosed map[int]*big.Int) ([]*big.Int, error) {
	var ints []*big.Int

	length := len(aResponses) + len(aDisclosed)

	for i := 1; i < length; i++ {
		if aResponses[i] == nil {
			if aDisclosed[i] == nil {
				// If index not found in aResponses it must be in aDisclosed
				return nil, &SessionError{
					ErrorType: ErrorCrypto,
					Info:      fmt.Sprintf("Missing attribute index: %v", i),
				} // TODO: error type?
			}

			ints = append(ints, aDisclosed[i])
		} else {
			// Don't include value of hidden attributes
			ints = append(ints, nil)
		}
	}
	return ints, nil
}

// NewAttributeListFromInts initializes a new AttributeList from disclosed attributes of a prooflist
func NewCredentialInfoFromADisclosed(aResponses map[int]*big.Int, aDisclosed map[int]*big.Int, conf *Configuration) (*CredentialInfo, error) {
	ints, err := convertProofResponsesToInts(aResponses, aDisclosed)
	if err != nil {
		return nil, err
	}

	return NewCredentialInfo(ints, conf), nil
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
	return strings.Compare(cl[i].Name, cl[j].Name) > 0
}
