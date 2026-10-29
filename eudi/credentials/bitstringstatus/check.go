package bitstringstatus

import (
	"fmt"
	"slices"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
)

// ListCredentialSubjectType is the `type` of a BitstringStatusListCredential's
// credentialSubject (W3C §2.2).
const ListCredentialSubjectType = "BitstringStatusList"

// ListCredentialSubject is the credentialSubject of a BitstringStatusListCredential
// (W3C §2.2): the purpose(s) the list covers and the Multibase+GZIP encodedList.
// A caller builds it only after verifying the status list credential's proof.
type ListCredentialSubject struct {
	StatusPurposes []StatusPurpose
	EncodedList    string
}

// ParseListCredentialSubject extracts the fields this package needs from a
// verified BitstringStatusListCredential's credentialSubject. statusPurpose may
// be a single string or an array — a single list may cover several purposes.
func ParseListCredentialSubject(subject map[string]any) (ListCredentialSubject, error) {
	if !vcdm.Document(subject).HasType(ListCredentialSubjectType) {
		return ListCredentialSubject{}, fmt.Errorf("%w: credentialSubject.type is not %s", ErrUnauthorized, ListCredentialSubjectType)
	}
	encoded, _ := subject["encodedList"].(string)
	if encoded == "" {
		return ListCredentialSubject{}, fmt.Errorf("%w: missing encodedList", ErrDecode)
	}
	purposes, err := parsePurposes(subject["statusPurpose"])
	if err != nil {
		return ListCredentialSubject{}, err
	}
	return ListCredentialSubject{StatusPurposes: purposes, EncodedList: encoded}, nil
}

func parsePurposes(v any) ([]StatusPurpose, error) {
	switch p := v.(type) {
	case string:
		if p == "" {
			return nil, fmt.Errorf("%w: empty statusPurpose", ErrUnauthorized)
		}
		return []StatusPurpose{StatusPurpose(p)}, nil
	case []any:
		out := make([]StatusPurpose, 0, len(p))
		for _, e := range p {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, fmt.Errorf("%w: statusPurpose array holds a non-string", ErrUnauthorized)
			}
			out = append(out, StatusPurpose(s))
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%w: empty statusPurpose array", ErrUnauthorized)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: statusPurpose is neither a string nor an array", ErrUnauthorized)
	}
}

// Check resolves an entry against an already-fetched-and-verified status list
// credential subject — the W3C §3.2 Validate algorithm minus the proof
// verification the caller performs before calling this. It confirms the list
// covers the entry's purpose, expands the bitstring, and returns the status
// value at the entry's index. For a single-bit revocation or suspension entry a
// non-zero value means the credential is revoked or suspended respectively.
func Check(entry Entry, subject ListCredentialSubject) (uint, error) {
	list, err := Expand(subject)
	if err != nil {
		return 0, err
	}
	return list.Value(entry)
}

// List is a verified status list credential subject with its bitstring
// expanded, for a caller that reads many entries of one list.
type List struct {
	purposes []StatusPurpose
	bits     []byte
}

// Expand expands the subject's bitstring.
func Expand(subject ListCredentialSubject) (*List, error) {
	bits, err := ExpandBitstring(subject.EncodedList)
	if err != nil {
		return nil, err
	}
	return &List{purposes: subject.StatusPurposes, bits: bits}, nil
}

// Value returns the status value at the entry's index; see Check.
func (l *List) Value(entry Entry) (uint, error) {
	if !slices.Contains(l.purposes, entry.StatusPurpose) {
		return 0, fmt.Errorf("%w: list purposes %v do not cover entry purpose %q", ErrUnauthorized, l.purposes, entry.StatusPurpose)
	}
	return StatusValueAt(l.bits, entry.StatusSize, entry.StatusListIndex)
}

// EntryStatus maps a revocation or suspension entry's value onto the Token
// Status List statuses the wallet stores, so both mechanisms share one
// revocation policy.
func EntryStatus(entry Entry, value uint) statuslist.Status {
	switch {
	case value == 0:
		return statuslist.StatusValid
	case entry.StatusPurpose == PurposeSuspension:
		return statuslist.StatusSuspended
	default:
		return statuslist.StatusInvalid
	}
}
