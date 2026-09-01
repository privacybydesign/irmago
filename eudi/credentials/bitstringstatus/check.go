package bitstringstatus

import "fmt"

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
	if !hasType(subject, ListCredentialSubjectType) {
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
	if !coversPurpose(subject.StatusPurposes, entry.StatusPurpose) {
		return 0, fmt.Errorf("%w: list purposes %v do not cover entry purpose %q", ErrUnauthorized, subject.StatusPurposes, entry.StatusPurpose)
	}
	bits, err := ExpandBitstring(subject.EncodedList)
	if err != nil {
		return 0, err
	}
	return StatusValueAt(bits, entry.StatusSize, entry.StatusListIndex)
}

func coversPurpose(have []StatusPurpose, want StatusPurpose) bool {
	for _, p := range have {
		if p == want {
			return true
		}
	}
	return false
}
