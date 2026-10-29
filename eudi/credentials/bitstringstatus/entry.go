package bitstringstatus

import (
	"fmt"
	"strconv"

	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
)

// EntryType is the `type` value that marks a credentialStatus object as a
// Bitstring Status List entry (W3C §2.1).
const EntryType = "BitstringStatusListEntry"

// DefaultStatusSize is the number of bits per entry when statusSize is absent
// (W3C §2.1: one bit).
const DefaultStatusSize = 1

// StatusPurpose is the purpose scope of a BitstringStatusListEntry (W3C §2.1).
// A credential may carry several entries with different purposes.
type StatusPurpose string

const (
	PurposeRevocation StatusPurpose = "revocation"
	PurposeSuspension StatusPurpose = "suspension"
	PurposeRefresh    StatusPurpose = "refresh"
	PurposeMessage    StatusPurpose = "message"
)

// Entry is one BitstringStatusListEntry taken from a VCDM credentialStatus
// property. It selects the StatusSize-bit value at StatusListIndex in the
// bitstring of the BitstringStatusListCredential located at StatusListCredential,
// scoped to StatusPurpose.
type Entry struct {
	ID                   string
	StatusPurpose        StatusPurpose
	StatusListIndex      uint64
	StatusListCredential string
	StatusSize           int
}

// ParseEntries reads the Bitstring Status List entries from a VCDM
// credentialStatus value. Per VCDM the property may be a single object or an
// array (e.g. a separate revocation and suspension entry), and may hold status
// mechanisms this package does not implement; only objects whose type is
// BitstringStatusListEntry are returned. A nil/absent credentialStatus yields no
// entries and no error.
func ParseEntries(credentialStatus any) ([]Entry, error) {
	if credentialStatus == nil {
		return nil, nil
	}

	var objs []map[string]any
	switch v := credentialStatus.(type) {
	case map[string]any:
		objs = []map[string]any{v}
	case []any:
		for _, e := range v {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%w: credentialStatus array element is not an object", ErrEntry)
			}
			objs = append(objs, m)
		}
	default:
		return nil, fmt.Errorf("%w: credentialStatus is neither an object nor an array", ErrEntry)
	}

	var entries []Entry
	for _, m := range objs {
		if !vcdm.Document(m).HasType(EntryType) {
			continue // a sibling status mechanism we do not handle
		}
		entry, err := parseEntry(m)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func parseEntry(m map[string]any) (Entry, error) {
	purpose, _ := m["statusPurpose"].(string)
	if purpose == "" {
		return Entry{}, fmt.Errorf("%w: missing statusPurpose", ErrEntry)
	}

	idxStr, _ := m["statusListIndex"].(string)
	if idxStr == "" {
		return Entry{}, fmt.Errorf("%w: statusListIndex must be a base-10 string", ErrEntry)
	}
	idx, err := strconv.ParseUint(idxStr, 10, 64)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: statusListIndex %q is not a base-10 uint: %v", ErrEntry, idxStr, err)
	}

	cred, _ := m["statusListCredential"].(string)
	if cred == "" {
		return Entry{}, fmt.Errorf("%w: missing statusListCredential", ErrEntry)
	}

	size := DefaultStatusSize
	if v, ok := m["statusSize"]; ok {
		size, err = asPositiveInt(v)
		if err != nil {
			return Entry{}, fmt.Errorf("%w: statusSize: %v", ErrEntry, err)
		}
	}
	// statusMessage is not checked. W3C §2.1 makes the issuer include it when
	// statusSize is greater than 1, one {status, message} per possible value,
	// but its messages are for developers and not shown to users, and the
	// wallet reads only the status value. A credential is not refused for
	// leaving it out or getting it wrong.

	id, _ := m["id"].(string)
	return Entry{
		ID:                   id,
		StatusPurpose:        StatusPurpose(purpose),
		StatusListIndex:      idx,
		StatusListCredential: cred,
		StatusSize:           size,
	}, nil
}

// asPositiveInt accepts the JSON number shapes statusSize may arrive as
// (float64 from encoding/json, or an integer type) and requires a positive
// whole number.
func asPositiveInt(v any) (int, error) {
	var n int
	switch x := v.(type) {
	case float64:
		if x != float64(int(x)) {
			return 0, fmt.Errorf("must be a whole number, got %v", x)
		}
		n = int(x)
	case int:
		n = x
	case int64:
		n = int(x)
	default:
		return 0, fmt.Errorf("must be a number, got %T", v)
	}
	if n < 1 {
		return 0, fmt.Errorf("must be at least 1, got %d", n)
	}
	return n, nil
}
