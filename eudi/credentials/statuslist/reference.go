package statuslist

import (
	"errors"
	"fmt"
	"math"
)

// StatusListTokenJWTTyp is the JOSE 'typ' header value mandated by the spec
// for the JWT encoding (draft-ietf-oauth-status-list-15 §5.1; the media
// type itself is registered in §8.2).
const StatusListTokenJWTTyp = "statuslist+jwt"

// StatusListTokenJWTContentType is the HTTP Content-Type value for the JWT
// encoding (draft-ietf-oauth-status-list-15 §8.2).
const StatusListTokenJWTContentType = "application/statuslist+jwt"

// StatusListTokenCWTContentType is both the HTTP Content-Type value (§8.2)
// and the value of the COSE protected header "type" (label 16, registered by
// RFC 9596) for the CWT encoding (draft-ietf-oauth-status-list-15 §5.2).
// Unlike the JWT encoding's `typ` (a bare "statuslist+jwt", by JOSE
// convention), the CWT "type" header carries the full media type string, so
// one constant serves both checks.
const StatusListTokenCWTContentType = "application/statuslist+cwt"

// StatusClaimKey is the JWT claim carrying a token's status (§6.2).
const StatusClaimKey = "status"

// StatusClaim is the shape of the `status` claim on a referenced token (an
// SD-JWT VC's JSON claim, or an mdoc MSO's CBOR field — see
// draft-ietf-oauth-status-list-15 §6.2/§6.3.2). The spec allows multiple
// sibling status mechanisms under `status`; v1 only supports `status_list`.
type StatusClaim struct {
	StatusList *Reference `json:"status_list,omitempty" cbor:"status_list,omitempty"`
}

// Reference identifies a single entry in a Status List Token:
// `idx` selects the bit-position, `uri` locates the token. The cbor tags
// are what let an mdoc MSO (which carries this as a CBOR map, §6.3.2) decode
// directly into the same type the JWT/SD-JWT VC path uses.
type Reference struct {
	Index uint64 `json:"idx" cbor:"idx"`
	URI   string `json:"uri" cbor:"uri"`
}

// ParseStatusClaim reads the Token Status List reference from the value of a
// decoded `status` claim, as found in a JSON-decoded credential payload. It
// returns nil when the claim carries no `status_list` member, which the spec
// allows as an extension point.
func ParseStatusClaim(status any) (*Reference, error) {
	claim, ok := status.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("status claim is not an object: %T", status)
	}
	raw, ok := claim["status_list"]
	if !ok {
		return nil, nil
	}
	list, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("status_list is not an object: %T", raw)
	}
	uri, ok := list["uri"].(string)
	if !ok || uri == "" {
		return nil, fmt.Errorf("status_list.uri is missing or not a string")
	}
	idx, ok := nonNegativeInteger(list["idx"])
	if !ok {
		return nil, fmt.Errorf("status_list.idx is missing or not a non-negative integer")
	}
	return &Reference{URI: uri, Index: idx}, nil
}

// nonNegativeInteger reads a JSON number as a uint64. A decoded payload holds
// it as a float64; a claim set built in code may hold an integer type.
func nonNegativeInteger(v any) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n < 0 || n != math.Trunc(n) {
			return 0, false
		}
		return uint64(n), true
	case int:
		return uint64(n), n >= 0
	case int64:
		return uint64(n), n >= 0
	case uint64:
		return n, true
	default:
		return 0, false
	}
}

// Status is the typed value returned by Checker.Check.
//
// Mapping from the raw bit-value n is:
//
//	n == 0 -> StatusValid
//	n == 1 -> StatusInvalid
//	n == 2 -> StatusSuspended  (requires bits >= 2)
//	n >= 3 -> StatusApplicationSpecific
//
// StatusUnknown is the zero value; it represents "not yet checked"
// and is the default for newly persisted credential rows.
type Status uint8

const (
	StatusUnknown             Status = 0
	StatusValid               Status = 1
	StatusInvalid             Status = 2
	StatusSuspended           Status = 3
	StatusApplicationSpecific Status = 4
)

// String returns a stable lowercase identifier for the status, used for
// log/diagnostic output and for surface-level wire formats.
func (s Status) String() string {
	switch s {
	case StatusValid:
		return "valid"
	case StatusInvalid:
		return "invalid"
	case StatusSuspended:
		return "suspended"
	case StatusApplicationSpecific:
		return "application_specific"
	default:
		return "unknown"
	}
}

// WorseStatus combines two statuses, for a credential with more than one status
// reference: revoked outranks suspended outranks anything else non-valid
// outranks valid. Unknown, no status information, never outranks a known one.
func WorseStatus(a, b Status) Status {
	rank := func(s Status) int {
		switch s {
		case StatusValid:
			return 0
		case StatusApplicationSpecific:
			return 1
		case StatusSuspended:
			return 2
		case StatusInvalid:
			return 3
		default:
			return -1
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// fromRaw converts a decoded bit-value into a Status.
func statusFromRaw(raw uint8) Status {
	switch raw {
	case 0:
		return StatusValid
	case 1:
		return StatusInvalid
	case 2:
		return StatusSuspended
	default:
		return StatusApplicationSpecific
	}
}

// Sentinel errors. Callers should use errors.Is to discriminate.
var (
	// ErrFetch wraps HTTP transport errors, non-2xx responses, and
	// content-type / body-size violations during the fetch step.
	ErrFetch = errors.New("status list fetch failed")

	// ErrUnauthorized covers signature failures, wrong typ, iss
	// mismatch, time-bound violations, and unsupported bit-sizes —
	// any integrity error after a successful fetch.
	ErrUnauthorized = errors.New("status list token signature/iss/typ invalid")

	// ErrDecode covers malformed zlib payloads and bit-array
	// length violations during decoding.
	ErrDecode = errors.New("status list lst could not be decoded")

	// ErrIndexBounds is returned when the reference idx falls
	// outside the decoded bit array.
	ErrIndexBounds = errors.New("status list idx out of bounds")
)
