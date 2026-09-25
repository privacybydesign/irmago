package statuslist

import "errors"

// StatusListTokenTyp is the JOSE 'typ' header value mandated by the spec
// for the JWT encoding (draft-ietf-oauth-status-list-15 §5.1; the media
// type itself is registered in §8.2).
const StatusListTokenTyp = "statuslist+jwt"

// StatusListTokenContentType is the HTTP Content-Type value for the JWT
// encoding (draft-ietf-oauth-status-list-15 §8.2).
const StatusListTokenContentType = "application/statuslist+jwt"

// StatusClaim is the JSON shape of the `status` claim on a referenced
// token (e.g. an SD-JWT VC). The spec allows multiple sibling status
// mechanisms under `status`; v1 only supports `status_list`.
type StatusClaim struct {
	StatusList *Reference `json:"status_list,omitempty"`
}

// Reference identifies a single entry in a Status List Token:
// `idx` selects the bit-position, `uri` locates the token.
type Reference struct {
	Index uint64 `json:"idx"`
	URI   string `json:"uri"`
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
