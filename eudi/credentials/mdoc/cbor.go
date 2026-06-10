// Package mdoc implements the low-level CBOR/COSE primitives required for
// ISO/IEC 18013-5 mobile documents (mdoc / mDL). It is the foundation that the
// mdoc data model, issuance and disclosure code build on.
//
// This file contains the CBOR encoding/decoding helpers. mdoc mandates
// deterministic (canonical) CBOR, so a single pair of fixed encode/decode modes
// is used throughout the package. It also defines the small set of tagged types
// that appear in the mdoc data model:
//
//   - EncodedCBOR: tag 24, a byte string wrapping nested, already-encoded CBOR
//     (#6.24(bstr .cbor X)). Used pervasively in 18013-5 so that nested
//     structures can be digested and signed byte-exactly.
//   - FullDate: tag 1004 (RFC 8943), a "full-date" text string "YYYY-MM-DD".
//   - DateTime: tag 0 (RFC 8949 §3.4.1), an RFC 3339 "date-time" text string,
//     encoded in UTC with no fractional seconds as required by 18013-5.
package mdoc

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// CBOR tag numbers used by ISO/IEC 18013-5.
const (
	// tagDateTime is the standard date/time tag (RFC 8949 §3.4.1).
	tagDateTime uint64 = 0
	// tagEncodedCBOR wraps a byte string holding embedded CBOR (RFC 8949 §3.4.5.1).
	tagEncodedCBOR uint64 = 24
	// tagFullDate is the "full-date" tag from RFC 8943.
	tagFullDate uint64 = 1004
)

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	// ISO/IEC 18013-5 §9.1.2 requires canonical CBOR encoding (RFC 7049 §3.9):
	// definite-length items, shortest-form integers and length-first ("canonical")
	// map key ordering. fxamacker's CanonicalEncOptions encodes exactly that.
	var err error
	encMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("mdoc: failed to build CBOR encode mode: %v", err))
	}

	// Decoding stays deliberately lenient (input arrives from issuers and
	// verifiers): default options, but reject indefinite-length items which are
	// not allowed by the mdoc profile and complicate digest recomputation.
	decMode, err = cbor.DecOptions{
		IndefLength: cbor.IndefLengthForbidden,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("mdoc: failed to build CBOR decode mode: %v", err))
	}
}

// MarshalCBOR encodes v using the canonical mdoc CBOR encoding.
func MarshalCBOR(v any) ([]byte, error) {
	return encMode.Marshal(v)
}

// UnmarshalCBOR decodes mdoc CBOR from data into v.
func UnmarshalCBOR(data []byte, v any) error {
	return decMode.Unmarshal(data, v)
}

// EncodeMode exposes the canonical mdoc CBOR encode mode, e.g. for callers that
// need to drive an encoder directly.
func EncodeMode() cbor.EncMode { return encMode }

// DecodeMode exposes the mdoc CBOR decode mode.
func DecodeMode() cbor.DecMode { return decMode }

// EncodedCBOR is the #6.24(bstr .cbor) construct: a byte string, tagged with 24,
// whose contents are themselves a complete, already-encoded CBOR data item. The
// raw embedded bytes are preserved verbatim so that digests and signatures over
// them remain byte-exact.
type EncodedCBOR struct {
	// Data holds the embedded, already-encoded CBOR bytes (the inner data item).
	Data []byte
}

// NewEncodedCBOR canonically encodes v and wraps the result as an EncodedCBOR.
func NewEncodedCBOR(v any) (EncodedCBOR, error) {
	data, err := encMode.Marshal(v)
	if err != nil {
		return EncodedCBOR{}, err
	}
	return EncodedCBOR{Data: data}, nil
}

// DecodeInto decodes the embedded CBOR into v.
func (e EncodedCBOR) DecodeInto(v any) error {
	return decMode.Unmarshal(e.Data, v)
}

// MarshalCBOR implements cbor.Marshaler, emitting #6.24(bstr) around the
// embedded bytes.
func (e EncodedCBOR) MarshalCBOR() ([]byte, error) {
	if e.Data == nil {
		return nil, fmt.Errorf("mdoc: EncodedCBOR has no data")
	}
	return encMode.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: e.Data})
}

// UnmarshalCBOR implements cbor.Unmarshaler, expecting #6.24(bstr).
func (e *EncodedCBOR) UnmarshalCBOR(data []byte) error {
	var raw cbor.RawTag
	if err := decMode.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Number != tagEncodedCBOR {
		return fmt.Errorf("mdoc: expected tag %d (EncodedCBOR), got %d", tagEncodedCBOR, raw.Number)
	}
	var inner []byte
	if err := decMode.Unmarshal(raw.Content, &inner); err != nil {
		return fmt.Errorf("mdoc: EncodedCBOR content is not a byte string: %w", err)
	}
	e.Data = inner
	return nil
}

// FullDate is a calendar date with no time-of-day component, encoded as a
// tag 1004 (RFC 8943) "full-date" text string in "YYYY-MM-DD" form.
type FullDate time.Time

const fullDateLayout = "2006-01-02"

// NewFullDate builds a FullDate from a time.Time, discarding the time of day.
func NewFullDate(t time.Time) FullDate { return FullDate(t) }

// Time returns the underlying time.Time.
func (d FullDate) Time() time.Time { return time.Time(d) }

// String returns the full-date representation.
func (d FullDate) String() string { return time.Time(d).Format(fullDateLayout) }

// MarshalCBOR implements cbor.Marshaler.
func (d FullDate) MarshalCBOR() ([]byte, error) {
	return encMode.Marshal(cbor.Tag{Number: tagFullDate, Content: time.Time(d).Format(fullDateLayout)})
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (d *FullDate) UnmarshalCBOR(data []byte) error {
	var raw cbor.RawTag
	if err := decMode.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Number != tagFullDate {
		return fmt.Errorf("mdoc: expected tag %d (full-date), got %d", tagFullDate, raw.Number)
	}
	var s string
	if err := decMode.Unmarshal(raw.Content, &s); err != nil {
		return fmt.Errorf("mdoc: full-date content is not a text string: %w", err)
	}
	t, err := time.Parse(fullDateLayout, s)
	if err != nil {
		return fmt.Errorf("mdoc: invalid full-date %q: %w", s, err)
	}
	*d = FullDate(t)
	return nil
}

// DateTime is a point in time encoded as a tag 0 (RFC 8949 §3.4.1) RFC 3339
// "date-time" text string. Per ISO/IEC 18013-5 it is always serialised in UTC
// with second precision and no fractional seconds.
type DateTime time.Time

const dateTimeLayout = "2006-01-02T15:04:05Z"

// NewDateTime builds a DateTime from a time.Time.
func NewDateTime(t time.Time) DateTime { return DateTime(t) }

// Time returns the underlying time.Time.
func (t DateTime) Time() time.Time { return time.Time(t) }

// String returns the RFC 3339 representation used on the wire.
func (t DateTime) String() string {
	return time.Time(t).UTC().Truncate(time.Second).Format(dateTimeLayout)
}

// MarshalCBOR implements cbor.Marshaler.
func (t DateTime) MarshalCBOR() ([]byte, error) {
	s := time.Time(t).UTC().Truncate(time.Second).Format(dateTimeLayout)
	return encMode.Marshal(cbor.Tag{Number: tagDateTime, Content: s})
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (t *DateTime) UnmarshalCBOR(data []byte) error {
	var raw cbor.RawTag
	if err := decMode.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Number != tagDateTime {
		return fmt.Errorf("mdoc: expected tag %d (date-time), got %d", tagDateTime, raw.Number)
	}
	var s string
	if err := decMode.Unmarshal(raw.Content, &s); err != nil {
		return fmt.Errorf("mdoc: date-time content is not a text string: %w", err)
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("mdoc: invalid date-time %q: %w", s, err)
	}
	*t = DateTime(parsed.UTC())
	return nil
}
