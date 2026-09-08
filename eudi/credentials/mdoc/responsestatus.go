package mdoc

import "fmt"

// ============================================================
// RESPONSE STATUS AND ERROR CODES — ISO/IEC 18013-5 8.3.2.1.2.3
// ============================================================
//
// Two things live here: the DeviceResponse-level status of Table 8, and the
// per-element error codes of Table 9 that let a response say what it could not
// return without failing outright.
//
// # These are not the session status codes
//
// Table 20 (9.1.1.4) defines a *different* set of status codes for SessionData,
// and the two overlap numerically with different meanings:
//
//	Table 8  (this file, DeviceResponse):  0 OK, 10 general error,
//	                                       11 CBOR decoding, 12 CBOR validation
//	Table 20 (session.go, SessionData):    10 session encryption error,
//	                                       11 CBOR decoding, 20 session termination
//
// A response status 10 means the mdoc declined to answer; a session status 10
// means the transport could not decrypt. They travel in different structures at
// different layers of the same stack, so the constants are named apart on purpose
// — ResponseStatus* here, Status* in session.go.

// DeviceResponse status codes, Table 8.
//
// 8.3.2.1.2.3 attaches one hard rule to them: "If the mdoc returns a status code
// different from 0, it shall not return any documents." Returning 11 and 12 is
// optional; 10 is the catch-all the table describes as "an error without any
// given reason".
const (
	ResponseStatusOK                  uint64 = 0
	ResponseStatusGeneralError        uint64 = 10
	ResponseStatusCBORDecodingError   uint64 = 11
	ResponseStatusCBORValidationError uint64 = 12
)

// ErrorCode is Table 9's per-document or per-data-element code, `ErrorCode = int`
// in the CDDL.
type ErrorCode int

// ErrorCodeDataNotReturned is the only code Table 9 defines: "The mdoc does not
// provide the requested document or data element without any given reason. This
// element may be used in all cases." Everything else in the table is RFU or
// application-specific.
//
// It is what makes partial satisfaction expressible. 8.3.2.1.2.1 says "The mdoc
// shall ignore all unknown data elements in a device retrieval mdoc request when
// processing the request", and this is how the response says which ones were
// ignored: return the elements that exist, and list the rest here. A whole
// response failed with a non-zero status would be the wrong answer to a request
// that asked for one element too many.
const ErrorCodeDataNotReturned ErrorCode = 0

// Errors is a Document's per-element error map from 8.3.2.1.2.2:
//
//	Errors = { + NameSpace => ErrorItems }
type Errors map[string]ErrorItems

// ErrorItems maps a data element identifier to its error code:
//
//	ErrorItems = { + DataElementIdentifier => ErrorCode }
type ErrorItems map[string]ErrorCode

// DocumentError reports a document that was requested but not returned at all:
//
//	DocumentError = { DocType => ErrorCode }
//
// Distinct from Errors, which reports individual elements missing from a document
// that *was* returned.
type DocumentError map[string]ErrorCode

// NewDocumentError builds the single-entry map of 8.3.2.1.2.2 for a docType the
// mdoc is not returning.
func NewDocumentError(docType string, code ErrorCode) (DocumentError, error) {
	if docType == "" {
		return nil, fmt.Errorf("DocumentError needs a docType")
	}
	return DocumentError{docType: code}, nil
}

// validate checks the `+` occurrences the CDDL places on these maps: an empty
// Errors, an empty ErrorItems or an empty DocumentError is well-formed CBOR and
// says nothing, and a peer receiving one cannot tell it apart from a bug.
func (e Errors) validate() error {
	if len(e) == 0 {
		return fmt.Errorf("Errors is empty: 8.3.2.1.2.2 requires at least one namespace")
	}
	for namespace, items := range e {
		if namespace == "" {
			return fmt.Errorf("Errors has an empty namespace identifier")
		}
		if len(items) == 0 {
			return fmt.Errorf(
				"Errors names namespace %q with no data elements: 8.3.2.1.2.2 requires at least one",
				namespace)
		}
		for identifier := range items {
			if identifier == "" {
				return fmt.Errorf("Errors has an empty data element identifier in namespace %q", namespace)
			}
		}
	}
	return nil
}
