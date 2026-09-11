package mdoc

import (
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// DEVICE RETRIEVAL MDOC REQUEST — ISO/IEC 18013-5 8.3.2.1.2.1
// ============================================================
//
// The clause, verbatim (its inline comments are printed one line above the member
// they annotate in the published PDF; they are placed correctly here):
//
//	DeviceRequest = {
//	       "version" : tstr,               ; Version of DeviceRequest structure
//	       "docRequests" : [+ DocRequest]  ; Requested documents
//	}
//
//	DocRequest = {
//	    "itemsRequest" : ItemsRequestBytes,
//	    ? "readerAuth" : ReaderAuth        ; mdoc reader authentication
//	}
//
//	ItemsRequestBytes = #6.24(bstr .cbor ItemsRequest)
//
//	ItemsRequest = {
//	       "docType" : DocType,
//	       "nameSpaces" : NameSpaces,
//	       ? "requestInfo" : {* tstr => any}   ; Additional information
//	}
//
//	NameSpaces = { + NameSpace => DataElements }
//
//	DataElements = { + DataElementIdentifier => IntentToRetain }
//
//	IntentToRetain = bool

// DeviceRequestVersion is the value 8.3.2.1.2.1 fixes for this edition: "in the
// current version of this document its value shall be '1.0'".
//
// The clause adds a rule for later versions that cannot be checked here: "the
// major version of a DeviceRequest structure shall not be higher than the major
// version of the device engagement structure communicated by the mdoc in the same
// transaction". Both are "1.0" today, so the comparison is vacuous; a caller that
// ever accepts a second version has to make it against the engagement it sent.
const DeviceRequestVersion = "1.0"

// DeviceRequest is the reader's request, the first thing the mdoc decrypts out of
// SessionEstablishment.
type DeviceRequest struct {
	Version     string       `cbor:"version"`
	DocRequests []DocRequest `cbor:"docRequests"`
}

// DocRequest asks for one document.
//
// ItemsRequest is cbor.RawMessage and holds the complete tag-24
// `ItemsRequestBytes`, not its contents. Two reasons, and the second is the
// binding one:
//
//   - the same tag-24-goes-inline rule as everywhere else in this package;
//   - 9.1.4 signs it. `ReaderAuthentication = ["ReaderAuthentication",
//     SessionTranscript, ItemsRequestBytes]`, and "The ItemsRequestBytes shall
//     contain the same data as in the mdoc request structure". Verifying that
//     signature means hashing the bytes as they arrived, so re-encoding a parsed
//     ItemsRequest would break reader authentication for a request that was
//     perfectly valid.
//
// ReaderAuth is likewise kept as raw CBOR: a COSE_Sign1 over the structure above,
// verified by Verifier.VerifyReaderAuth (9.1.4, readerauth.go). A present
// ReaderAuth still means only that the reader SENT one — it is evidence of nothing
// until that call has succeeded, so do not treat a request as authenticated
// because this field is non-nil.
type DocRequest struct {
	ItemsRequest cbor.RawMessage `cbor:"itemsRequest"`
	ReaderAuth   cbor.RawMessage `cbor:"readerAuth,omitempty"`
}

// ItemsRequest names the document and the data elements wanted from it.
//
// RequestInfo is carried but not interpreted: "This document does not define any
// key-value pairs for use in requestInfo. An mdoc shall ignore any key-value pairs
// that it is not able to interpret." Keeping it raw means a reader extension is
// neither acted on nor lost.
type ItemsRequest struct {
	DocType     string                     `cbor:"docType"`
	NameSpaces  map[string]DataElements    `cbor:"nameSpaces"`
	RequestInfo map[string]cbor.RawMessage `cbor:"requestInfo,omitempty"`
}

// DataElements maps a data element identifier to its IntentToRetain flag.
//
// IntentToRetain is the verifier's declaration that it "intends to retain the
// received data element", where to retain is "to store for a period longer than
// necessary to conduct the transaction in realtime". The mdoc cannot enforce it
// and must not act on it: it changes what the user is being asked to agree to, not
// what is disclosed, so the only correct handling is to carry it through to the
// consent screen. That is what the DCQL translation does with it.
type DataElements map[string]bool

// DecodeDeviceRequest reads a request off the wire, after session decryption.
func DecodeDeviceRequest(data []byte) (DeviceRequest, error) {
	var request DeviceRequest
	if err := mdocDecMode.Unmarshal(data, &request); err != nil {
		return DeviceRequest{}, fmt.Errorf("decode DeviceRequest: %w", err)
	}
	if err := request.Validate(); err != nil {
		return DeviceRequest{}, err
	}
	return request, nil
}

// Validate checks the structure against what 8.3.2.1.2.1 fixes: the version, and
// the CDDL's three `+` occurrences, each of which requires at least one member.
//
// An empty docRequests, an empty nameSpaces or an empty DataElements map is
// well-formed CBOR and meaningless as a request — a document nobody asked
// anything of. Rejecting here means the consent screen is never built from one.
func (r DeviceRequest) Validate() error {
	// Only the MAJOR version is checked, for the reason 8.3.2.1.2.1 states itself:
	// "If other versions are specified in the future, the major version of a
	// DeviceRequest structure shall not be higher than the major version of the
	// device engagement structure communicated by the mdoc in the same
	// transaction." Our engagement is major 1, so any 1.x request satisfies that,
	// and 8.1's versioning rule makes a minor increment backward compatible by
	// construction — a "1.1" request is a structure this code still reads
	// correctly.
	//
	// This was an equality check against "1.0" until 11 Sept 2026, when the first
	// real transaction against an independent reader refused a perfectly good
	// request: the Multipaz test app sends version "1.1". The refusal was
	// invisible on the wire — 8.3.2.1.2.3 gives the reader a bare status code —
	// and cost an afternoon. Mirrors the MobileSecurityObject version rule in
	// verifier.go, which had it right.
	if major, _, _ := strings.Cut(r.Version, "."); major != "1" {
		return fmt.Errorf(
			"DeviceRequest version is %q: this implementation reads ISO/IEC 18013-5 version 1.x only",
			r.Version)
	}
	if len(r.DocRequests) == 0 {
		return fmt.Errorf("DeviceRequest has no docRequests: 8.3.2.1.2.1 requires at least one")
	}
	for i, docRequest := range r.DocRequests {
		items, err := docRequest.Items()
		if err != nil {
			return fmt.Errorf("docRequests[%d]: %w", i, err)
		}
		if err := items.validate(); err != nil {
			return fmt.Errorf("docRequests[%d]: %w", i, err)
		}
	}
	return nil
}

// Items decodes the tag-24 ItemsRequestBytes.
//
// The raw bytes stay on the DocRequest; this returns a parsed copy. Callers that
// need to verify reader authentication must use DocRequest.ItemsRequest, never a
// re-encoding of what this returns.
func (d DocRequest) Items() (ItemsRequest, error) {
	if err := validateTag24Slot("ItemsRequestBytes", d.ItemsRequest); err != nil {
		return ItemsRequest{}, err
	}
	items, err := tag24Unwrap[ItemsRequest](d.ItemsRequest)
	if err != nil {
		return ItemsRequest{}, fmt.Errorf("decode ItemsRequest: %w", err)
	}
	return items, nil
}

func (i ItemsRequest) validate() error {
	if i.DocType == "" {
		return fmt.Errorf("ItemsRequest has no docType")
	}
	if len(i.NameSpaces) == 0 {
		return fmt.Errorf(
			"ItemsRequest for %q has no nameSpaces: 8.3.2.1.2.1 requires at least one", i.DocType)
	}
	for namespace, elements := range i.NameSpaces {
		if namespace == "" {
			return fmt.Errorf("ItemsRequest for %q has an empty namespace identifier", i.DocType)
		}
		if len(elements) == 0 {
			return fmt.Errorf(
				"ItemsRequest for %q requests no data elements in namespace %q: 8.3.2.1.2.1 requires at least one",
				i.DocType, namespace)
		}
		for element := range elements {
			if element == "" {
				return fmt.Errorf(
					"ItemsRequest for %q has an empty data element identifier in namespace %q",
					i.DocType, namespace)
			}
		}
	}
	return nil
}

// Encode CBOR-encodes the request. Used by the reader side and by tests; the mdoc
// only ever decodes one.
func (r DeviceRequest) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	encoded, err := cbor.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode DeviceRequest: %w", err)
	}
	return encoded, nil
}

// NewDocRequest builds a DocRequest around an ItemsRequest, wrapping it as the
// tag-24 ItemsRequestBytes the CDDL calls for.
//
// readerAuth may be nil. When present it must be an encoded COSE_Sign1 over the
// ReaderAuthentication structure of 9.1.4, computed over the very bytes this
// function produced for ItemsRequestBytes.
func NewDocRequest(items ItemsRequest, readerAuth cbor.RawMessage) (DocRequest, error) {
	if err := items.validate(); err != nil {
		return DocRequest{}, err
	}
	wrapped, err := tag24Wrap(items)
	if err != nil {
		return DocRequest{}, fmt.Errorf("wrap ItemsRequestBytes: %w", err)
	}
	return DocRequest{ItemsRequest: wrapped, ReaderAuth: readerAuth}, nil
}
