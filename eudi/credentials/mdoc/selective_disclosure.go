package mdoc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// SelectFromIssuerSigned returns a copy of src containing only the requested
// data elements. `requested` maps namespace → element identifiers. Namespaces
// not present in the map are dropped; elements listed but missing from the
// source cause an error (the caller asked for something the holder does not
// have).
//
// Every kept IssuerSignedItem preserves its on-wire tag-24 bytes, which is
// what the verifier re-hashes against MSO.valueDigests — so a simple subset
// filter is guaranteed to round-trip through digest verification.
func SelectFromIssuerSigned(src *IssuerSigned, requested map[NamespaceName][]string) (*IssuerSigned, error) {
	if src == nil {
		return nil, fmt.Errorf("mdoc: source IssuerSigned is nil")
	}

	filtered := make(IssuerNamespaces, len(requested))
	for ns, elements := range requested {
		srcItems, ok := src.Namespaces[ns]
		if !ok {
			return nil, fmt.Errorf("mdoc: namespace %q not present in credential", ns)
		}
		// Index by identifier for O(n+m) lookup rather than O(n*m).
		byID := make(map[string]IssuerSignedItem, len(srcItems))
		for _, it := range srcItems {
			byID[it.ElementIdentifier] = it
		}

		kept := make([]IssuerSignedItem, 0, len(elements))
		for _, el := range elements {
			it, ok := byID[el]
			if !ok {
				return nil, fmt.Errorf("mdoc: element %q not present in namespace %q", el, ns)
			}
			kept = append(kept, it)
		}
		filtered[ns] = kept
	}

	return &IssuerSigned{
		Namespaces: filtered,
		IssuerAuth: src.IssuerAuth,
	}, nil
}

// EncodeIssuerSigned serialises an IssuerSigned to CBOR. Each item's on-wire
// tag-24 bytes are preserved verbatim in the nameSpaces arrays so the MSO's
// per-item digest commitments still verify. The IssuerAuth COSE_Sign1 is
// rebuilt from its parsed parts — the signed bytes (protected header and
// payload) survive byte-for-byte, so the signature remains valid even though
// the unprotected header is re-encoded.
func EncodeIssuerSigned(src *IssuerSigned) ([]byte, error) {
	if src == nil {
		return nil, fmt.Errorf("mdoc: source IssuerSigned is nil")
	}

	nameSpaces := make(map[string][]cbor.RawMessage, len(src.Namespaces))
	for ns, items := range src.Namespaces {
		encoded := make([]cbor.RawMessage, 0, len(items))
		for i, it := range items {
			if len(it.taggedBytes) == 0 {
				return nil, fmt.Errorf("mdoc: item %d in namespace %q has no raw tagged bytes; was it produced by the parser?", i, ns)
			}
			encoded = append(encoded, cbor.RawMessage(it.taggedBytes))
		}
		nameSpaces[ns] = encoded
	}

	issuerAuth := []any{
		src.IssuerAuth.ProtectedHeader,
		src.IssuerAuth.UnprotectedHeader,
		src.IssuerAuth.Payload,
		src.IssuerAuth.Signature,
	}

	return cbor.Marshal(issuerSignedEncode{
		NameSpaces: nameSpaces,
		IssuerAuth: issuerAuth,
	})
}

// issuerSignedEncode mirrors the on-wire IssuerSigned CBOR map: nameSpaces
// and issuerAuth. Fields are declared in the order the spec uses.
type issuerSignedEncode struct {
	NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
	IssuerAuth []any                        `cbor:"issuerAuth"`
}

// Document is a per-credential entry inside a DeviceResponse. In a full
// disclosure the holder produces one Document per requested credential.
type Document struct {
	DocType      DocType
	IssuerSigned *IssuerSigned
	// DeviceSigned is the raw CBOR encoding of the `deviceSigned` map —
	// typically produced by SignDeviceAuth (Phase C). Required by ISO 18013-5
	// §8.3.2.1.2.1: a Document without DeviceSigned is malformed.
	DeviceSigned []byte
}

// DeviceResponseStatusOK is the success status code in a DeviceResponse per
// ISO 18013-5 Table 8 (status 0 = OK).
const DeviceResponseStatusOK uint64 = 0

// deviceResponseEncode is the top-level DeviceResponse CBOR shape.
type deviceResponseEncode struct {
	Version   string            `cbor:"version"`
	Documents []documentEncode  `cbor:"documents,omitempty"`
	Status    uint64            `cbor:"status"`
}

type documentEncode struct {
	DocType      string          `cbor:"docType"`
	IssuerSigned cbor.RawMessage `cbor:"issuerSigned"`
	DeviceSigned cbor.RawMessage `cbor:"deviceSigned"`
}

// BuildDeviceResponse assembles a DeviceResponse CBOR value from one or more
// documents. `status` is the top-level result code (0 = OK).
func BuildDeviceResponse(docs []Document, status uint64) ([]byte, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("mdoc: DeviceResponse needs at least one document")
	}

	encoded := make([]documentEncode, len(docs))
	for i, d := range docs {
		if d.IssuerSigned == nil {
			return nil, fmt.Errorf("mdoc: document %d has no IssuerSigned", i)
		}
		if len(d.DeviceSigned) == 0 {
			return nil, fmt.Errorf("mdoc: document %d has no DeviceSigned", i)
		}
		isCBOR, err := EncodeIssuerSigned(d.IssuerSigned)
		if err != nil {
			return nil, fmt.Errorf("mdoc: document %d: encode IssuerSigned: %w", i, err)
		}
		encoded[i] = documentEncode{
			DocType:      d.DocType,
			IssuerSigned: isCBOR,
			DeviceSigned: d.DeviceSigned,
		}
	}

	return cbor.Marshal(deviceResponseEncode{
		Version:   "1.0",
		Documents: encoded,
		Status:    status,
	})
}
