package mdoc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// DEVICE RESPONSE — the top-level container a holder actually
// transmits to a verifier, per ISO 18013-5
// ============================================================

// DeviceSigned bundles the holder-signed portion of a presented document:
// NameSpaces (any holder-asserted claims — always empty for this profile,
// since eu.europa.ec.av.1 has no holder-added attributes) and DeviceAuth
// (the COSE_Sign1 proving device possession).
// NameSpaces is cbor.RawMessage for the same reason as
// DeviceAuthentication.DeviceNameSpaces: ISO 18013-5's DeviceNameSpacesBytes is
// a tag-24 value at this position, and the field already holds that encoding.
type DeviceSigned struct {
	NameSpaces cbor.RawMessage `cbor:"nameSpaces"` // Tag24(empty map) — see holder.go's SignDeviceAuth
	DeviceAuth DeviceAuth      `cbor:"deviceAuth"`
}

// DeviceAuth carries the mdoc's authentication of a DeviceResponse. ISO/IEC
// 18013-5 8.3.2.1.2.2 makes it a choice of exactly one branch:
//
//	DeviceAuth = {
//	   "deviceSignature" : DeviceSignature //   ; "//" means or
//	   "deviceMac" : DeviceMac
//	}
//
// deviceSignature is a COSE_Sign1 over DeviceAuthenticationBytes (9.1.3.6,
// Holder.SignDeviceAuth); deviceMac is an untagged COSE_Mac0 over the same
// detached content (9.1.3.5, MacDeviceAuth).
//
// Which branch is WHOLLY THE MDOC'S CHOICE: nothing in DeviceRequest selects
// one, and 9.1.3.4's only support obligation is "an mdoc reader shall support
// both approaches". This wallet always sends deviceSignature, which is why
// AttachDeviceSigned populates that branch unconditionally — the reasoning, and
// why 9.1.3.4's one-purpose-per-key rule makes it a wallet-wide rather than a
// proximity-local decision, is in devicemac.go's header comment.
//
// Both branches are still parsed and verified on the way IN, because this
// package is also the mdoc reader, which must accept either.
//
// Both are cbor.RawMessage, not []byte: the COSE array must be embedded inline as
// CBOR, not wrapped in the extra byte string a plain []byte field would produce.
// Both are omitempty because exactly one is present — see validate.
type DeviceAuth struct {
	DeviceSignature cbor.RawMessage `cbor:"deviceSignature,omitempty"`
	DeviceMac       cbor.RawMessage `cbor:"deviceMac,omitempty"`
}

// validate enforces the CDDL's exclusive choice. Neither branch is a document
// nothing authenticates; both is a document making two claims a verifier would
// have to pick between, and nothing says which wins.
func (d DeviceAuth) validate() error {
	switch {
	case len(d.DeviceSignature) == 0 && len(d.DeviceMac) == 0:
		return fmt.Errorf(
			"DeviceAuth has neither deviceSignature nor deviceMac: 8.3.2.1.2.2 requires one")
	case len(d.DeviceSignature) > 0 && len(d.DeviceMac) > 0:
		return fmt.Errorf(
			"DeviceAuth has both deviceSignature and deviceMac: 8.3.2.1.2.2 permits exactly one")
	}
	return nil
}

// AttachDeviceSigned returns a copy of mdoc with DeviceSigned populated
// from a deviceAuth signature already produced by Holder.SignDeviceAuth.
// Kept separate from SignDeviceAuth itself so existing callers that just
// want the raw deviceAuth bytes (e.g. Verifier.VerifyWithDeviceAuth, which
// takes the signature as a parameter and works with or without a
// DeviceSigned envelope) don't need to change — this is purely additive,
// for building a real DeviceResponse to bundle up and transmit.
func AttachDeviceSigned(mdoc *MDoc, deviceAuthBytes []byte) (*MDoc, error) {
	emptyNS, err := tag24Wrap(map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("wrap empty deviceNameSpaces: %w", err)
	}

	attached := *mdoc
	attached.DeviceSigned = &DeviceSigned{
		NameSpaces: emptyNS,
		DeviceAuth: DeviceAuth{DeviceSignature: cbor.RawMessage(deviceAuthBytes)},
	}
	return &attached, nil
}

// DeviceResponse is the top-level container ISO/IEC 18013-5 8.3.2.1.2.2 transmits
// to the verifier — as opposed to a bare MDoc, which is what this package's
// issuer/holder/verifier functions work with directly:
//
//	DeviceResponse = {
//	    "version" : tstr,
//	    ? "documents" : [+Document],
//	    ? "documentErrors": [+DocumentError],
//	    "status" : uint
//	}
//
// Both optional members are omitempty because the CDDL requires each to hold at
// least one entry when present, so an empty array is not a conformant way to say
// "none".
//
// documents is optional for a real reason rather than a technicality: 8.3.2.1.2.3
// says "If the mdoc returns a status code different from 0, it shall not return
// any documents", so an error response has a status and nothing else. Validate
// enforces it.
//
// Two different kinds of failure are reportable, and they are not
// interchangeable. documentErrors names a whole document that is not being
// returned; Document.Errors names individual data elements missing from a
// document that is. A request for an element the wallet does not hold produces the
// second, not the first, and certainly not a non-zero status.
// zkDocuments is not in the CDDL above, which is the 2021 edition's. It carries
// presentations made as zero-knowledge proofs instead of disclosures, per
// ISO/IEC DIS 18013-5 (Second Edition) 10.2.7 — see zkp.go. The choice between
// it and documents is per document rather than per response: a reader may ask
// for one credential in the clear and another as a proof in a single request,
// so a response can legitimately carry both arrays.
type DeviceResponse struct {
	Version        string          `cbor:"version"`
	Documents      []MDoc          `cbor:"documents,omitempty"`
	ZkDocuments    []ZkDocument    `cbor:"zkDocuments,omitempty"`
	DocumentErrors []DocumentError `cbor:"documentErrors,omitempty"`
	Status         uint64          `cbor:"status"`
}

// DeviceResponseVersion is the value 8.3.2.1.2.2 fixes for this edition.
//
// As with DeviceRequest, the clause adds a cross-structure rule for future
// versions that cannot be checked from here: a DeviceResponse's major version
// "shall not be higher than" that of the device engagement, nor of the request it
// answers. All three are "1.0" today.
const DeviceResponseVersion = "1.0"

// DeviceResponseVersionZk is the value a response carrying second-edition
// members announces itself with.
//
// `zkDocuments` does not exist in the 2021 edition — it is ISO/IEC DIS 18013-5
// (Second Edition) 10.2.7 — so a response carrying one is not a 1.0 response and
// saying "1.0" would be a second-edition payload wearing a first-edition label. A
// verifier that trusted the version would parse it as 1.0 and meet a member it
// has no rule for.
//
// Verified against Multipaz rather than quoted from the clause: the second
// edition is not published, only a draft in ballot, so there is no clause to
// quote. DeviceResponse.kt's builder:
//
//	val versionToUse = version ?: if (
//	    zkDocuments.isNotEmpty() || encryptedDocuments.isNotEmpty() || otherDocuments.isNotEmpty()
//	) "1.1" else "1.0"
//
// Its other two triggers are members this package does not implement, so the rule
// here is the zkDocuments half of the same rule. If encryptedDocuments or
// otherDocuments ever land, they join this condition.
//
// This was found by decoding a DeviceResponse Multipaz actually produced — see
// zkp_multipaz_vector_test.go. Before that, NewZkDeviceResponse emitted "1.0" and
// Validate rejected "1.1" outright, so this wallet would have sent a mislabelled
// response and refused every conformant one it received.
const DeviceResponseVersionZk = "1.1"

// versionFor picks the version a response with these contents must carry, so the
// choice lives in one place rather than at each construction site.
func versionFor(zkDocuments []ZkDocument) string {
	if len(zkDocuments) > 0 {
		return DeviceResponseVersionZk
	}
	return DeviceResponseVersion
}

// NewDeviceResponse bundles one or more presented documents (each already carrying
// DeviceSigned via AttachDeviceSigned) into a successful DeviceResponse.
func NewDeviceResponse(documents ...MDoc) DeviceResponse {
	return DeviceResponse{
		Version:   DeviceResponseVersion,
		Documents: documents,
		Status:    ResponseStatusOK,
	}
}

// NewZkDeviceResponse bundles one or more zero-knowledge presentations into a
// DeviceResponse. Separate from NewDeviceResponse rather than a variadic
// addition to it because the two are produced at different points: a ZK
// presentation is built from a document that has already been through the
// ordinary presentation path, so by the time these exist the plain documents
// for the same request no longer travel.
func NewZkDeviceResponse(documents ...ZkDocument) DeviceResponse {
	return DeviceResponse{
		Version:     versionFor(documents),
		ZkDocuments: documents,
		Status:      ResponseStatusOK,
	}
}

// NewErrorDeviceResponse builds the response of 8.3.2.1.2.3 for a request the mdoc
// is not answering: a status and nothing else.
//
// Reach for this only when no document can be returned at all. A request naming
// one element the wallet does not hold is not this case — return the document with
// Document.Errors, per ErrorCodeDataNotReturned.
func NewErrorDeviceResponse(status uint64) (DeviceResponse, error) {
	if status == ResponseStatusOK {
		return DeviceResponse{}, fmt.Errorf(
			"NewErrorDeviceResponse called with status 0 (OK): use NewDeviceResponse for a successful response")
	}
	return DeviceResponse{Version: DeviceResponseVersion, Status: status}, nil
}

// WithDocumentErrors attaches documentErrors for documents that are not being
// returned. It is additive: a response can carry both returned documents and
// errors for others.
func (r DeviceResponse) WithDocumentErrors(errors ...DocumentError) DeviceResponse {
	r.DocumentErrors = append(r.DocumentErrors, errors...)
	return r
}

// Validate checks what 8.3.2.1.2.2 and .3 fix about the response as a whole.
//
// The status rule is the load-bearing one and is not obvious from the CDDL, which
// makes documents merely optional: it is 8.3.2.1.2.3's prose that forbids
// combining a non-zero status with documents. A verifier that trusted the status
// and ignored the documents, or vice versa, would disagree with one that did the
// opposite.
func (r DeviceResponse) Validate() error {
	// The version is checked against what this response CONTAINS, not against a
	// single fixed value. 8.3.2.1.2.2 fixes "1.0" for the 2021 edition, but
	// zkDocuments is a second-edition member and a response carrying one says
	// "1.1" — see DeviceResponseVersionZk. Enforcing the correspondence in both
	// directions is what keeps a mislabelled response from being built here or
	// accepted from elsewhere: a 1.0 response cannot carry proofs, and a response
	// carrying proofs cannot claim 1.0.
	if want := versionFor(r.ZkDocuments); r.Version != want {
		return fmt.Errorf(
			"DeviceResponse version is %q, want %q: a response carrying %d zkDocuments is version %q, one carrying none is %q",
			r.Version, want, len(r.ZkDocuments), DeviceResponseVersionZk, DeviceResponseVersion)
	}
	if r.Status != ResponseStatusOK && len(r.Documents) > 0 {
		return fmt.Errorf(
			"DeviceResponse has status %d and %d documents: 8.3.2.1.2.3 requires that an mdoc returning a status other than 0 return no documents",
			r.Status, len(r.Documents))
	}
	for i, documentError := range r.DocumentErrors {
		if len(documentError) == 0 {
			return fmt.Errorf("documentErrors[%d] is empty", i)
		}
		for docType := range documentError {
			if docType == "" {
				return fmt.Errorf("documentErrors[%d] has an empty docType", i)
			}
		}
	}
	for i, document := range r.Documents {
		// A returned document must authenticate itself. 9.1.3 makes deviceAuth the
		// only thing standing between a genuine presentation and a replayed
		// IssuerSigned, so a Document without it is not a weaker response, it is an
		// unauthenticated one.
		if document.DeviceSigned == nil {
			return fmt.Errorf("documents[%d] has no deviceSigned: 8.3.2.1.2.2 makes it mandatory in a returned Document", i)
		}
		if err := document.DeviceSigned.DeviceAuth.validate(); err != nil {
			return fmt.Errorf("documents[%d]: %w", i, err)
		}
		if document.Errors == nil {
			continue
		}
		if err := document.Errors.validate(); err != nil {
			return fmt.Errorf("documents[%d]: %w", i, err)
		}
	}
	return nil
}

// Encode CBOR-encodes the response for transmission.
func (r DeviceResponse) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	encoded, err := cbor.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode DeviceResponse: %w", err)
	}
	return encoded, nil
}

// DisclosedElements lists the data element identifiers each namespace of this
// document actually carries, which is what a caller compares against a request to
// find out what it could not answer.
func (m MDoc) DisclosedElements() (map[string][]string, error) {
	disclosed := make(map[string][]string, len(m.IssuerSigned.NameSpaces))
	for namespace, items := range m.IssuerSigned.NameSpaces {
		for _, tag24item := range items {
			item, err := tag24Unwrap[IssuerSignedItem](tag24item.EncodedItem)
			if err != nil {
				return nil, fmt.Errorf("decode IssuerSignedItem in namespace %q: %w", namespace, err)
			}
			disclosed[namespace] = append(disclosed[namespace], item.ElementIdentifier)
		}
	}
	return disclosed, nil
}

// ErrorsForRequest reports the data elements requested of this document that it
// does not carry, as the Errors map of 8.3.2.1.2.2 with Table 9's
// ErrorCodeDataNotReturned against each.
//
// This is what 8.3.2.1.2.1's "The mdoc shall ignore all unknown data elements in a
// device retrieval mdoc request when processing the request" amounts to on the
// response side: the elements that exist are returned, and the ones that do not
// are named here rather than failing the exchange.
//
// Returns nil when the document answers the request completely, which is the
// value Document.Errors should then hold — the member is absent, not empty.
//
// Elements withheld by the user are indistinguishable from elements the wallet
// never had, and both belong here: Table 9's only code covers the document not
// providing an element "without any given reason", which is exactly as much as a
// reader is entitled to learn about a refusal.
func (m MDoc) ErrorsForRequest(requested ItemsRequest) (Errors, error) {
	disclosed, err := m.DisclosedElements()
	if err != nil {
		return nil, err
	}

	var errors Errors
	for namespace, elements := range requested.NameSpaces {
		present := make(map[string]struct{}, len(disclosed[namespace]))
		for _, identifier := range disclosed[namespace] {
			present[identifier] = struct{}{}
		}
		for identifier := range elements {
			if _, ok := present[identifier]; ok {
				continue
			}
			if errors == nil {
				errors = Errors{}
			}
			if errors[namespace] == nil {
				errors[namespace] = ErrorItems{}
			}
			errors[namespace][identifier] = ErrorCodeDataNotReturned
		}
	}
	return errors, nil
}
