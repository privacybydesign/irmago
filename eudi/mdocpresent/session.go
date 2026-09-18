package mdocpresent

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
)

// ============================================================
// THE org-iso-mdoc SESSION
// ============================================================
//
// One exchange, start to finish: a DeviceRequest delivered by the W3C Digital
// Credentials API goes in, an HPKE-sealed DeviceResponse comes out.
//
// Everything cryptographic is in eudi/credentials/mdoc and everything about
// this wallet's own storage and consent is behind Discloser. What is left here
// is the order the steps go in, which is where the interesting mistakes live:
//
//  1. build the session transcript, before anything is verified or asked, because
//     reader authentication is checked *against* it;
//  2. authenticate the reader per document, never per session (7.2.1);
//  3. decide what each reader is allowed to be shown, authenticated or not;
//  4. ask the wallet, which asks the user;
//  5. sign, assemble and seal — and only then let the wallet commit.
//
// Step 5's ordering is the one worth stating twice: a single-use instance must
// not be spent on a response that is never produced. See Commit.

// Request is an org-iso-mdoc request as the platform delivered it.
//
// EncryptionInfo is the base64url text exactly as received and must not be
// re-encoded from a decoded structure — the session transcript hashes that text,
// so a re-encoding that differs by so much as padding produces a transcript the
// reader does not share. See mdoc.NewDCAPISessionTranscript.
//
// Origin is the web origin the platform authenticated for the caller. It is not
// a field of the request and cannot be recovered from one: a wallet that does
// not receive it from the browser or OS cannot answer at all, because the
// transcript binds to it.
type Request struct {
	DeviceRequest  []byte
	EncryptionInfo string
	Origin         string
}

func (r Request) validate() error {
	switch {
	case len(r.DeviceRequest) == 0:
		return fmt.Errorf("request carries no deviceRequest")
	case r.EncryptionInfo == "":
		return fmt.Errorf("request carries no encryptionInfo: org-iso-mdoc responses are always encrypted")
	case r.Origin == "":
		return fmt.Errorf("request carries no origin: the platform must supply the origin it authenticated, and the session transcript binds to it")
	}
	return nil
}

// RequestedDocument is one docRequest after the reader has been authenticated
// (or found not to be) and 7.2.1 has decided what that entitles it to.
//
// Requested is what the reader asked for. Permitted is the subset the wallet may
// release to *this* reader, which differs only when the reader is
// unauthenticated. Keeping both is what lets the response report what was
// withheld instead of silently answering a smaller question.
type RequestedDocument struct {
	DocType   string
	Requested mdoc.ItemsRequest
	Permitted mdoc.ItemsRequest
	Withheld  map[string][]string

	// Reader is the authentication result, or nil when the request carried no
	// readerAuth. Nil is an ordinary case rather than an error: ISO 18013-5 makes
	// reader authentication optional, and the captured EUDI Age Verification
	// reader sends none at all.
	Reader *mdoc.ReaderAuthResult

	// Zk is the reader's zkRequest for this document, or nil when it asked for a
	// plain disclosure. Per document rather than per session, because that is
	// where the reader puts it — see mdoc.ZkRequestKey.
	Zk *mdoc.ZkRequest
}

// ZkRequested reports whether the reader will accept a zero-knowledge proof for
// this document.
func (d RequestedDocument) ZkRequested() bool { return d.Zk != nil }

// ZkRequired reports whether the reader has refused the plain A.6 fallback. A
// wallet that cannot prove must fail the session rather than answer such a
// request in the clear.
func (d RequestedDocument) ZkRequired() bool { return d.Zk != nil && d.Zk.ZkRequired }

// Authenticated reports whether this document's request was signed by a reader
// whose certificate chained to a trusted anchor.
func (d RequestedDocument) Authenticated() bool { return d.Reader != nil }

// Servable reports whether anything at all may be released for this document.
// An unauthenticated reader asking only for elements 7.2.1 does not release
// leaves nothing to answer, which is a refusal rather than a failure.
func (d RequestedDocument) Servable() bool { return len(d.Permitted.NameSpaces) > 0 }

// DisclosureRequest is what the session asks the wallet for.
type DisclosureRequest struct {
	Origin    string
	Documents []RequestedDocument
}

// Selection is one document the wallet agreed to present, already narrowed to
// the elements the user consented to, together with the holder that can sign
// deviceAuth for it.
//
// Holder rather than a private key: the device key may live in hardware and is
// reached only through mdoc.Holder.
type Selection struct {
	DocType  string
	Document mdoc.MDoc
	Holder   mdoc.Holder
}

// Discloser is the wallet behind a session: it finds candidates, asks the user,
// and returns what they agreed to.
//
// Returning no selections is a refusal and is expected rather than exceptional —
// the user declining, or an unauthenticated reader asking for nothing it is
// entitled to. It produces an empty response, not an error.
type Discloser interface {
	Disclose(DisclosureRequest) ([]Selection, error)
}

// Committer is implemented by a Discloser that holds resources across a
// disclosure — in practice, the single-use instances a presentation spends.
//
// Commit is called once, after the response is assembled and sealed, which is
// the first moment nothing further can fail. Spending earlier would burn an
// instance on a response the verifier never receives: a use lost with nothing to
// show for it, and precisely the correlation that batch issuance exists to
// prevent.
type Committer interface {
	Commit() error
}

// Releaser gives back whatever a disclosure reserved and did not spend. Called
// on every path out of Respond, including the successful one, where releasing
// what Commit already spent is a no-op.
type Releaser interface {
	Release()
}

// Session answers one org-iso-mdoc request.
//
// Verifier authenticates readers. It may be nil, which is not the same as a
// reader failing to authenticate: a session with no verifier cannot evaluate any
// readerAuth, so every document is treated as unauthenticated and 7.2.1 decides
// what that is worth. That is the correct behaviour for a wallet with no reader
// trust store, and it is stated rather than left to a nil dereference.
type Session struct {
	Verifier  *mdoc.Verifier
	Discloser Discloser

	// ZkSystems are the zero-knowledge systems this build has. Nil is the
	// ordinary state of a build without the native prover, not an error: A.8
	// requires that such a build "fall back to the plain ISO mDoc presentation
	// defined in Section A.6", so absence routes to the fallback. It becomes a
	// failure only against a reader that set zkRequired.
	ZkSystems *mdoc.ZkSystemRepository

	// Now supplies the timestamp a proof is taken at. Nil means time.Now.
	// Injectable because the timestamp is inside the statement the circuit
	// proves, so a test cannot assert on a proof it cannot pin the clock for.
	Now func() time.Time
}

func (s *Session) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Respond runs the whole exchange and returns the sealed response.
func (s *Session) Respond(request Request) (mdoc.DCAPIEncryptedResponse, error) {
	var empty mdoc.DCAPIEncryptedResponse

	if s.Discloser == nil {
		return empty, fmt.Errorf("session has no discloser: nothing can be presented")
	}
	if err := request.validate(); err != nil {
		return empty, err
	}

	// Only the key is taken from the decoded form. The nonce is not read here:
	// it reaches the response through the transcript, which hashes the encoded
	// text rather than anything recovered from it.
	recipient, err := recipientKeyFrom(request.EncryptionInfo)
	if err != nil {
		return empty, err
	}

	// Built first: reader authentication is verified against this transcript, so
	// it has to exist before any docRequest is judged.
	transcript, err := mdoc.NewDCAPISessionTranscript(request.EncryptionInfo, request.Origin)
	if err != nil {
		return empty, fmt.Errorf("build session transcript: %w", err)
	}

	deviceRequest, err := mdoc.DecodeDeviceRequest(request.DeviceRequest)
	if err != nil {
		return empty, fmt.Errorf("decode deviceRequest: %w", err)
	}
	if err := deviceRequest.Validate(); err != nil {
		return empty, fmt.Errorf("invalid deviceRequest: %w", err)
	}

	documents, err := s.evaluate(deviceRequest, transcript)
	if err != nil {
		return empty, err
	}

	// Before the user is asked anything. A reader that set zkRequired against a
	// build with no usable system is going to be refused whatever the user says,
	// and prompting first would collect consent for a disclosure that then never
	// happens — the one outcome worse than refusing early, because the user has
	// agreed to something and has no way to tell it did not occur.
	if err := s.checkZkSatisfiable(documents); err != nil {
		return empty, err
	}

	selections, err := s.Discloser.Disclose(DisclosureRequest{
		Origin:    request.Origin,
		Documents: documents,
	})
	if releaser, ok := s.Discloser.(Releaser); ok {
		defer releaser.Release()
	}
	if err != nil {
		return empty, fmt.Errorf("disclose: %w", err)
	}

	response, err := s.assemble(documents, selections, transcript)
	if err != nil {
		return empty, err
	}

	// Encode rather than cbor.Marshal: Encode validates first, so a response this
	// session assembled wrongly is caught here instead of at the reader.
	encoded, err := response.Encode()
	if err != nil {
		return empty, fmt.Errorf("encode deviceResponse: %w", err)
	}

	sealed, err := mdoc.SealDCAPIResponse(encoded, recipient, transcript)
	if err != nil {
		return empty, err
	}

	// Last, when nothing further can fail: the response exists and is sealed, so
	// an instance spent now is an instance the verifier will actually receive.
	if committer, ok := s.Discloser.(Committer); ok {
		if err := committer.Commit(); err != nil {
			return empty, fmt.Errorf("commit disclosure: %w", err)
		}
	}

	return sealed, nil
}

// recipientKeyFrom recovers the reader's ephemeral public key from the base64url
// EncryptionInfo.
//
// The decoded structure is deliberately not returned. Everything else the
// transcript needs comes from the encoded *text*, and handing callers a decoded
// copy is how a re-encoding of it ends up in the digest by accident.
func recipientKeyFrom(encoded string) (*ecdsa.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
	if err != nil {
		return nil, fmt.Errorf("encryptionInfo is not base64url: %w", err)
	}
	var info mdoc.DCAPIEncryptionInfo
	if err := cbor.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("decode encryptionInfo: %w", err)
	}
	key, err := info.RecipientKey()
	if err != nil {
		return nil, fmt.Errorf("encryptionInfo: %w", err)
	}
	return key, nil
}

// evaluate authenticates the reader for each requested document and works out
// what it is entitled to see.
//
// Per document, not per session. The decision belongs to each docRequest because
// a session that refused an unauthenticated reader outright and one that served
// everything to it are both wrong, and which applies differs per docType.
//
// # 18013-5 7.2.1 does NOT bind this transport, and that is a live choice
//
// 18013-5 7.2.1 says "An mDL shall not require mdoc reader authentication as a
// precondition for the release of any of the mandatory data elements", and
// ReleasableWithoutReaderAuth implements exactly that.
//
// ISO/IEC TS 18013-7:2025 Clause 7 lifts it for the transports IT defines —
// which is this one, Annex C being the org-iso-mdoc retrieval this package
// answers: "The mDL data model descriptions and requirements in ISO/IEC 18013-5
// shall apply in this document with the following exception: an mDL may require
// mdoc reader authentication as a precondition for the release of any of the
// mandatory data elements. NOTE This differs from the corresponding requirement
// in ISO/IEC 18013-5."
//
// So over the DC API this wallet MAY refuse an unauthenticated reader every
// element, mDL mandatory ones included — which is what its policy elsewhere does
// (see the AV docType in profile.go, and mdoc.VerifyReaderAuth). It currently
// does not: the carve-out is applied here as written for 18013-5, which is
// permitted but more generous than the policy. Tightening it is a deliberate
// decision about what leaves the wallet, not a bug fix, so it is recorded rather
// than taken.
func (s *Session) evaluate(request mdoc.DeviceRequest, transcript mdoc.SessionTranscript) ([]RequestedDocument, error) {
	documents := make([]RequestedDocument, 0, len(request.DocRequests))

	for i, docRequest := range request.DocRequests {
		items, err := docRequest.Items()
		if err != nil {
			return nil, fmt.Errorf("docRequest %d: %w", i, err)
		}

		zkRequest, zkRequested, err := mdoc.ZkRequestFrom(items)
		if err != nil {
			return nil, fmt.Errorf("docRequest %d (%s): %w", i, items.DocType, err)
		}

		var reader *mdoc.ReaderAuthResult
		if s.Verifier != nil {
			result, err := s.Verifier.VerifyReaderAuth(docRequest, transcript)
			switch {
			case err == nil:
				reader = result
			case errors.Is(err, mdoc.ErrNoReaderAuth):
				// Absent, not invalid. 7.2.1 decides what that is worth below.
			default:
				// Present and bad. This is not the same as absent: someone signed
				// this request and the signature does not stand up, so serving even
				// the 7.2.1 minimum would be answering a request whose origin is in
				// doubt.
				return nil, fmt.Errorf("docRequest %d (%s): reader authentication failed: %w",
					i, items.DocType, err)
			}
		}

		document := RequestedDocument{
			DocType:   items.DocType,
			Requested: items,
			Reader:    reader,
		}
		if zkRequested {
			document.Zk = &zkRequest
		}
		if reader != nil {
			document.Permitted = items
		} else {
			releasable, withheld := mdoc.ReleasableWithoutReaderAuth(items)
			document.Permitted = mdoc.ItemsRequest{DocType: items.DocType, NameSpaces: releasable}
			document.Withheld = withheld
		}
		documents = append(documents, document)
	}

	return documents, nil
}

// assemble signs each selected document over the session transcript, records what
// could not be returned, and bundles the result into a DeviceResponse.
//
// A selection with no documents produces a response with no documents, which is
// a refusal expressed the way 8.3.2.1.2.2 expresses one: status 0, nothing to
// show, and a documentError naming each document that was asked for. A non-zero
// status would say the request could not be processed, which is not what happened
// when a user simply declined.
//
// requested is the session's full list, not the servable subset: a document the
// wallet never offered the user still has to be reported to the reader.
func (s *Session) assemble(
	requested []RequestedDocument,
	selections []Selection,
	transcript mdoc.SessionTranscript,
) (mdoc.DeviceResponse, error) {
	var (
		documents   = make([]mdoc.MDoc, 0, len(selections))
		zkDocuments = make([]mdoc.ZkDocument, 0, len(selections))
		served      = make(map[string]bool, len(selections))
	)

	for _, selection := range selections {
		asked, ok := documentFor(requested, selection.DocType)
		if !ok {
			return mdoc.DeviceResponse{}, fmt.Errorf(
				"wallet selected a %s document, which this request did not ask for", selection.DocType)
		}

		// The ordinary presentation path runs first and unchanged, ZK or not.
		// That is not an optimisation to skip when a proof is wanted: the proof
		// covers the device signature over this session's transcript, so the
		// document must already carry its DeviceSigned before it can be proved.
		// longfellow's prover refuses one that does not, with
		// MDOC_PROVER_DEVICE_SIGNED_MISSING.
		document, err := signDocument(selection, asked.Requested, transcript)
		if err != nil {
			return mdoc.DeviceResponse{}, err
		}
		served[selection.DocType] = true

		if asked.ZkRequested() {
			zkDocument, proved, err := s.prove(asked, *document, transcript)
			if err != nil {
				return mdoc.DeviceResponse{}, err
			}
			if proved {
				// The plain document does NOT also travel. Sending both would
				// disclose in the clear exactly what the proof exists to keep
				// hidden, and the reader would have no reason to look at the proof.
				zkDocuments = append(zkDocuments, *zkDocument)
				continue
			}
			if asked.ZkRequired() {
				return mdoc.DeviceResponse{}, fmt.Errorf(
					"reader requires a zero-knowledge proof for %s and this build cannot produce one: "+
						"answering in the clear would disclose more than the reader asked for", selection.DocType)
			}
			// A.8's fallback: "where the User's device does not support
			// Zero-Knowledge Proof generation, the AVI SHALL fall back to the
			// plain ISO mDoc presentation defined in Section A.6."
		}
		documents = append(documents, *document)
	}

	// Every requested document that is not being returned gets a documentError.
	// 8.3.2.1.2.2 keeps the two failure kinds apart and they are not
	// interchangeable: documentErrors is "for unreturned documents",
	// Document.Errors "can contain error codes for data elements that are not
	// returned" from a document that IS returned.
	//
	// Returning either is a may, not a shall — see the clause quoted in
	// WalletDiscloser's partial-satisfaction header for why this package does it
	// regardless.
	var documentErrors []mdoc.DocumentError
	for _, document := range requested {
		if served[document.DocType] {
			continue
		}
		documentError, err := mdoc.NewDocumentError(document.DocType, mdoc.ErrorCodeDataNotReturned)
		if err != nil {
			return mdoc.DeviceResponse{}, fmt.Errorf("build documentError for %s: %w", document.DocType, err)
		}
		documentErrors = append(documentErrors, documentError)
	}

	// Status stays 0 throughout. 8.3.2.1.2.3 forbids returning documents with a
	// non-zero status, so reporting "you cannot have this" as a status would throw
	// away everything the wallet DID agree to release in the same request.
	// Both lists can be non-empty at once: zkRequest is per docRequest, so a
	// reader may ask for a proof of one document and a plain disclosure of
	// another. WithZkDocuments is what keeps the version correct for that case.
	response := mdoc.NewDeviceResponse(documents...)
	if len(zkDocuments) > 0 {
		response = response.WithZkDocuments(zkDocuments...)
	}
	if len(documentErrors) > 0 {
		response = response.WithDocumentErrors(documentErrors...)
	}
	return response, nil
}

// checkZkSatisfiable refuses, before the user is asked anything, a request this
// build cannot possibly answer.
//
// Only the cases that are decidable without knowing what the user will pick:
// zkRequired against a build with no prover at all, or against one holding no
// circuit from any system the reader offered. Whether a circuit exists for the
// number of elements finally disclosed cannot be known yet and is caught in
// assemble.
func (s *Session) checkZkSatisfiable(documents []RequestedDocument) error {
	for _, document := range documents {
		if !document.ZkRequired() {
			continue
		}
		var haveSystem bool
		for _, offered := range document.Zk.SystemSpecs {
			if s.ZkSystems.Lookup(offered.System) != nil {
				haveSystem = true
				break
			}
		}
		if !haveSystem {
			return fmt.Errorf(
				"reader requires a zero-knowledge proof for %s under one of %d offered systems and this build has none: "+
					"the reader has refused the plain fallback, so there is nothing to present",
				document.DocType, len(document.Zk.SystemSpecs))
		}
	}
	return nil
}

// prove turns a signed document into a zero-knowledge presentation of it.
//
// The false return is a fallback rather than a failure and covers every way a
// build can come up short: no prover compiled in, no circuit in common with the
// reader, or no circuit built for this many elements. The caller decides what
// that means, which is ZkRequest.ZkRequired's decision to make.
//
// An error, by contrast, is a prover that was selected and then failed. That is
// never a fallback: a wallet that quietly disclosed in the clear because proving
// broke would turn a crash into an over-disclosure.
func (s *Session) prove(
	asked RequestedDocument,
	document mdoc.MDoc,
	transcript mdoc.SessionTranscript,
) (*mdoc.ZkDocument, bool, error) {
	disclosed, err := document.DisclosedElements()
	if err != nil {
		return nil, false, fmt.Errorf("count disclosed elements of %s: %w", asked.DocType, err)
	}
	var count int
	for _, elements := range disclosed {
		count += len(elements)
	}

	// Counted after narrowing, not from the request. A circuit is built for an
	// exact number of attributes, and what the proof is over is what the user
	// actually agreed to disclose — which partial satisfaction may have made
	// smaller than what the reader asked for.
	system, spec, ok := s.ZkSystems.SelectProver(*asked.Zk, count)
	if !ok {
		return nil, false, nil
	}

	zkDocument, err := system.GenerateProof(spec, document, transcript, s.now())
	if err != nil {
		return nil, false, fmt.Errorf("generate %s proof for %s: %w", system.Name(), asked.DocType, err)
	}
	if zkDocument == nil {
		return nil, false, fmt.Errorf("%s returned no proof and no error for %s", system.Name(), asked.DocType)
	}
	return zkDocument, true, nil
}

// documentFor finds what the reader asked of a docType.
func documentFor(documents []RequestedDocument, docType string) (RequestedDocument, bool) {
	for _, document := range documents {
		if document.DocType == docType {
			return document, true
		}
	}
	return RequestedDocument{}, false
}

// signDocument signs one selected document for this session and records the
// elements it could not return.
func signDocument(
	selection Selection,
	requested mdoc.ItemsRequest,
	transcript mdoc.SessionTranscript,
) (*mdoc.MDoc, error) {
	if selection.Holder == nil {
		return nil, fmt.Errorf(
			"selection for %s carries no holder: nothing can sign deviceAuth for it", selection.DocType)
	}
	// DeviceAuthentication binds the docType, and a verifier reads it from the
	// document rather than from whatever the wallet labelled the selection with.
	// Disagreeing here produces a signature over a docType the document does not
	// carry — valid CBOR, valid HPKE, and a signature check that fails at the
	// reader with nothing naming the cause.
	if selection.Document.DocType != selection.DocType {
		return nil, fmt.Errorf(
			"selection is labelled %s but carries a %s document: deviceAuth would sign a docType the document does not have",
			selection.DocType, selection.Document.DocType)
	}

	deviceAuth, err := selection.Holder.SignDeviceAuth(selection.DocType, transcript)
	if err != nil {
		return nil, fmt.Errorf("sign deviceAuth for %s: %w", selection.DocType, err)
	}

	document, err := mdoc.AttachDeviceSigned(&selection.Document, deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("attach deviceSigned for %s: %w", selection.DocType, err)
	}

	// This is the other half of the partial-satisfaction fix in WalletDiscloser.
	// narrow answers with what the wallet has; this says what it did not.
	//
	// Comparing against the ORIGINAL request rather than the permitted one is what
	// makes the reader's view complete: an element withheld because the reader did
	// not authenticate is reported with the same Table 9 code as one the wallet
	// does not hold, which is the truthful answer — in both cases the data was
	// requested and is not being returned. Reporting only the unheld ones would
	// tell an unauthenticated reader that the wallet holds nothing it withheld.
	errs, err := document.ErrorsForRequest(requested)
	if err != nil {
		return nil, fmt.Errorf("compute errors for %s: %w", selection.DocType, err)
	}
	document.Errors = errs

	return document, nil
}
