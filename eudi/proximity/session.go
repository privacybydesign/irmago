package proximity

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
)

// ============================================================
// THE MDOC SIDE OF A DEVICE RETRIEVAL SESSION
// ============================================================
//
// This is the orchestrator the pieces in eudi/credentials/mdoc were built for.
// Each of those files implements one clause and is tested in isolation; until now
// nothing drove them in sequence, which is the part where a transaction either
// works or does not.
//
// The sequence, and the clause that fixes each step:
//
//	engagement       8.2.1.1 / 8.2.2.3   DeviceEngagement, offered as a QR code
//	establishment    9.1.1.4             SessionEstablishment carries EReaderKey
//	transcript       9.1.5.1             QRHandover over both parties' key bytes
//	session keys     9.1.1.5             SKDevice / SKReader, counters from 1
//	request          8.3.2.1.2.1         DeviceRequest, decrypted from the above
//	reader auth      9.1.4               per DocRequest, against the Verifiers store
//	release policy   7.2.1               what survives an unauthenticated reader
//	consent          --                  the wallet's, via Discloser
//	disclosure       8.3.2.1.2.2         SelectiveDisclose + deviceAuth + errors
//	response         8.3.2.1.2.3         DeviceResponse, encrypted into SessionData
//	termination      9.1.1.4 / Table 20  status 20, then destroy the keys
//
// # What this type does NOT do
//
// It moves no bytes. Handle takes one complete, reassembled message and returns
// the one to send back, so the transport — BLE in production (ble.go's chunking
// and MessageAssembler), net.Pipe in the Tier 0 tests — stays entirely outside.
// That boundary is what lets the whole flow be exercised with no radio and no
// second device.
//
// It also decides nothing about which credentials exist or whether the user
// agrees. That is Discloser.

// DeviceKeyBinder resolves the device key a presentation must be signed with,
// given the device public key the credential's MSO is bound to.
//
// Deliberately the same shape as mdoc_dcql.DeviceKeyBinder rather than a shared
// import: the two packages are independent entry points into the same wallet, and
// one implementation (services.NewMdocDeviceKeyBinder) satisfies both. Keeping the
// private half behind this interface is what lets a hardware-backed device key
// work here unchanged — see mdoc.NewHolderFromSigner.
type DeviceKeyBinder interface {
	HolderForDeviceKey(deviceKey *ecdsa.PublicKey) (mdoc.Holder, error)
}

// Selection is one document the wallet has decided to disclose, after candidate
// selection and user consent.
//
// Reveal names the elements to keep; everything else in the namespace is stripped
// before the document is signed. Elements the reader asked for that are not in
// Reveal — because the wallet does not hold them, because the user declined, or
// because reader authentication did not permit them — are reported back as Table 9
// errors rather than silently omitted. See buildDocument.
type Selection struct {
	// Document is the issuer-signed credential instance to present, with no
	// DeviceSigned: one is attached per presentation.
	Document mdoc.MDoc

	// Reveal maps namespace to the element identifiers to keep. A map rather than
	// one namespace and one list because 7.1 lets an issuing authority add
	// namespaces to a document and a single DocRequest may name elements in
	// several; everything not named here is stripped before signing.
	Reveal map[string][]string

	// QueryId names the credential query, and so the DocRequest, this selection
	// answers. Set it whenever the wallet knows it.
	//
	// Nothing else can carry that link reliably. A DeviceRequest may hold two
	// DocRequests of the SAME docType — "give me the mDL's portrait" and "give me
	// the mDL's age_over_18" are two requests, and 8.3.2.1.2.1 does not forbid a
	// reader splitting them — and matching a returned document to its request by
	// docType alone then answers the wrong one, strips it against the wrong
	// ItemsRequest and leaves the other request with no documentError at all.
	//
	// Optional, because a Discloser that never sees the DCQL query cannot fill it
	// in: empty means "match by docType", which is exactly right for the ordinary
	// request where each docType appears once. See requestedFor.
	QueryId string
}

// RequestedDocument is one DocRequest after parsing, reader authentication and the
// 7.2.1 release policy have run over it.
type RequestedDocument struct {
	DocType string

	// Requested is the ItemsRequest exactly as the reader sent it.
	Requested mdoc.ItemsRequest

	// Permitted is Requested narrowed to what this reader is allowed to receive. It
	// equals Requested for an authenticated reader. For an unauthenticated one it
	// is whatever 7.2.1 still permits: the mDL's mandatory elements, and for every
	// other docType nothing at all.
	//
	// The user is never asked about an element that is not in here, which is why
	// the narrowing happens before consent rather than after it.
	Permitted mdoc.ItemsRequest

	// Reader is the authenticated reader identity, or nil.
	Reader *mdoc.ReaderAuthResult

	// ReaderAuthErr is why authentication failed, when a readerAuth was present but
	// did not verify. Kept so the wallet can distinguish "did not authenticate"
	// from "tried to authenticate and failed" — very different things to show a
	// user, and mdoc.ErrNoReaderAuth exists to keep them apart.
	ReaderAuthErr error
}

// Authenticated reports whether this document's request came from a reader whose
// certificate chained to a trusted anchor.
func (d RequestedDocument) Authenticated() bool { return d.Reader != nil }

// Servable reports whether anything at all may be released for this document.
// False means the reader asked for something it is not entitled to without
// authenticating, and the response carries a DocumentError instead.
func (d RequestedDocument) Servable() bool { return len(d.Permitted.NameSpaces) > 0 }

// DisclosureRequest is what the wallet is asked to decide on.
type DisclosureRequest struct {
	// Query is the reader's request translated into the wallet's own query
	// language, so proximity reuses the candidate selection, claim matching, consent
	// screen and disclosure log that already exist. It is built from the PERMITTED
	// items, never the requested ones.
	Query dcql.DcqlQuery

	// Documents is the per-DocRequest detail behind Query, in the order the reader
	// sent them. A wallet that only needs the query can ignore it; a wallet that
	// wants to show who is asking needs Reader.
	Documents []RequestedDocument
}

// Discloser is the wallet: it finds candidates, asks the user, and returns what may
// be sent.
//
// Returning an empty slice is a valid answer and means "nothing" — a refusal at the
// consent screen, or no credential matching the query. It produces a response
// carrying documentErrors rather than a failed session, because a reader learning
// that the wallet will not answer is a normal outcome of a transaction rather than
// a protocol error.
type Discloser interface {
	Disclose(DisclosureRequest) ([]Selection, error)
}

// Committer is an optional Discloser extension, for a wallet whose credentials are
// single-use.
//
// Commit is called once every selected document has been signed and the response
// assembled — that is, at the first moment nothing further can fail. A wallet that
// spent its credential instance inside Disclose instead would burn one whenever a
// later step errored, and the credential would silently lose a use having
// disclosed nothing. The OpenID4VP path orders itself the same way, which is why
// services.MdocInstanceSelector separates Reserve from Spend.
//
// A Discloser that does not implement this is simply never committed, which is
// correct for a wallet holding reusable credentials.
type Committer interface {
	Commit() error
}

// Releaser is the other half of Committer, for the transactions that end without
// one.
//
// Reserving a single-use credential takes it out of circulation for as long as
// the disclosure it was chosen for might still succeed. A transaction that then
// fails — the response would not assemble, a signature would not produce — has
// to give those back, or the wallet spends the rest of its life believing they
// are in use by a session that ended. Separate from Committer because the two
// are answers to opposite questions, and a Discloser holding reusable
// credentials should have to implement neither.
type Releaser interface {
	Release()
}

// SessionConfig is everything a Session needs that it cannot generate itself.
type SessionConfig struct {
	// Discloser is the wallet's side of the transaction. Required.
	Discloser Discloser

	// DeviceKeys resolves the signer for each disclosed credential. Required.
	DeviceKeys DeviceKeyBinder

	// Readers authenticates the mdoc reader (9.1.4). Required: this wallet mirrors
	// its OpenID4VP policy, where a verifier that cannot be authenticated is not
	// talked to. Build it as mdoc.NewVerifierFromTrustSource(conf.Verifiers) — the
	// same store that authenticates an OpenID4VP relying party.
	Readers *mdoc.Verifier

	// ServiceUUID is the BLE service UUID this transaction advertises (8.3.3.1.1.3,
	// unique per transaction). Generated when nil.
	ServiceUUID []byte

	// Debugf, when set, receives a line for every decision that is invisible in the
	// response: a request refused at decode or validation, the outcome of reader
	// authentication, and a document that ends up with nothing releasable.
	//
	// Those paths are deliberately quiet on the wire — 8.3.2.1.2.3 gives the reader
	// a status code and nothing else, which is right, and leaves the wallet with no
	// way to say why. Without this, "the reader received 21 bytes" is the whole
	// story available to anyone debugging a transport.
	//
	// Never given credential contents: element identifiers, docTypes and error
	// reasons only.
	Debugf func(format string, args ...any)
}

type sessionState int

const (
	// stateEngaging: the QR is available and the reader has not spoken yet.
	stateEngaging sessionState = iota
	// stateEstablished: session keys exist and messages are SessionData.
	stateEstablished
	// stateTerminated: keys destroyed, nothing further will be processed.
	stateTerminated
)

// Session is one mdoc-side device retrieval transaction.
//
// Not safe for concurrent use: it owns a mdoc.Session, whose message counters carry
// the one rule in Clause 9 whose breach is catastrophic rather than merely
// non-conformant (9.1.1.5 — never reuse a counter under the same key).
type Session struct {
	cfg SessionConfig

	state sessionState

	eDeviceKey      *ecdsa.PrivateKey
	engagement      mdoc.DeviceEngagement
	engagementBytes cbor.RawMessage

	transcript mdoc.SessionTranscript
	crypto     *mdoc.Session
}

// NewSession generates this transaction's ephemeral device key and engagement.
//
// The key is generated here and never leaves: EDeviceKey is ephemeral and
// per-transaction, unlike the static device key in a credential's MSO that
// deviceAuth signs with. Confusing the two produces a session that encrypts
// correctly and authenticates nothing.
func NewSession(cfg SessionConfig) (*Session, error) {
	switch {
	case cfg.Discloser == nil:
		return nil, fmt.Errorf("proximity session needs a Discloser to ask the wallet what may be released")
	case cfg.DeviceKeys == nil:
		return nil, fmt.Errorf("proximity session needs a DeviceKeyBinder to sign deviceAuth")
	case cfg.Readers == nil:
		return nil, fmt.Errorf(
			"proximity session needs a reader trust model: this wallet requires mdoc reader " +
				"authentication (9.1.4), mirroring its OpenID4VP verifier policy")
	}

	eDeviceKey, err := mdoc.GenerateEDeviceKey()
	if err != nil {
		return nil, fmt.Errorf("generate EDeviceKey: %w", err)
	}

	serviceUUID := cfg.ServiceUUID
	if serviceUUID == nil {
		if serviceUUID, err = mdoc.NewTransactionUUID(); err != nil {
			return nil, fmt.Errorf("generate BLE service UUID: %w", err)
		}
	}

	// mdoc central client mode: the wallet is the GATT client and never advertises.
	// 8.3.3.1.1.1 defines both modes and says a reader should select central client
	// when the mdoc indicates both, so advertising only this one leaves the reader
	// no choice to make and halves the native surface.
	engagement, err := mdoc.NewBLECentralClientEngagement(&eDeviceKey.PublicKey, serviceUUID)
	if err != nil {
		return nil, fmt.Errorf("build device engagement: %w", err)
	}
	engagementBytes, err := engagement.DeviceEngagementBytes()
	if err != nil {
		return nil, fmt.Errorf("encode DeviceEngagementBytes: %w", err)
	}

	return &Session{
		cfg:             cfg,
		state:           stateEngaging,
		eDeviceKey:      eDeviceKey,
		engagement:      engagement,
		engagementBytes: engagementBytes,
	}, nil
}

// debugf reports a decision the response cannot carry. No-op unless the caller
// asked for it.
func (s *Session) debugf(format string, args ...any) {
	if s.cfg.Debugf != nil {
		s.cfg.Debugf(format, args...)
	}
}

// EngagementQR returns the "mdoc:" URI of 8.2.2.3 for this transaction.
//
// It carries the bare DeviceEngagement, not DeviceEngagementBytes, and needs no
// network on either side — everything the reader needs to open the session is in
// the code.
func (s *Session) EngagementQR() (string, error) {
	return s.engagement.QRCodeURI()
}

// ServiceUUID is the BLE service the reader should look for, taken from the
// engagement this session generated.
func (s *Session) ServiceUUID() ([]byte, error) {
	method, err := s.engagement.SelectRetrievalMethod(mdoc.RetrievalMethodBLE)
	if err != nil {
		return nil, err
	}
	options, ok, err := method.BleOptions()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("engagement offers no BLE retrieval method")
	}
	return options.CentralClientModeUUID, nil
}

// Terminated reports whether the session is over. A terminated session has
// destroyed its keys and refuses further messages.
func (s *Session) Terminated() bool { return s.state == stateTerminated }

// Handle processes one complete message from the reader and returns the one to send
// back, or nil when there is nothing to say.
//
// The caller supplies whole messages: on BLE that means the output of
// mdoc.MessageAssembler, and the reply goes back out through mdoc.ChunkMessage.
//
// An error return is a local fault the reader cannot be told about. Everything the
// reader IS told about — an undecryptable message, malformed CBOR, a request that
// cannot be served — comes back as a reply carrying the right status code, because
// those are outcomes of the protocol rather than failures of it.
func (s *Session) Handle(message []byte) ([]byte, error) {
	switch s.state {
	case stateTerminated:
		return nil, fmt.Errorf("session is terminated")
	case stateEngaging:
		return s.handleEstablishment(message)
	default:
		return s.handleSessionData(message)
	}
}

// handleEstablishment processes the first message (9.1.1.4): the reader's ephemeral
// public key and the first encrypted request, together.
func (s *Session) handleEstablishment(message []byte) ([]byte, error) {
	establishment, err := mdoc.DecodeSessionEstablishment(message)
	if err != nil {
		// Table 20 status 11, and the session ends. No keys exist yet, so there is
		// nothing to destroy — but the state still has to move, or a peer could keep
		// retrying establishment forever.
		return s.terminateWith(mdoc.StatusErrorCBORDecoding)
	}

	eReaderKey, err := establishment.EReaderKey()
	if err != nil {
		return s.terminateWith(mdoc.StatusErrorCBORDecoding)
	}

	// 9.1.5.1. Both leading slots hold their tag-24 encodings inline, and the
	// reader's key bytes must be the ones that ARRIVED: re-encoding a parsed
	// COSE_Key yields different bytes, a different transcript, and session keys that
	// agree with nothing.
	transcript, err := mdoc.NewQRSessionTranscript(s.engagementBytes, establishment.EReaderKeyBytes)
	if err != nil {
		return s.terminateWith(mdoc.StatusErrorCBORDecoding)
	}
	s.transcript = transcript

	crypto, err := mdoc.NewMdocSession(s.eDeviceKey, eReaderKey, transcript)
	if err != nil {
		return s.terminateWith(mdoc.StatusErrorSessionEncryption)
	}
	s.crypto = crypto
	s.state = stateEstablished

	plaintext, err := crypto.Decrypt(establishment.Data)
	if err != nil {
		return s.terminateWith(mdoc.StatusErrorSessionEncryption)
	}

	return s.answer(plaintext)
}

// handleSessionData processes every later message (9.1.1.4).
func (s *Session) handleSessionData(message []byte) ([]byte, error) {
	data, err := mdoc.DecodeSessionData(message)
	if err != nil {
		return s.terminateWith(mdoc.StatusErrorCBORDecoding)
	}

	// A status from the reader ends the session: 20 is an orderly termination,
	// anything else is the reader reporting it cannot continue. Either way the keys
	// go and there is nothing to reply to — answering a termination would be a
	// message the peer has already stopped reading.
	if data.Status != nil {
		s.destroy()
		return nil, nil
	}

	if len(data.Data) == 0 {
		return s.terminateWith(mdoc.StatusErrorCBORDecoding)
	}

	plaintext, err := s.crypto.Decrypt(data.Data)
	if err != nil {
		// Decrypt deliberately does not advance the receive counter on failure, but a
		// message that failed to decrypt has desynchronised the stream in every case
		// that matters. Table 20 gives this its own code precisely because it is
		// unrecoverable.
		return s.terminateWith(mdoc.StatusErrorSessionEncryption)
	}

	return s.answer(plaintext)
}

// answer turns a decrypted DeviceRequest into an encrypted DeviceResponse.
func (s *Session) answer(plaintext []byte) ([]byte, error) {
	response, err := s.respondTo(plaintext)
	if err != nil {
		return nil, err
	}

	encoded, err := response.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode DeviceResponse: %w", err)
	}
	ciphertext, err := s.crypto.Encrypt(encoded)
	if err != nil {
		return nil, fmt.Errorf("encrypt DeviceResponse: %w", err)
	}
	sessionData, err := mdoc.NewSessionData(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("wrap DeviceResponse in SessionData: %w", err)
	}
	return sessionData.Encode()
}

// terminateWith destroys the session state and returns the status message to send.
//
// 9.1.1.4 requires both parties to destroy the session keys and ephemeral key
// material on termination, which is why this is the only path that ends a session
// and why it always runs destroy.
func (s *Session) terminateWith(status uint) ([]byte, error) {
	s.destroy()
	return mdoc.NewSessionStatus(status).Encode()
}

// destroy zeroes what can be zeroed and marks the session over.
func (s *Session) destroy() {
	if s.crypto != nil {
		s.crypto.Close()
	}
	s.eDeviceKey = nil
	s.state = stateTerminated
}

// Close ends the session from this side, returning Table 20's termination message
// to send if the session was still live.
//
// Safe to call more than once; a terminated session returns nil.
func (s *Session) Close() ([]byte, error) {
	if s.state == stateTerminated {
		return nil, nil
	}
	return s.terminateWith(mdoc.StatusSessionTermination)
}

// respondTo runs the whole request-to-response path.
func (s *Session) respondTo(requestBytes []byte) (mdoc.DeviceResponse, error) {
	request, err := mdoc.DecodeDeviceRequest(requestBytes)
	if err != nil {
		// A malformed request is reportable in the response rather than by killing the
		// session: Table 8 has a code for exactly this, and 8.3.2.1.2.3 lets the mdoc
		// return it with no documents.
		s.debugf("DeviceRequest could not be decoded, answering with status %d: %v",
			mdoc.ResponseStatusCBORDecodingError, err)
		return mdoc.NewErrorDeviceResponse(mdoc.ResponseStatusCBORDecodingError)
	}
	if err := request.Validate(); err != nil {
		s.debugf("DeviceRequest is structurally invalid, answering with status %d: %v",
			mdoc.ResponseStatusCBORValidationError, err)
		return mdoc.NewErrorDeviceResponse(mdoc.ResponseStatusCBORValidationError)
	}
	s.debugf("DeviceRequest carries %d docRequest(s)", len(request.DocRequests))

	documents, err := s.classify(request)
	if err != nil {
		return mdoc.DeviceResponse{}, err
	}

	selections, offered, err := s.consent(documents)
	if err != nil {
		return mdoc.DeviceResponse{}, err
	}

	response, err := s.assemble(documents, offered, selections)
	if err != nil {
		// Assembly is the step Reserve-then-Commit exists to survive, and surviving
		// it means handing back what the disclosure had claimed. See Releaser.
		s.releaseDisclosure()
		return mdoc.DeviceResponse{}, err
	}

	// Last, when nothing further can fail. See Committer.
	if committer, ok := s.cfg.Discloser.(Committer); ok && len(selections) > 0 {
		if err := committer.Commit(); err != nil {
			s.releaseDisclosure()
			return mdoc.DeviceResponse{}, fmt.Errorf("commit disclosure: %w", err)
		}
	}
	return response, nil
}

// releaseDisclosure gives back whatever the discloser reserved for a transaction
// that will not complete. A Discloser with nothing to give back implements
// nothing and is skipped.
func (s *Session) releaseDisclosure() {
	if releaser, ok := s.cfg.Discloser.(Releaser); ok {
		releaser.Release()
	}
}

// classify runs reader authentication and the 7.2.1 release policy over every
// DocRequest.
//
// # Why this is per document rather than per session
//
// The obvious reading of "mandatory reader authentication" is to terminate the
// session when it fails, which is what the OpenID4VP path does with a verifier it
// cannot authenticate. 7.2.1 forbids that here whenever an mDL is among the
// documents asked for: "An mDL shall not require mdoc reader authentication as a
// precondition for the release of any of the mandatory data elements", with NOTE 3
// explaining the intent — the holder can always use the mDL as a driving licence,
// "including if an mDL reader does not use mdoc reader authentication".
// Terminating would make reader authentication a precondition for those elements
// too, so the prohibition is breached by the session-level policy, not honoured by
// it.
//
// So the policy is applied at the level 7.2.1 words it at: the data element. An
// unauthenticated reader gets the mandatory elements of an mDL and nothing from any
// other docType, and a request mixing the two is served in part rather than
// refused whole.
func (s *Session) classify(request mdoc.DeviceRequest) ([]RequestedDocument, error) {
	documents := make([]RequestedDocument, 0, len(request.DocRequests))

	for i, docRequest := range request.DocRequests {
		items, err := docRequest.Items()
		if err != nil {
			return nil, fmt.Errorf("read itemsRequest of docRequest %d: %w", i, err)
		}

		document := RequestedDocument{DocType: items.DocType, Requested: items}

		result, err := s.cfg.Readers.VerifyReaderAuth(docRequest, s.transcript)
		switch {
		case err == nil:
			s.debugf("docRequest %d (%s): reader authenticated as %q", i, items.DocType, result.CommonName())
			document.Reader = result
			// An authenticated reader may have everything it asked for, subject to
			// consent. Whether it is AUTHORIZED to ask is a separate question,
			// answered against the certificate by the scheme layer exactly as the
			// OpenID4VP path does — see ReaderAuthResult.
			document.Permitted = items
		default:
			// mdoc.ErrNoReaderAuth means the reader sent none; anything else means it
			// sent one that did not verify. Both are unauthenticated and get the same
			// narrowing, but the wallet is told which so it can say so.
			if !errorIsNoReaderAuth(err) {
				document.ReaderAuthErr = err
				s.debugf("docRequest %d (%s): reader authentication FAILED: %v", i, items.DocType, err)
			} else {
				s.debugf("docRequest %d (%s): reader sent no readerAuth", i, items.DocType)
			}
			releasable, _ := mdoc.ReleasableWithoutReaderAuth(items)
			document.Permitted = mdoc.ItemsRequest{
				DocType:     items.DocType,
				NameSpaces:  releasable,
				RequestInfo: items.RequestInfo,
			}
		}

		documents = append(documents, document)
	}

	return documents, nil
}

// consent translates the permitted request and hands it to the wallet.
//
// The second return value is the map back: element i is the index in documents of
// the i'th DocRequest handed to the wallet, which is the i'th credential query of
// the translated DCQL query and therefore the one queryId(i) names. Unservable
// documents are not offered to the wallet, so the two orderings are not the same
// and assemble cannot recompute this without repeating the filter.
func (s *Session) consent(documents []RequestedDocument) ([]Selection, []int, error) {
	servable := make([]mdoc.DocRequest, 0, len(documents))
	offered := make([]int, 0, len(documents))
	for i, document := range documents {
		if !document.Servable() {
			continue
		}
		// Rebuilt from the PERMITTED items, so nothing the reader may not have
		// reaches the query, the consent screen or the disclosure log. The readerAuth
		// is dropped rather than carried: it signs the items as they were SENT, so
		// against a narrowed request it would no longer verify, and a signature that
		// cannot verify is worse than none.
		docRequest, err := mdoc.NewDocRequest(document.Permitted, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("rebuild permitted docRequest for %s: %w", document.DocType, err)
		}
		servable = append(servable, docRequest)
		offered = append(offered, i)
	}

	// Nothing may be released, so there is nothing to ask the user about. Consent
	// screens for requests that can only be refused are noise.
	if len(servable) == 0 {
		s.debugf("nothing is releasable for any requested document, so the user is not asked")
		return nil, nil, nil
	}

	query, err := DcqlQueryFromDeviceRequest(mdoc.DeviceRequest{
		Version:     mdoc.DeviceRequestVersion,
		DocRequests: servable,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("translate device request: %w", err)
	}

	selections, err := s.cfg.Discloser.Disclose(DisclosureRequest{Query: query, Documents: documents})
	if err != nil {
		return nil, nil, err
	}
	return selections, offered, nil
}

// assemble builds the DeviceResponse from what the wallet agreed to release.
//
// offered is consent's map from credential query position back to DocRequest; a
// nil one is fine and falls the resolution back to docType. See requestedFor.
func (s *Session) assemble(
	documents []RequestedDocument, offered []int, selections []Selection,
) (mdoc.DeviceResponse, error) {
	var (
		presented []mdoc.MDoc
		// Indexed by DocRequest rather than keyed by docType: a request may hold two
		// DocRequests of the same docType, and one of them being answered says
		// nothing about the other.
		served = make([]bool, len(documents))
	)

	for _, selection := range selections {
		index, err := requestedFor(documents, offered, served, selection)
		if err != nil {
			return mdoc.DeviceResponse{}, err
		}

		document, err := s.buildDocument(selection, documents[index].Requested)
		if err != nil {
			return mdoc.DeviceResponse{}, err
		}
		presented = append(presented, *document)
		served[index] = true
	}

	// Every requested document that is not being returned gets a documentError.
	// 8.3.2.1.2.2 keeps the two failure kinds apart and they are not
	// interchangeable: documentErrors names a whole document that is absent,
	// Document.Errors names elements missing from one that is present.
	//
	// Deduplicated by docType, which is all a DocumentError can name: two
	// unanswered DocRequests for the same docType have nothing to tell them apart
	// in the response, so reporting the docType twice would say the same thing
	// twice rather than say more.
	var documentErrors []mdoc.DocumentError
	reported := make(map[string]bool, len(documents))
	for i, document := range documents {
		if served[i] || reported[document.DocType] {
			continue
		}
		documentError, err := mdoc.NewDocumentError(document.DocType, mdoc.ErrorCodeDataNotReturned)
		if err != nil {
			return mdoc.DeviceResponse{}, fmt.Errorf("build documentError for %s: %w", document.DocType, err)
		}
		documentErrors = append(documentErrors, documentError)
		reported[document.DocType] = true
	}

	// Status stays 0 throughout. 8.3.2.1.2.3 forbids returning documents with a
	// non-zero status, so reporting "you cannot have this" as a status would throw
	// away everything the wallet DID agree to release in the same request.
	response := mdoc.NewDeviceResponse(presented...)
	if len(documentErrors) > 0 {
		response = response.WithDocumentErrors(documentErrors...)
	}
	if err := response.Validate(); err != nil {
		return mdoc.DeviceResponse{}, fmt.Errorf("assembled an invalid DeviceResponse: %w", err)
	}
	return response, nil
}

// buildDocument strips the document to what was consented to, signs it for this
// session, and records what could not be returned.
func (s *Session) buildDocument(selection Selection, requested mdoc.ItemsRequest) (*mdoc.MDoc, error) {
	// Shared with the OpenID4VP path deliberately: the same stored credential must
	// be stripped identically however it was asked for, or it would reveal
	// different things depending on the transport.
	disclosed, err := services.SelectiveDiscloseNamespaces(&selection.Document, selection.Reveal)
	if err != nil {
		return nil, fmt.Errorf("selective disclosure for %s: %w", selection.Document.DocType, err)
	}

	// Which key must sign is asked of the CREDENTIAL, not of any key record joined
	// to it: the MSO's deviceKeyInfo is what the issuer bound this document to and
	// what the reader checks the signature against, so a signer resolved from it is
	// the only one that can produce a presentation that verifies.
	deviceKey, err := mdoc.DeviceKeyFromIssuerAuth(disclosed.IssuerSigned.IssuerAuth)
	if err != nil {
		return nil, fmt.Errorf("read device key of %s: %w", selection.Document.DocType, err)
	}
	holder, err := s.cfg.DeviceKeys.HolderForDeviceKey(deviceKey)
	if err != nil {
		return nil, fmt.Errorf("no device key available to sign %s: %w", selection.Document.DocType, err)
	}

	// deviceSignature, never deviceMac. 9.1.3.4 forbids one key producing both over
	// its lifetime and the OpenID4VP path already signs with this same key — see
	// devicemac.go's header comment for the full decision.
	deviceAuth, err := holder.SignDeviceAuth(disclosed.DocType, s.transcript)
	if err != nil {
		return nil, fmt.Errorf("sign deviceAuth for %s: %w", selection.Document.DocType, err)
	}
	document, err := mdoc.AttachDeviceSigned(disclosed, deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("attach deviceSigned to %s: %w", selection.Document.DocType, err)
	}

	// This closes the partial-satisfaction gap DcqlQueryFromDeviceRequest documents
	// and deliberately leaves open: DCQL is all-or-nothing, so a request naming an
	// element the wallet does not hold yields no candidate, where 8.3.2.1.2.1 wants
	// the mdoc to "ignore all unknown data elements" and answer with the rest.
	//
	// Comparing against the ORIGINAL request rather than the permitted one is what
	// makes the reader's view complete: an element withheld because the reader did
	// not authenticate is reported with the same Table 9 code as one the wallet does
	// not hold, which is the truthful answer — in both cases the data was requested
	// and is not being returned.
	errs, err := document.ErrorsForRequest(requested)
	if err != nil {
		return nil, fmt.Errorf("compute errors for %s: %w", selection.Document.DocType, err)
	}
	document.Errors = errs

	return document, nil
}

// requestedFor resolves the DocRequest a selection answers, as an index into
// documents.
//
// Why this is not simply a docType lookup: a DeviceRequest may carry two
// DocRequests of the same docType, asking for different elements of it. Answering
// both against the first would strip the second document to the first request's
// elements — disclosing what the reader asked for in the wrong place and, worse,
// leaving the second request looking served, so it gets no documentError. The
// wallet's own accounting is right; only the join back to the request was lossy.
//
// So the DCQL query id is used where the wallet supplied one: the query it names
// IS one DocRequest, by construction of DcqlQueryFromDeviceRequest, and offered
// maps that position back past the unservable documents consent filtered out. A
// selection whose id resolves to a different docType than the document it carries
// is refused rather than reassigned: the wallet answered a query with the wrong
// credential, and presenting it anyway would send a document no DocRequest asked
// for.
//
// Without an id — a Discloser that builds selections from something other than the
// query — the docType is all there is, and the first request of that docType not
// yet answered is the best available reading. That is exactly right for every
// request naming each docType once, which is every request in practice.
func requestedFor(
	documents []RequestedDocument, offered []int, served []bool, selection Selection,
) (int, error) {
	docType := selection.Document.DocType

	if position, ok := queryIndex(selection.QueryId); ok {
		if position >= len(offered) {
			return 0, fmt.Errorf(
				"wallet answered query %q, which this request does not have", selection.QueryId)
		}
		index := offered[position]
		if documents[index].DocType != docType {
			return 0, fmt.Errorf(
				"wallet answered query %q, which asked for %s, with a %s document",
				selection.QueryId, documents[index].DocType, docType)
		}
		return index, nil
	}

	for i, document := range documents {
		if document.DocType == docType && !served[i] {
			return i, nil
		}
	}
	return 0, fmt.Errorf(
		"wallet selected a %s document, which this request did not ask for (or asked for once and got twice)",
		docType)
}

// errorIsNoReaderAuth distinguishes "the reader sent no readerAuth" from "the
// reader sent one that did not verify".
//
// mdoc.ErrNoReaderAuth is a sentinel for exactly this: the first is a reader that
// simply does not authenticate, which 9.1.4.4's optional `? "readerAuth"` permits;
// the second is a reader claiming an identity it cannot prove, which is the more
// alarming of the two and worth surfacing differently.
func errorIsNoReaderAuth(err error) bool {
	return errors.Is(err, mdoc.ErrNoReaderAuth)
}

// EDeviceKeyBytes is this transaction's ephemeral device key as it appears in the
// engagement: the complete tag-24 wrapping of 9.1.1.4.
//
// Exposed for the Ident check of 8.3.3.1.1.3, whose HKDF takes exactly these bytes
// as its IKM — not the COSE_Key inside them. Public material: it is in the QR code
// the reader already scanned.
func (s *Session) EDeviceKeyBytes() cbor.RawMessage {
	return s.engagement.Security.EDeviceKeyBytes
}
