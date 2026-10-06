// Package reader builds the relying party half of an org-iso-mdoc exchange: a
// signed ISO/IEC 18013-5 DeviceRequest, and the state needed to open the
// response that comes back.
//
// It is the mirror of the wallet in eudi/isomdoc, and deliberately a separate
// package: a reader needs none of the wallet machinery that package is built
// around (candidate selection, consent, single-use instance accounting), and
// depends only on the structures and cryptography in eudi/credentials/mdoc.
//
// # Why this exists at all
//
// Until now nothing in irmago could produce one of these. The wallet side has
// been exercised by a throwaway command outside the tree, because the primitives
// were all here and only the composition was missing. That is fine for a test
// and not fine for a deployment: the composition is where the traps are, and
// they are not the kind that fail loudly.
//
// # The transcript is the whole difficulty
//
// Three values have to agree for a response to be openable, and two of them are
// easy to get subtly wrong:
//
//   - The encryptionInfo is bound as TEXT. The wallet rebuilds the transcript
//     from the base64 string it received, not from a re-encoding of the decoded
//     structure, so what is hashed here must be the exact string the request
//     carried. Encoding once and keeping the string is the only safe order.
//   - The origin is bound too, and it is an input rather than something derived:
//     a response built for one origin is not valid at another, and only the
//     deployment knows which origin its page is actually served from.
//   - The recipient key must outlive the request. The response arrives after a
//     human has tapped a button, which is why Build hands it back rather than
//     hiding it: a builder that dropped it would produce responses nobody can
//     open.
//
// A mismatch in any of the three surfaces as a decryption failure, which reads
// like a broken proof and is not one.
package reader

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/isomdoc"
	"github.com/veraison/go-cose"
)

// Builder holds what a relying party knows before any particular session: who it
// is, and which zero-knowledge circuits it deals in.
type Builder struct {
	// Chain is the reader certificate chain, leaf first. The wallet authenticates
	// the reader from this and then holds it to the attribute sets its scheme
	// extension authorizes, so a chain whose leaf is not entitled to the docType
	// being asked for produces a refusal rather than a consent screen.
	Chain []*x509.Certificate

	// Signer signs readerAuth. Separate from Chain because a deployment may keep
	// the key somewhere that only implements crypto.Signer.
	Signer crypto.Signer

	// Algorithm is the COSE algorithm for readerAuth, matching Signer.
	Algorithm cose.Algorithm

	// Specs are the zero-knowledge systems this relying party deals in. ONE list,
	// used both to offer circuits in the request and to accept proofs in the
	// response -- see AcceptedCircuits for why splitting them is a bug waiting to
	// happen. Empty means no zkRequest is sent at all, which is a plain ISO
	// request.
	Specs []mdoc.ZkSystemSpec

	// Verifier is the trust model a response is checked against: which attestation
	// providers are pinned, and which certificates are revoked. Required by Verify,
	// and the half a proof cannot supply -- a proof establishes that some key signed
	// the attestation, never whose key it is, so without this a wallet that minted
	// its own IACA produces proofs that verify perfectly and mean nothing.
	Verifier *mdoc.Verifier

	// ZkSystems are the zero-knowledge systems this relying party can verify
	// under. Distinct from Specs, which says which circuits are OFFERED and
	// ACCEPTED: this says which implementations exist to run them. A spec offered
	// with no system behind it is refused at verification rather than at build,
	// because a build-time check would not survive a system being unregistered.
	ZkSystems *mdoc.ZkSystemRepository

	// ZkRequired refuses a plain presentation. Left false by age-verification
	// deployments on purpose: A.6 mandates the fallback and requires the relying
	// party to verify both paths, so forbidding the alternative would put us
	// outside the profile rather than ahead of it.
	ZkRequired bool
}

// Request is one exchange in flight: the bytes to send, and the state needed to
// open what comes back.
//
// Everything here except DeviceRequest belongs in session storage. A deployment
// that persists the request and forgets the rest has thrown away the ability to
// read the answer.
type Request struct {
	// DeviceRequest is the CBOR to hand the page, which base64url-encodes it into
	// the protocol payload.
	DeviceRequest []byte

	// EncryptionInfo is the base64url TEXT the request carries. Stored verbatim
	// rather than re-derived: the transcript binds this exact string.
	EncryptionInfo string

	// Recipient is the ephemeral key the response is sealed to. Ephemeral in the
	// protocol sense -- one per request, never reused -- but it has to survive
	// until the wallet answers.
	Recipient *ecdsa.PrivateKey

	// Transcript is what readerAuth signed and what the response is bound to.
	Transcript mdoc.SessionTranscript

	// Origin is the web origin this request was built for, kept so a response can
	// be refused if it arrives claiming another.
	Origin string
}

// Build assembles a signed DeviceRequest for one docType and its elements.
//
// elements maps each data element to its intentToRetain flag. The flag is shown
// to the user, so false is not a default to set absentmindedly: it is a claim
// about what the relying party will do with the answer.
func (b Builder) Build(origin, docType string, elements mdoc.DataElements) (*Request, error) {
	if len(b.Chain) == 0 {
		return nil, fmt.Errorf("reader: no certificate chain")
	}
	if b.Signer == nil {
		return nil, fmt.Errorf("reader: no signer for readerAuth")
	}
	if origin == "" {
		return nil, fmt.Errorf(
			"reader: no origin; the session transcript binds it and it cannot be guessed")
	}
	if docType == "" {
		return nil, fmt.Errorf("reader: no docType")
	}
	if len(elements) == 0 {
		return nil, fmt.Errorf(
			"reader: no data elements for %q; an mdoc presentation has no always-disclosed payload, "+
				"so a request naming none asks for a signature over nothing", docType)
	}

	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("reader: generate the recipient key: %w", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("reader: generate the nonce: %w", err)
	}

	info, err := isomdoc.NewDCAPIEncryptionInfo(nonce, &recipient.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("reader: build encryptionInfo: %w", err)
	}
	encodedInfo, err := cbor.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("reader: encode encryptionInfo: %w", err)
	}
	// Encoded once and reused from here on. See the package comment.
	encryptionInfo := base64.RawURLEncoding.EncodeToString(encodedInfo)

	transcript, err := mdoc.NewDCAPISessionTranscript(encryptionInfo, origin)
	if err != nil {
		return nil, fmt.Errorf("reader: build the session transcript: %w", err)
	}

	items := mdoc.ItemsRequest{
		DocType:    docType,
		NameSpaces: map[string]mdoc.DataElements{docType: elements},
	}
	if len(b.Specs) > 0 {
		encoded, err := cbor.Marshal(mdoc.ZkRequest{
			SystemSpecs: b.Specs,
			ZkRequired:  b.ZkRequired,
		})
		if err != nil {
			return nil, fmt.Errorf("reader: encode the zkRequest: %w", err)
		}
		items.RequestInfo = map[string]cbor.RawMessage{mdoc.ZkRequestKey: encoded}
	}

	docRequest, err := mdoc.NewDocRequest(items, nil)
	if err != nil {
		return nil, fmt.Errorf("reader: build the docRequest: %w", err)
	}
	readerAuth, err := mdoc.SignReaderAuth(
		b.Signer, b.Algorithm, b.Chain, transcript, docRequest.ItemsRequest)
	if err != nil {
		return nil, fmt.Errorf("reader: sign readerAuth: %w", err)
	}
	docRequest.ReaderAuth = readerAuth

	encoded, err := mdoc.DeviceRequest{
		Version:     mdoc.DeviceRequestVersion,
		DocRequests: []mdoc.DocRequest{docRequest},
	}.Encode()
	if err != nil {
		return nil, fmt.Errorf("reader: encode the DeviceRequest: %w", err)
	}

	return &Request{
		DeviceRequest:  encoded,
		EncryptionInfo: encryptionInfo,
		Recipient:      recipient,
		Transcript:     transcript,
		Origin:         origin,
	}, nil
}

// Restore rebuilds a Request from what a session store kept, so a response can
// be opened by a process that did not build the request.
//
// That is the ordinary case rather than an exotic one: the request is built when
// a page loads and the response arrives on a later HTTP call, possibly in
// another process. Only three things have to survive in between, and the
// transcript is NOT one of them -- it is derived here from the same two inputs
// it was derived from originally, which is also what the wallet does on its
// side.
//
// The encryptionInfo must be the exact string the request carried. Storing a
// decoded structure and re-encoding it here would produce a transcript that
// differs from the wallet's in a way nothing reports until decryption fails.
func Restore(encryptionInfo, origin string, recipient *ecdsa.PrivateKey) (*Request, error) {
	if encryptionInfo == "" {
		return nil, fmt.Errorf("reader: no encryptionInfo; the transcript cannot be rebuilt without it")
	}
	if origin == "" {
		return nil, fmt.Errorf("reader: no origin; the transcript cannot be rebuilt without it")
	}
	if recipient == nil {
		return nil, fmt.Errorf("reader: no recipient key; the response cannot be opened without it")
	}
	transcript, err := mdoc.NewDCAPISessionTranscript(encryptionInfo, origin)
	if err != nil {
		return nil, fmt.Errorf("reader: rebuild the session transcript: %w", err)
	}
	return &Request{
		EncryptionInfo: encryptionInfo,
		Recipient:      recipient,
		Transcript:     transcript,
		Origin:         origin,
	}, nil
}

// AcceptedCircuits is the gate A.8 requires the relying party to apply before
// verifying a proof, built from the SAME list the request offered.
//
// One list on purpose. Offering a circuit that would then be rejected is not a
// harmless inconsistency: the wallet spends seconds generating a proof under it
// and the relying party refuses the result, which looks to everyone involved
// like a broken wallet. Deriving the gate from the offer makes that state
// unrepresentable.
func (b Builder) AcceptedCircuits() *mdoc.AcceptedCircuits {
	hashes := make([]string, 0, len(b.Specs))
	for _, spec := range b.Specs {
		if hash, ok := spec.CircuitHash(); ok {
			hashes = append(hashes, hash)
		}
	}
	return mdoc.NewAcceptedCircuits(hashes...)
}

// Open decrypts a sealed response and returns the DeviceResponse bytes.
//
// A failure here means the two sides did not share a transcript -- a different
// origin, or an encryptionInfo that was re-encoded somewhere along the way. It
// does not mean the proof is bad, and reporting it as a bad proof sends whoever
// reads the log looking in the wrong place.
func (r *Request) Open(sealed isomdoc.DCAPIEncryptedResponse) ([]byte, error) {
	if r.Recipient == nil {
		return nil, fmt.Errorf(
			"reader: no recipient key for this request; it was not carried from the session that built it")
	}
	plaintext, err := isomdoc.OpenDCAPIResponse(sealed, r.Recipient, r.Transcript)
	if err != nil {
		return nil, fmt.Errorf(
			"reader: decrypt the response (the transcripts differed; this is not a failed proof): %w", err)
	}
	return plaintext, nil
}

// OpenBase64 is Open for a response that arrives as the base64url string the
// page received.
func (r *Request) OpenBase64(sealed string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("reader: response is not base64url: %w", err)
	}
	var envelope isomdoc.DCAPIEncryptedResponse
	if err := cbor.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("reader: decode the response envelope: %w", err)
	}
	return r.Open(envelope)
}
