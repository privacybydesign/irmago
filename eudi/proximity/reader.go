package proximity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// THE TIER 0 MDOC READER
// ============================================================
//
// The counterpart of Session: the other side of a device retrieval transaction,
// in Go, so the whole flow can be driven with no radio and no second device.
//
// # Why this exists in the shipping tree rather than in a test file
//
// Three reasons, in increasing order of importance:
//
//  1. A wallet is testable only against a reader. Every part of Clause 9 is a
//     two-party agreement — the transcript, the session keys, the IV discipline,
//     the detached-payload signatures — and a one-sided test can only assert that
//     this package agrees with itself. Two independent implementations of the same
//     clause disagreeing is the bug that matters, and it is invisible from one
//     side.
//  2. Reader authentication (9.1.4) needs a reader that genuinely signs. Fixtures
//     with recorded signatures rot against every change to the transcript.
//  3. It is the only way to test the mdoc's behaviour toward a HOSTILE peer — a
//     reader that replays another session's readerAuth, widens its request after
//     signing, or sends a message the session keys cannot open. A conformant reader
//     cannot produce those, so they have to be constructed.
//
// # What it is not
//
// It is not a product. It does no candidate policy, shows nothing to a user, and
// holds no trust list of its own beyond the anchors it is handed. It is the
// minimum that can conduct a real transaction and check the result — which is
// exactly what the wallet needs to be tested against, and nothing more.
//
// Deliberately NOT a mirror image of Session. Session is a state machine driven by
// arriving bytes because a wallet reacts; Reader is a sequence of calls because a
// reader drives.

// ReaderConfig configures one Tier 0 reader.
type ReaderConfig struct {
	// Signer, Algorithm and Chain produce readerAuth (9.1.4.4). All three are
	// optional together: a reader with no signer sends no readerAuth, which is a
	// conformant thing for a reader to be — 9.1.4.4's CDDL has `? "readerAuth"` —
	// and is what exercises the wallet's 7.2.1 release policy.
	//
	// Chain is leaf-first, as the x5chain of 9.1.4.4 requires.
	Signer    crypto.Signer
	Algorithm cose.Algorithm
	Chain     []*x509.Certificate

	// Issuers verifies the documents that come back: the IACA anchors this reader
	// trusts. A reader without one can still conduct a session and read a response,
	// but cannot verify it, so Verify refuses rather than returning a result that
	// checked nothing.
	Issuers *mdoc.Verifier
}

// Reader is one reader-side device retrieval transaction.
//
// Not safe for concurrent use, for the same reason Session is not: it owns a
// mdoc.Session whose message counters must never repeat under one key.
type Reader struct {
	cfg ReaderConfig

	eReaderKey      *ecdsa.PrivateKey
	eReaderKeyBytes cbor.RawMessage

	engagement      mdoc.DeviceEngagement
	engagementBytes cbor.RawMessage

	transcript mdoc.SessionTranscript
	crypto     *mdoc.Session

	engaged     bool
	established bool
}

// NewReader creates a reader that has not yet engaged with an mdoc.
func NewReader(cfg ReaderConfig) *Reader {
	return &Reader{cfg: cfg}
}

// Engage consumes the mdoc's QR code (8.2.2.3) and fixes this session's transcript.
//
// This is where a real reader would also start scanning for the BLE service the
// engagement names; the Tier 0 reader is handed a byte pipe instead, which is the
// entire difference between it and a deployed one.
func (r *Reader) Engage(qrCodeURI string) error {
	if r.engaged {
		return fmt.Errorf("reader has already engaged")
	}

	// ParseQRCodeURI returns the tag-24 wrap of the bytes AS RECEIVED rather than a
	// re-encode. That is not a nicety: the transcript is hashed, and an mdoc whose
	// CBOR differs from this package's by so much as a map ordering would derive
	// different session keys from an engagement that decoded perfectly.
	engagement, engagementBytes, err := mdoc.ParseQRCodeURI(qrCodeURI)
	if err != nil {
		return fmt.Errorf("parse device engagement QR: %w", err)
	}

	eReaderKey, err := mdoc.GenerateEDeviceKey()
	if err != nil {
		return fmt.Errorf("generate EReaderKey: %w", err)
	}
	// 9.1.1.4 defines EReaderKeyBytes identically to EDeviceKeyBytes, which is why
	// one encoder serves both.
	eReaderKeyBytes, err := mdoc.EncodeEDeviceKeyBytes(&eReaderKey.PublicKey)
	if err != nil {
		return fmt.Errorf("encode EReaderKeyBytes: %w", err)
	}

	eDeviceKey, err := engagement.EDeviceKey()
	if err != nil {
		return fmt.Errorf("read EDeviceKey from engagement: %w", err)
	}

	transcript, err := mdoc.NewQRSessionTranscript(engagementBytes, eReaderKeyBytes)
	if err != nil {
		return fmt.Errorf("build session transcript: %w", err)
	}

	session, err := mdoc.NewReaderSession(eReaderKey, eDeviceKey, transcript)
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}

	r.engagement = engagement
	r.engagementBytes = engagementBytes
	r.eReaderKey = eReaderKey
	r.eReaderKeyBytes = eReaderKeyBytes
	r.transcript = transcript
	r.crypto = session
	r.engaged = true
	return nil
}

// Transcript is the SessionTranscript this reader derived, for tests that need to
// assert both sides built the same one.
func (r *Reader) Transcript() mdoc.SessionTranscript { return r.transcript }

// ServiceUUID is the BLE service the engagement named, which a deployed reader
// would scan for.
func (r *Reader) ServiceUUID() ([]byte, error) {
	if !r.engaged {
		return nil, fmt.Errorf("reader has not engaged")
	}
	method, err := r.engagement.SelectRetrievalMethod(mdoc.RetrievalMethodBLE)
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

// Request builds the first message: a DeviceRequest for the given documents,
// signed if this reader authenticates, encrypted, and wrapped in the
// SessionEstablishment of 9.1.1.4.
func (r *Reader) Request(items ...mdoc.ItemsRequest) ([]byte, error) {
	if !r.engaged {
		return nil, fmt.Errorf("reader must engage before requesting")
	}
	if r.established {
		return nil, fmt.Errorf("session is already established; use Continue for later requests")
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("a DeviceRequest needs at least one docRequest")
	}

	request, err := r.buildRequest(items...)
	if err != nil {
		return nil, err
	}

	ciphertext, err := r.crypto.Encrypt(request)
	if err != nil {
		return nil, fmt.Errorf("encrypt DeviceRequest: %w", err)
	}

	establishment, err := mdoc.NewSessionEstablishment(r.eReaderKeyBytes, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("build SessionEstablishment: %w", err)
	}
	r.established = true
	return establishment.Encode()
}

// Continue builds a further request inside an established session, as SessionData
// rather than SessionEstablishment. 9.1.1.4 allows the exchange to continue.
func (r *Reader) Continue(items ...mdoc.ItemsRequest) ([]byte, error) {
	if !r.established {
		return nil, fmt.Errorf("session is not established; call Request first")
	}

	request, err := r.buildRequest(items...)
	if err != nil {
		return nil, err
	}
	ciphertext, err := r.crypto.Encrypt(request)
	if err != nil {
		return nil, fmt.Errorf("encrypt DeviceRequest: %w", err)
	}
	data, err := mdoc.NewSessionData(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("wrap DeviceRequest in SessionData: %w", err)
	}
	return data.Encode()
}

// buildRequest assembles and signs a DeviceRequest.
func (r *Reader) buildRequest(items ...mdoc.ItemsRequest) ([]byte, error) {
	docRequests := make([]mdoc.DocRequest, 0, len(items))
	for i, item := range items {
		// Built unsigned first because readerAuth signs the ItemsRequestBytes, so
		// those bytes have to exist before there is anything to sign. NewDocRequest
		// is what fixes them.
		docRequest, err := mdoc.NewDocRequest(item, nil)
		if err != nil {
			return nil, fmt.Errorf("build docRequest %d: %w", i, err)
		}

		if r.cfg.Signer != nil {
			// 18013-5:2021 has exactly one readerAuth PER DocRequest — there is no
			// request-wide signature in this edition. Signing each separately is not a
			// simplification.
			readerAuth, err := mdoc.SignReaderAuth(
				r.cfg.Signer, r.cfg.Algorithm, r.cfg.Chain, r.transcript, docRequest.ItemsRequest)
			if err != nil {
				return nil, fmt.Errorf("sign readerAuth for docRequest %d: %w", i, err)
			}
			docRequest.ReaderAuth = readerAuth
		}

		docRequests = append(docRequests, docRequest)
	}

	request := mdoc.DeviceRequest{Version: mdoc.DeviceRequestVersion, DocRequests: docRequests}
	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("built an invalid DeviceRequest: %w", err)
	}
	return request.Encode()
}

// ReadResponse decrypts a reply and decodes the DeviceResponse inside it.
//
// A reply carrying a status instead of data is a Table 20 session message — a
// termination, or the mdoc reporting it could not decrypt or decode. That is
// returned as an error naming the code, because it means no response is coming.
func (r *Reader) ReadResponse(message []byte) (mdoc.DeviceResponse, error) {
	if !r.established {
		return mdoc.DeviceResponse{}, fmt.Errorf("session is not established")
	}

	data, err := mdoc.DecodeSessionData(message)
	if err != nil {
		return mdoc.DeviceResponse{}, fmt.Errorf("decode SessionData: %w", err)
	}
	if data.Status != nil {
		return mdoc.DeviceResponse{}, fmt.Errorf("mdoc ended the session with status %d", *data.Status)
	}
	if len(data.Data) == 0 {
		return mdoc.DeviceResponse{}, fmt.Errorf("SessionData carried neither data nor status")
	}

	plaintext, err := r.crypto.Decrypt(data.Data)
	if err != nil {
		return mdoc.DeviceResponse{}, fmt.Errorf("decrypt DeviceResponse: %w", err)
	}

	var response mdoc.DeviceResponse
	if err := mdoc.Unmarshal(plaintext, &response); err != nil {
		return mdoc.DeviceResponse{}, fmt.Errorf("decode DeviceResponse: %w", err)
	}
	if err := response.Validate(); err != nil {
		return mdoc.DeviceResponse{}, fmt.Errorf("mdoc sent an invalid DeviceResponse: %w", err)
	}
	return response, nil
}

// Verify checks every document in a response: the issuer's signature and chain,
// and the device signature against the transcript THIS reader built.
//
// Verifying against the reader's own transcript rather than anything the mdoc sent
// is the whole point. The payload of deviceAuth is detached, so the bytes fed into
// the signature check come from the reader's own session state — which is what
// makes a response from another session fail, and what a verifier trusting a
// transmitted transcript would lose.
func (r *Reader) Verify(response mdoc.DeviceResponse, namespace, docType string) ([]mdoc.VerificationResult, error) {
	if r.cfg.Issuers == nil {
		return nil, fmt.Errorf("this reader holds no issuer trust anchors, so it cannot verify a response")
	}
	return r.cfg.Issuers.VerifyDeviceResponse(response, namespace, docType, r.transcript)
}

// Terminate builds Table 20's session termination message and destroys this side's
// key material, as 9.1.1.4 requires of both parties.
func (r *Reader) Terminate() ([]byte, error) {
	message, err := mdoc.NewSessionStatus(mdoc.StatusSessionTermination).Encode()
	if err != nil {
		return nil, err
	}
	r.Close()
	return message, nil
}

// Close destroys this reader's session keys without sending anything.
func (r *Reader) Close() {
	if r.crypto != nil {
		r.crypto.Close()
	}
	r.eReaderKey = nil
	r.established = false
}
