package mdocpresent

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

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
}

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

	response, err := assemble(selections, transcript)
	if err != nil {
		return empty, err
	}

	encoded, err := cbor.Marshal(response)
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
// Per document, not per session. 7.2.1 forbids requiring reader authentication
// for an mDL's mandatory elements, so a session that refused an unauthenticated
// reader outright would violate it — while a session that served everything to
// one would be worse. The decision therefore belongs to each docRequest.
func (s *Session) evaluate(request mdoc.DeviceRequest, transcript mdoc.SessionTranscript) ([]RequestedDocument, error) {
	documents := make([]RequestedDocument, 0, len(request.DocRequests))

	for i, docRequest := range request.DocRequests {
		items, err := docRequest.Items()
		if err != nil {
			return nil, fmt.Errorf("docRequest %d: %w", i, err)
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

// assemble signs each selected document over the session transcript and bundles
// them into a DeviceResponse.
//
// A selection with no documents produces a response with no documents, which is
// a refusal expressed the way 8.3.2.1.2.2 expresses one: status 0 and nothing to
// show. A non-zero status would say the request could not be processed, which is
// not what happened when a user simply declined.
func assemble(selections []Selection, transcript mdoc.SessionTranscript) (mdoc.DeviceResponse, error) {
	documents := make([]mdoc.MDoc, 0, len(selections))

	for _, selection := range selections {
		if selection.Holder == nil {
			return mdoc.DeviceResponse{}, fmt.Errorf(
				"selection for %s carries no holder: nothing can sign deviceAuth for it", selection.DocType)
		}

		deviceAuth, err := selection.Holder.SignDeviceAuth(selection.DocType, transcript)
		if err != nil {
			return mdoc.DeviceResponse{}, fmt.Errorf("sign deviceAuth for %s: %w", selection.DocType, err)
		}

		presented, err := mdoc.AttachDeviceSigned(&selection.Document, deviceAuth)
		if err != nil {
			return mdoc.DeviceResponse{}, fmt.Errorf("attach deviceSigned for %s: %w", selection.DocType, err)
		}
		documents = append(documents, *presented)
	}

	return mdoc.NewDeviceResponse(documents...), nil
}
