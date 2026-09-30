package reader

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
)

// VerifiedDocument is one document a response actually established, after every
// check that had to pass before its contents could be believed.
//
// Nothing here is attacker-controlled by the time a caller sees it: a value only
// reaches this struct once the proof (or the issuer signature and deviceAuth)
// verified AND the issuer chained to a pinned root. That is why this type exists
// rather than handing back the decoded response — a decoded ZkDocumentData looks
// exactly the same whether or not anything checked it, which is how an unverified
// presentation gets believed.
type VerifiedDocument struct {
	// DocType is the document type, as established rather than as claimed.
	DocType string

	// ZeroKnowledge says which kind of presentation this was. A relying party
	// that leaves ZkRequired false may receive either, per A.6, and may want to
	// record which it got.
	ZeroKnowledge bool

	// Spec is the circuit the proof was accepted under. Zero value for a plain
	// presentation.
	Spec mdoc.ZkSystemSpec

	// IssuerSigner is the document signer this was established under, after
	// chain, EKU and revocation checks. Set for a zero-knowledge presentation,
	// where it is the only issuer identity there is; for a plain one the
	// equivalent is Plain.IssuerIdentifier.
	IssuerSigner *x509.Certificate

	// Elements are the proved data elements per namespace, for a zero-knowledge
	// presentation. The values stay raw CBOR because the proof is a statement
	// about those exact bytes, and re-encoding one would move the digest it was
	// proved against. Nil for a plain presentation, whose decoded attributes are
	// on Plain.
	Elements map[string][]mdoc.ZkSignedItem

	// Plain is the ordinary verification result for a non-ZK document. Nil for a
	// zero-knowledge one.
	Plain *mdoc.VerificationResult
}

// Verify checks a whole DeviceResponse and returns only what it established.
//
// This is the entry point a relying party should use. It exists because the
// obvious alternatives are each wrong in a way that does not announce itself:
//
//   - mdoc.Verifier.VerifyDeviceResponseAsReader walks documents only, so a
//     response whose content is all proofs used to come back as an empty slice
//     and a nil error. It now refuses such a response outright, and this is what
//     handles it instead.
//   - mdoc.VerifyZkDocument resolves the circuit, applies the accepted set,
//     checks the timestamp against the clock and verifies the proof — and
//     deliberately does not decide whether the issuer is trusted. A caller that
//     stops there has established that SOME key signed the attestation, which
//     includes a key the wallet minted for itself an hour ago.
//
// Both halves are applied to every document. A response is rejected whole rather
// than in part: a caller handed a partial list has to notice that it is partial,
// and letting a document it could not check pass as one it did is the single
// thing a verifier must never do.
//
// docType is what the relying party asked for, passed in rather than read out of
// the response. That is the point of the parameter — it makes this check that
// the answer matches the question, instead of trusting the answer's account of
// itself. Build uses the docType as the namespace too, so one value covers both.
//
// now is the verifier's own clock, for the proof's timestamp check. Pass the
// same instant used for the rest of the presentation.
func (b Builder) Verify(
	request *Request,
	deviceResponse []byte,
	docType string,
	now time.Time,
) ([]VerifiedDocument, error) {
	if request == nil {
		return nil, fmt.Errorf(
			"reader: no request; a response is bound to its transcript and cannot be checked without one")
	}
	if b.Verifier == nil {
		return nil, fmt.Errorf(
			"reader: no Verifier configured; without a trust model nothing establishes that the issuer is an issuer, " +
				"and a proof under a self-minted issuer key verifies perfectly")
	}
	if docType == "" {
		return nil, fmt.Errorf("reader: no docType to check the response against")
	}

	var response mdoc.DeviceResponse
	if err := cbor.Unmarshal(deviceResponse, &response); err != nil {
		return nil, fmt.Errorf("reader: decode the deviceResponse: %w", err)
	}
	// Before anything reads the structure. Validate enforces 8.3.2.1.2.3's rule
	// that a non-zero status carries no content, and the version/zkDocuments
	// correspondence: a response malformed in those ways is not one whose
	// documents are worth verifying.
	if err := response.Validate(); err != nil {
		return nil, fmt.Errorf("reader: invalid deviceResponse: %w", err)
	}
	if response.Status != mdoc.ResponseStatusOK {
		return nil, fmt.Errorf(
			"reader: the wallet answered with status %d rather than with a presentation", response.Status)
	}
	if len(response.Documents) == 0 && len(response.ZkDocuments) == 0 {
		return nil, fmt.Errorf(
			"reader: the response carries no documents (%d documentErrors): the wallet refused, "+
				"which is a well-formed answer and not a presentation", len(response.DocumentErrors))
	}

	verified := make([]VerifiedDocument, 0, len(response.ZkDocuments)+len(response.Documents))

	accepted := b.AcceptedCircuits()
	for i, document := range response.ZkDocuments {
		// The issuer first. It is the cheaper of the two checks, and its failure
		// means something different: a proof that verifies under an untrusted
		// issuer is a sound proof of a worthless statement, and verifying the
		// circuit first would mean computing a success and then taking it back.
		signer, err := b.Verifier.VerifyZkIssuer(document)
		if err != nil {
			return nil, fmt.Errorf("reader: zkDocument %d: %w", i, err)
		}

		spec, err := mdoc.VerifyZkDocument(document, b.ZkSystems, accepted, request.Transcript, now)
		if err != nil {
			return nil, fmt.Errorf("reader: zkDocument %d: %w", i, err)
		}

		// Only now is DocumentData believable, so only now is its docType worth
		// comparing. Checked at all because a wallet answering a request for one
		// document with a proof about another is a substitution the proof itself
		// does nothing to prevent: it binds the elements to the docType it was
		// made for, not to the one that was asked for.
		if got := document.DocumentData.DocType; got != docType {
			return nil, fmt.Errorf(
				"reader: zkDocument %d proves docType %q, but %q was requested", i, got, docType)
		}

		verified = append(verified, VerifiedDocument{
			DocType:       document.DocumentData.DocType,
			ZeroKnowledge: true,
			Spec:          spec,
			IssuerSigner:  signer,
			Elements:      document.DocumentData.IssuerSigned,
		})
	}

	if len(response.Documents) == 0 {
		return verified, nil
	}

	// Cleared deliberately, and this is the one place that may do it. The plain
	// entry point refuses a response carrying proofs precisely so that skipping
	// them cannot happen by accident; clearing the field here is this function
	// saying it has already verified them, which it has, immediately above.
	plain := response
	plain.ZkDocuments = nil

	results, err := b.Verifier.VerifyDeviceResponseAsReader(
		plain, docType, docType, request.Transcript, request.Recipient)
	if err != nil {
		return nil, fmt.Errorf("reader: verify the plain documents: %w", err)
	}
	for i := range results {
		result := results[i]
		// Valid is the verdict; a result can carry an authentic issuer identity
		// and still be invalid, so nothing here may read Attributes before this.
		if !result.Valid {
			return nil, fmt.Errorf("reader: document %d did not verify: %s", i, result.Error)
		}
		if result.DocType != docType {
			return nil, fmt.Errorf(
				"reader: document %d is docType %q, but %q was requested", i, result.DocType, docType)
		}
		verified = append(verified, VerifiedDocument{
			DocType: result.DocType,
			Plain:   &result,
		})
	}

	return verified, nil
}
