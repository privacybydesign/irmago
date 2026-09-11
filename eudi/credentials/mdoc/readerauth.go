package mdoc

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// MDOC READER AUTHENTICATION — ISO/IEC 18013-5 9.1.4
// ============================================================
//
// 9.1.4.1: "mdoc reader authentication uses information stored in the mdoc reader
// to confirm that the mdoc reader and the mdoc request are authenticated."
// 9.1.4.2 scopes it to device retrieval, which is exactly this transport.
//
// The mechanism, 9.1.4.4 verbatim where it constrains bytes:
//
//   - "The signature is contained in an untagged COSE_Sign1 structure as defined
//     in RFC 8152 and identified as ReaderAuth. Within the COSE_Sign1 structure,
//     the payload shall have a null value. The detached content is
//     ReaderAuthenticationBytes. The `external_aad' fields shall be a bytestring
//     of size zero."
//   - "The alg element (RFC 8152) shall be included as an element in the
//     protected header."
//   - "The certificate containing the mdoc reader public key shall be included as
//     a x5chain element ... It shall be included as an unprotected header element.
//     The x5chain element shall include at least one certificate and may contain
//     more."
//
//	ReaderAuthenticationBytes = #6.24(bstr .cbor ReaderAuthentication)
//
//	ReaderAuthentication = [        ; Same as in mdoc request
//	       "ReaderAuthentication",
//	       SessionTranscript,
//	       ItemsRequestBytes
//	]
//
// So this is structurally the same job as deviceMac (9.1.3.5) and deviceSignature
// (9.1.3.6) with the direction reversed: a detached tag-24 payload the receiving
// party rebuilds from inputs it already holds, a zero-length external_aad, and an
// algorithm read from the protected header rather than assumed. NOTE 1 spells the
// consequence out: "The ReaderAuthentication structure itself is not transferred
// as part of the mdoc request, only the resulting signature."
//
// # Why ItemsRequestBytes is never re-encoded
//
// "The ItemsRequestBytes shall contain the same data as in the mdoc request
// structure (see 8.3.2.1.2.1)." DocRequest.ItemsRequest already preserves the
// exact bytes that arrived for this reason; verification hashes them as received.
// Round-tripping through a parsed ItemsRequest and re-serialising yields different
// bytes and fails a perfectly valid signature.
//
// # What the mdoc does with the result is NOT decided here
//
// 9.1.4.4 says the key "may be used to authenticate the mdoc reader" and the
// DocRequest CDDL has `? "readerAuth"`, so sending it is optional in 18013-5 and
// the standard deliberately leaves enforcement to the deployment. This file
// therefore verifies and reports; it never decides to abort a session. The wallet
// policy is stated at VerifyReaderAuth and enforced by its caller.

// isoMdocReaderAuthEKU is the extended key usage ISO/IEC 18013-5 Annex B.1.7
// Table B.6 puts on a reader authentication certificate: 1.0.18013.5.1.6
// (mdlReaderAuth), mandatory and critical. It is the sibling of the document
// signer's 1.0.18013.5.1.2.
var isoMdocReaderAuthEKU = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}

// isoGenericMdocReaderAuthEKU is the ISO/IEC 23220-4 reader usage,
// 1.0.23220.4.1.6, accepted alongside the mDL-named OID for the same reason
// isoGenericMdocDocumentSignerEKU is accepted next to 1.0.18013.5.1.2: this
// package targets mso_mdoc in general, not driving licences. Both OIDs are
// first-class in Multipaz's own table (ISO_18013_5_MDL_READER_AUTH and
// ISO_23220_4_MDOC_READER_AUTH in asn1/OID.kt).
var isoGenericMdocReaderAuthEKU = asn1.ObjectIdentifier{1, 0, 23220, 4, 1, 6}

// mdocReaderAuthEKUs are the extended key usages accepted as evidence that a leaf
// certificate is authorized to authenticate an mdoc reader.
var mdocReaderAuthEKUs = []asn1.ObjectIdentifier{
	isoMdocReaderAuthEKU,
	isoGenericMdocReaderAuthEKU,
}

// ReaderAuthentication is the structure of 9.1.4.4 that a reader signs and the
// mdoc rebuilds. An untagged three-element array, like every other
// "…Authentication" structure in this package.
//
// ItemsRequest holds the complete tag-24 ItemsRequestBytes inline, not its
// contents — the same rule as SessionTranscript's leading slots and for the same
// reason. It is copied from DocRequest.ItemsRequest byte for byte.
type ReaderAuthentication struct {
	_                 struct{} `cbor:",toarray"`
	Context           string
	SessionTranscript SessionTranscript
	ItemsRequest      cbor.RawMessage
}

// readerAuthenticationBytes builds the ReaderAuthenticationBytes of 9.1.4.4 —
// `#6.24(bstr .cbor ReaderAuthentication)` — which is the detached content the
// COSE_Sign1 signature actually covers.
//
// itemsRequestBytes must be the tag-24 ItemsRequestBytes exactly as it appears in
// the DocRequest, so this refuses the contents-instead-of-wrapper mistake up front
// rather than producing a signature nobody can verify.
func readerAuthenticationBytes(transcript SessionTranscript, itemsRequestBytes cbor.RawMessage) ([]byte, error) {
	if err := validateTag24Slot("ItemsRequestBytes", itemsRequestBytes); err != nil {
		return nil, err
	}
	payload, err := tag24Wrap(ReaderAuthentication{
		Context:           "ReaderAuthentication",
		SessionTranscript: transcript,
		ItemsRequest:      itemsRequestBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("wrap readerAuthentication: %w", err)
	}
	return payload, nil
}

// SignReaderAuth produces the ReaderAuth of 9.1.4.4 for one DocRequest.
//
// The mdoc never calls this — a wallet only ever verifies. It exists for the
// reader side: the Go reader the proximity work is tested against, and any
// conformance fixture that needs a genuine signature rather than a recorded one.
//
// chain goes into unprotected header 33 with the reader's own certificate first,
// which is the order 9.1.4.4's x5chain requires and the order VerifyReaderAuth
// reads it back in. At least one certificate is mandatory.
func SignReaderAuth(
	signer crypto.Signer,
	algorithm cose.Algorithm,
	chain []*x509.Certificate,
	transcript SessionTranscript,
	itemsRequestBytes cbor.RawMessage,
) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("no signer for readerAuth")
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf(
			"readerAuth needs at least one certificate in x5chain: 9.1.4.4 makes it mandatory")
	}
	if !slices.Contains(mdocSignatureAlgorithms, algorithm) {
		return nil, fmt.Errorf(
			"readerAuth cannot be signed with %v: 9.1.4.4 names ES256, ES384, ES512 and EdDSA", algorithm)
	}

	payload, err := readerAuthenticationBytes(transcript, itemsRequestBytes)
	if err != nil {
		return nil, err
	}

	coseSigner, err := cose.NewSigner(algorithm, signer)
	if err != nil {
		return nil, fmt.Errorf("create readerAuth signer: %w", err)
	}

	der := make([][]byte, len(chain))
	for i, cert := range chain {
		if cert == nil {
			return nil, fmt.Errorf("readerAuth x5chain[%d] is nil", i)
		}
		der[i] = cert.Raw
	}

	// Untagged, per 9.1.4.4's "untagged COSE_Sign1 structure" — the same choice
	// issuerAuth and deviceSignature make in this package.
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers, Payload: payload}
	msg.Headers.Protected.SetAlgorithm(algorithm)
	msg.Headers.Unprotected[int64(33)] = der

	// nil external_aad: go-cose substitutes a zero-length byte string, which is
	// what 9.1.4.4 requires ("a bytestring of size zero"). Not the same as
	// omitting the field.
	if err := msg.Sign(rand.Reader, nil, coseSigner); err != nil {
		return nil, fmt.Errorf("sign readerAuth: %w", err)
	}

	// Detach: "the payload shall have a null value". The signature was computed
	// over the real bytes above and stays valid; this only changes what is sent.
	msg.Payload = nil

	return msg.MarshalCBOR()
}

// ReaderAuthResult is what a verified reader authentication establishes.
//
// It answers "which reader is this, and does it chain to something the wallet
// trusts" — nothing more. Whether that reader is authorized to ask for the
// attributes in its request is a separate question, answered against the
// certificate's own contents by the scheme layer, exactly as the OpenID4VP path
// does with a relying party certificate.
type ReaderAuthResult struct {
	// Certificate is the reader's leaf certificate, x5chain[0].
	Certificate *x509.Certificate

	// Chain is every certificate the reader shipped, leaf first, as parsed.
	Chain []*x509.Certificate

	// VerifiedChains are the paths to a trusted anchor that x509 accepted.
	VerifiedChains [][]*x509.Certificate

	// HasReaderAuthEKU records whether the leaf carries one of the reader
	// authentication usages of Table B.6. Reported rather than enforced: see
	// checkReaderAuthEKU for why this is not a gate.
	HasReaderAuthEKU bool
}

// CommonName is the reader's commonName, which Table B.6 makes mandatory on a
// reader authentication certificate. It is the fallback display identity, the
// same fallback the OpenID4VP path uses when a certificate carries no scheme
// extension to read a name out of.
func (r *ReaderAuthResult) CommonName() string {
	if r == nil || r.Certificate == nil {
		return ""
	}
	return r.Certificate.Subject.CommonName
}

// ErrNoReaderAuth reports a DocRequest that carried no readerAuth at all.
//
// Distinguishable from every other failure on purpose. 18013-5 permits its
// absence, so "the reader did not authenticate itself" and "the reader tried and
// failed" are different events, and a caller applying a policy has to be able to
// tell them apart — including to report them differently to the user.
var ErrNoReaderAuth = fmt.Errorf("DocRequest carries no readerAuth")

// VerifyReaderAuth verifies the mdoc reader authentication on one DocRequest
// against this Verifier's trust anchors and revocation information.
//
// Construct the Verifier from the wallet's *verifier* trust model — the same
// anchors that authenticate an OpenID4VP relying party — rather than the issuer
// one:
//
//	readerVerifier := mdoc.NewVerifierFromTrustSource(conf.Verifiers)
//
// # Wallet policy: absence and failure are both fatal, and that is a choice
//
// 18013-5 makes reader authentication optional, so this function reports rather
// than decides; the wallet's policy lives with the caller. That policy is to
// require it, mirroring what the OpenID4VP path already does, where an
// authorization request whose verifier cannot be authenticated never reaches the
// consent screen: every branch of CompositeVerifierValidator returns an error, and
// a client_id with no recognised scheme is refused outright because "there is no
// registry to resolve it against, so the verifier cannot be authenticated". A
// proximity reader that cannot be identified gets the same treatment, terminating
// the session (Table 20) before any consent screen is built.
//
// # The mDL carve-out, which the policy above must not run over
//
// 7.2.1, immediately after Table 5: "An mDL may require mdoc reader
// authentication (see 9.1.4) before releasing data elements not marked as
// mandatory in Table 5. An mDL shall not require mdoc reader authentication as a
// precondition for the release of any of the mandatory data elements." NOTE 3
// gives the intent — the holder is "always able to use the mDL as a driving
// licence", "including if an mDL reader does not use mdoc reader
// authentication".
//
// Read the granularity carefully: the prohibition is **per data element**, not
// per session. A hard-fail wallet policy applied to docType
// org.iso.18013.5.1.mDL would breach it, because terminating the session makes
// reader authentication a precondition for the mandatory elements too. The
// compliant behaviour is to release the mandatory elements (subject to holder
// consent, which is never in question) and withhold the optional ones — which
// 8.3.2.1.2.3 already has a vocabulary for: the withheld elements come back as
// ErrorCodeDataNotReturned at status 0, alongside a document.
//
// ReleasableWithoutReaderAuth performs that split, so the caller applies the
// policy to what it returns rather than to the request as a whole. For every
// docType other than the mDL it returns nothing releasable, which is the
// hard-fail above.
func (v *Verifier) VerifyReaderAuth(docRequest DocRequest, transcript SessionTranscript) (*ReaderAuthResult, error) {
	if len(docRequest.ReaderAuth) == 0 {
		return nil, ErrNoReaderAuth
	}

	msg, err := decodeCoseSign1(docRequest.ReaderAuth)
	if err != nil {
		return nil, fmt.Errorf("decode readerAuth as COSE_Sign1: %w", err)
	}

	// "the payload shall have a null value". A reader that transmits the payload
	// is refused rather than accommodated: the bytes below are rebuilt from this
	// wallet's own session transcript, so honouring a transmitted payload would
	// let the reader choose what its signature is checked against.
	if len(msg.Payload) != 0 {
		return nil, fmt.Errorf(
			"readerAuth carries a payload: 9.1.4.4 requires a null payload with ReaderAuthenticationBytes as detached content")
	}

	certs, err := certificatesFromX5Chain(msg, "readerAuth")
	if err != nil {
		return nil, err
	}
	readerCert := certs[0]

	// Intermediates come from both the request's own x5chain and the trust model,
	// for the same reason as the document signer path: a reader shipping only its
	// leaf certificate is unverifiable without the pinned intermediate, and the
	// trust model's pool is shared with every other verification so it is cloned
	// rather than added to.
	opts := v.verificationOptions()
	intermediates := x509.NewCertPool()
	if opts.Intermediates != nil {
		intermediates = opts.Intermediates.Clone()
	}
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	chains, err := readerCert.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: intermediates,
		// ExtKeyUsageAny for the same reason as the document signer walk: it stops
		// Go defaulting to ExtKeyUsageServerAuth, which no reader certificate
		// carries. It expresses no policy — see checkReaderAuthEKU.
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: v.currentTime(),
	})
	if err != nil {
		return nil, fmt.Errorf(
			"readerAuth chain verification failed: %v (reader subject %q, serial %X, issued by %q, x5chain length %d)",
			err, readerCert.Subject.String(), readerCert.SerialNumber, readerCert.Issuer.String(), len(certs))
	}

	// Revocation. 9.3.3 requires a party performing path validation to have
	// "access to certificate revocation information", and Table B.6 makes a CRL
	// distribution point mandatory on a reader certificate so this is possible.
	// A reader whose key was compromised and withdrawn yesterday still presents a
	// chain that verifies on dates and signatures alone.
	if err := v.checkChainRevocationFor(chains, "mdoc reader's"); err != nil {
		return nil, err
	}

	// The signature, last: everything above is a statement about the certificate,
	// not about whether this reader signed this request in this session.
	//
	// The payload is rebuilt from THIS wallet's session transcript and the
	// ItemsRequestBytes as received. Substituting our own transcript is what
	// defeats replay — a signature made over a different session hashes
	// differently and fails here — and since the transmitted payload is null, this
	// reconstruction is the only source of the bytes fed into Sig_structure, which
	// collapses "the request matches" and "the signature is valid" into one check.
	payload, err := readerAuthenticationBytes(transcript, docRequest.ItemsRequest)
	if err != nil {
		return nil, err
	}
	msg.Payload = payload

	coseVerifier, err := coseVerifierFor(msg, readerCert.PublicKey, "readerAuth")
	if err != nil {
		return nil, err
	}
	// nil external_aad, which go-cose encodes as the zero-length byte string
	// 9.1.4.4 requires.
	if err := msg.Verify(nil, coseVerifier); err != nil {
		return nil, fmt.Errorf(
			"readerAuth signature does not authenticate this request in this session: %v (reader subject %q)",
			err, readerCert.Subject.String())
	}

	return &ReaderAuthResult{
		Certificate:      readerCert,
		Chain:            certs,
		VerifiedChains:   chains,
		HasReaderAuthEKU: checkReaderAuthEKU(readerCert) == nil,
	}, nil
}

// checkReaderAuthEKU reports whether a leaf certificate carries one of the reader
// authentication usages of Table B.6.
//
// # Why this is reported and not enforced
//
// Unlike the document signer check, this one is not a gate, and the difference is
// deliberate. Annex B.1.7 says the reader "should use the certificate profile
// according to Table B.6" — a recommendation, where B.1.2's document signer
// requirements are not. Enforcing a "should" would also break every reader this
// wallet can actually talk to today: Yivi's own relying party certificates carry
// clientAuth and the Yivi scheme extension (2.1.123.1) and no ISO usage at all,
// and they additionally set keyEncipherment, which Table B.6 requires to be 0. A
// hard gate here would refuse every one of them while reporting it as though the
// reader were untrustworthy.
//
// The same tension already exists one layer up and was resolved the same way: the
// document signer EKU check accepts the ISO 23220 sibling precisely because
// insisting on the mDL-named OID rejected conformant non-mDL credentials.
//
// So the result travels on ReaderAuthResult.HasReaderAuthEKU, where a deployment
// that has arranged for conformant reader certificates can require it, and where
// its absence is visible rather than silently ignored. Turning it into a gate is a
// one-line change at the call site once the CA stamps 1.0.18013.5.1.6 — the same
// shape of pending CA work as the document signer EKU already tracked against
// staging.
func checkReaderAuthEKU(cert *x509.Certificate) error {
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return fmt.Errorf(
			"reader certificate %q carries no extended key usage, so nothing authorizes it for mdoc reader authentication (Table B.6 requires 1.0.18013.5.1.6)",
			cert.Subject.String())
	}
	if slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if slices.ContainsFunc(mdocReaderAuthEKUs, oid.Equal) {
			return nil
		}
	}
	return fmt.Errorf(
		"reader certificate %q is not authorized for mdoc reader authentication: it carries %s, and Table B.6 requires 1.0.18013.5.1.6 (or the ISO 23220 equivalent 1.0.23220.4.1.6)",
		cert.Subject.String(), extKeyUsagesOf(cert))
}

// ReleasableWithoutReaderAuth splits an ItemsRequest into the elements the mdoc
// may still release to a reader that did not authenticate itself, and the
// elements it may withhold.
//
// This exists for one clause: 7.2.1's "An mDL shall not require mdoc reader
// authentication as a precondition for the release of any of the mandatory data
// elements", quoted in full at VerifyReaderAuth. Because that prohibition is per
// element rather than per request, a caller cannot honour it by deciding whether
// to continue — it has to decide what to continue *with*.
//
// The two return values map onto what the caller does next:
//
//   - releasable goes to the consent screen, and to SelectiveDisclose after it.
//     Empty means the request cannot be served at all, which is the case for
//     every docType except the mDL.
//   - withheld is reported back to the reader as ErrorCodeDataNotReturned (Table
//     9) at status 0, the same channel MDoc.ErrorsForRequest uses for elements
//     the credential simply does not carry. Sorted, so the response is
//     deterministic.
//
// # Call this for ErrNoReaderAuth only, NOT for a failed verification
//
// The clause covers a reader that does not use reader authentication, and says
// nothing about one that uses it and fails. NOTE 3's wording is exactly that:
// "including if an mDL reader does not use mdoc reader authentication".
//
// Those are different events and 7.2.1 protects only the first. A readerAuth
// that is present but does not verify — forged signature, untrusted CA, revoked
// or expired certificate — is a reader actively misrepresenting itself, and
// extending the carve-out to it would mean handing family_name, birth_date and
// the holder's portrait to a reader whose certificate the wallet knows has been
// withdrawn. Nothing in the standard asks for that, and it is a worse outcome
// than refusing.
//
// So: call this when VerifyReaderAuth returned ErrNoReaderAuth. On any other
// error, terminate. ErrNoReaderAuth exists as a distinct sentinel to make that
// distinction cheap at the call site.
//
// It also never releases anything on its own, and is not a substitute for
// verifying reader authentication when the reader did send some.
func ReleasableWithoutReaderAuth(items ItemsRequest) (releasable map[string]DataElements, withheld map[string][]string) {
	permitted := profileFor(items.DocType).releasableWithoutReaderAuth

	releasable = map[string]DataElements{}
	withheld = map[string][]string{}

	for namespace, elements := range items.NameSpaces {
		for element, intentToRetain := range elements {
			if permitted != nil && permitted(namespace, element) {
				if releasable[namespace] == nil {
					releasable[namespace] = DataElements{}
				}
				// IntentToRetain is carried through unchanged: it changes what the
				// holder is being asked to agree to, and this function is not
				// entitled to alter that.
				releasable[namespace][element] = intentToRetain
				continue
			}
			withheld[namespace] = append(withheld[namespace], element)
		}
	}

	// Map iteration order is random in Go, and these names reach both the consent
	// screen and the wire.
	for namespace := range withheld {
		slices.Sort(withheld[namespace])
	}
	return releasable, withheld
}

// certificatesFromX5Chain reads the x5chain of COSE header 33, leaf first.
//
// 9.1.4.4 for readerAuth and Annex B for issuerAuth both put the signing
// certificate here, so the decoding quirks are shared: go-cose surfaces a CBOR
// array of byte strings as []any, and a single certificate may legitimately arrive
// unwrapped rather than as a one-element array.
func certificatesFromX5Chain(msg *cose.Sign1Message, what string) ([]*x509.Certificate, error) {
	rawVal, exists := msg.Headers.Unprotected[int64(33)]
	if !exists {
		return nil, fmt.Errorf("no x5chain in %s header 33", what)
	}

	chainRaw, ok := rawVal.([]any)
	if !ok {
		single, isSingle := rawVal.([]byte)
		if !isSingle {
			return nil, fmt.Errorf("%s x5chain wrong type: %T", what, rawVal)
		}
		chainRaw = []any{single}
	}
	if len(chainRaw) == 0 {
		return nil, fmt.Errorf("%s x5chain is empty: 9.1.4.4 requires at least one certificate", what)
	}

	certs := make([]*x509.Certificate, 0, len(chainRaw))
	for i, raw := range chainRaw {
		der, isDER := raw.([]byte)
		if !isDER {
			return nil, fmt.Errorf("%s x5chain[%d] wrong type: %T", what, i, raw)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse %s x5chain[%d]: %v", what, i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
