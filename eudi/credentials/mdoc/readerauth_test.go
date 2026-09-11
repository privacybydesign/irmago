package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// MDOC READER AUTHENTICATION — ISO/IEC 18013-5 9.1.4
// ============================================================
//
// Three properties carry the security of this clause and each has its own test
// below, because passing the happy path proves none of them:
//
//   - the signature binds to THIS session, so a readerAuth lifted from another
//     transaction fails (the transcript is the wallet's own, never the reader's);
//   - the signature binds to THIS request, so the elements asked for cannot be
//     swapped after signing;
//   - the external_aad really is a zero-length byte string rather than absent,
//     which is invisible in a round trip that gets it wrong on both sides.
//
// Everything else here is structure (the wire shape 9.1.4.4 fixes) and trust
// (chain, dates, revocation, x5chain handling).

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readerPKI is one reader identity plus the CA that issued it.
type readerPKI struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	cert     *x509.Certificate
	// key is typed crypto.Signer rather than *ecdsa.PrivateKey because Table 22
	// permits EdDSA for the mdoc reader authentication key, so an Ed25519 reader
	// has to travel this same path.
	key crypto.Signer
}

// chain is the x5chain a conformant reader sends: its own certificate first.
func (p readerPKI) chain() []*x509.Certificate {
	return []*x509.Certificate{p.cert, p.rootCert}
}

// roots is the anchor pool a wallet would hold for this reader. In the wallet
// this is Configuration.Verifiers — the same trust model that authenticates an
// OpenID4VP relying party — rather than the issuer store.
func (p readerPKI) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.rootCert)
	return pool
}

func (p readerPKI) verifier() *Verifier {
	return NewVerifierFromPool(p.roots())
}

// readerPKIOptions varies the parts of the reader certificate individual tests
// care about. The zero value is a conformant P-256 reader carrying the
// 1.0.18013.5.1.6 usage of Table B.6.
type readerPKIOptions struct {
	curve elliptic.Curve
	// ed25519 makes the reader authentication key an Ed25519 key instead of an
	// EC one, for the fourth algorithm 9.1.4.4 names. Mutually exclusive with
	// curve, which it overrides.
	ed25519     bool
	notBefore   time.Time
	notAfter    time.Time
	eku         []x509.ExtKeyUsage
	unknownEKU  []asn1.ObjectIdentifier
	noUnknown   bool // suppress the default ISO usage without supplying another
	commonName  string
	untrustedCA bool // sign the reader cert with a CA the wallet does not trust
}

func newReaderPKI(t *testing.T, opts readerPKIOptions) readerPKI {
	t.Helper()

	curve := opts.curve
	if curve == nil {
		curve = elliptic.P256()
	}
	notBefore := opts.notBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-5 * time.Minute)
	}
	notAfter := opts.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	commonName := opts.commonName
	if commonName == "" {
		commonName = "Test mdoc Reader"
	}
	unknownEKU := opts.unknownEKU
	if unknownEKU == nil && !opts.noUnknown {
		unknownEKU = []asn1.ObjectIdentifier{isoMdocReaderAuthEKU}
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate reader CA key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x0CA),
		Subject:      pkix.Name{CommonName: "Test Reader CA", Organization: []string{"Yivi Test"}},
		// A year either side, unlike the leaf: a CA that only just became valid
		// would put the backdated clock in TestReaderAuthRejectsExpiredCertificate
		// outside the CA's own window, so the leaf's expiry could not be isolated.
		NotBefore:             time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create reader CA cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse reader CA cert: %v", err)
	}

	signingCert, signingKey := rootCert, rootKey
	if opts.untrustedCA {
		rogueKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate rogue CA key: %v", err)
		}
		rogueTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(0x0BAD),
			Subject:               pkix.Name{CommonName: "Rogue Reader CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
		}
		rogueDER, err := x509.CreateCertificate(rand.Reader, rogueTemplate, rogueTemplate, &rogueKey.PublicKey, rogueKey)
		if err != nil {
			t.Fatalf("create rogue CA cert: %v", err)
		}
		rogueCert, err := x509.ParseCertificate(rogueDER)
		if err != nil {
			t.Fatalf("parse rogue CA cert: %v", err)
		}
		signingCert, signingKey = rogueCert, rogueKey
	}

	var readerKey crypto.Signer
	if opts.ed25519 {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate Ed25519 reader key: %v", err)
		}
		readerKey = priv
	} else {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("generate reader key: %v", err)
		}
		readerKey = priv
	}
	readerTemplate := &x509.Certificate{
		// 0xEADE12 renders as EADE12 — distinctive in an error message, and
		// unlike the DS fixtures' serials so a mixed-up chain is obvious.
		SerialNumber:          big.NewInt(0xEADE12),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Yivi Test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           opts.eku,
		UnknownExtKeyUsage:    unknownEKU,
	}
	readerDER, err := x509.CreateCertificate(rand.Reader, readerTemplate, signingCert, readerKey.Public(), signingKey)
	if err != nil {
		t.Fatalf("create reader cert: %v", err)
	}
	readerCert, err := x509.ParseCertificate(readerDER)
	if err != nil {
		t.Fatalf("parse reader cert: %v", err)
	}

	return readerPKI{rootCert: rootCert, rootKey: rootKey, cert: readerCert, key: readerKey}
}

// testItemsRequest is a minimal but valid ItemsRequest: 8.3.2.1.2.1's three `+`
// occurrences all need at least one member.
func testItemsRequest(docType string, elements ...string) ItemsRequest {
	if len(elements) == 0 {
		elements = []string{"age_over_18"}
	}
	requested := DataElements{}
	for _, e := range elements {
		requested[e] = false
	}
	return ItemsRequest{
		DocType:    docType,
		NameSpaces: map[string]DataElements{docType: requested},
	}
}

// testReaderTranscript is a SessionTranscript with distinct, tag-24 correct
// slots. The contents are arbitrary — what matters is that reader and mdoc agree
// on one transcript, and that a second transcript differs from it.
func testReaderTranscript(label string) SessionTranscript {
	return SessionTranscript{
		DeviceEngagementBytes: testTag24("engagement-" + label),
		EReaderKeyBytes:       testTag24("ereaderkey-" + label),
		Handover:              nil, // QRHandover is null, per 9.1.5.1
	}
}

// signedDocRequest builds a DocRequest whose readerAuth is a genuine signature
// by pki over transcript, which is the state a wallet finds a request in.
func signedDocRequest(t *testing.T, pki readerPKI, transcript SessionTranscript, items ItemsRequest) DocRequest {
	t.Helper()
	docRequest, err := NewDocRequest(items, nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	readerAuth, err := SignReaderAuth(pki.key, cose.AlgorithmES256, pki.chain(), transcript, docRequest.ItemsRequest)
	if err != nil {
		t.Fatalf("SignReaderAuth: %v", err)
	}
	docRequest.ReaderAuth = readerAuth
	return docRequest
}

// ---------------------------------------------------------------------------
// Happy path and wire structure
// ---------------------------------------------------------------------------

func TestReaderAuthRoundTrip(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{commonName: "Acme Age Check"})
	transcript := testReaderTranscript("a")
	docRequest := signedDocRequest(t, pki, transcript, testItemsRequest(AgeVerificationDocType))

	result, err := pki.verifier().VerifyReaderAuth(docRequest, transcript)
	if err != nil {
		t.Fatalf("VerifyReaderAuth: %v", err)
	}
	if result.CommonName() != "Acme Age Check" {
		t.Errorf("CommonName = %q, want %q", result.CommonName(), "Acme Age Check")
	}
	if !result.Certificate.Equal(pki.cert) {
		t.Error("result carries a different leaf certificate than the reader sent")
	}
	if len(result.Chain) != 2 {
		t.Errorf("Chain length = %d, want 2 (leaf + CA)", len(result.Chain))
	}
	if len(result.VerifiedChains) == 0 {
		t.Error("VerifiedChains is empty despite verification succeeding")
	}
	if !result.HasReaderAuthEKU {
		t.Error("HasReaderAuthEKU = false for a certificate carrying 1.0.18013.5.1.6")
	}
}

// TestReaderAuthWireShape pins what 9.1.4.4 fixes about the transmitted bytes:
// untagged COSE_Sign1, null payload, alg in the protected header, x5chain in the
// unprotected header.
func TestReaderAuthWireShape(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{})
	transcript := testReaderTranscript("a")
	items := testItemsRequest(AgeVerificationDocType)
	docRequest, err := NewDocRequest(items, nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	readerAuth, err := SignReaderAuth(pki.key, cose.AlgorithmES256, pki.chain(), transcript, docRequest.ItemsRequest)
	if err != nil {
		t.Fatalf("SignReaderAuth: %v", err)
	}

	// Untagged: 0xd2 is the COSE_Sign1_Tagged (tag 18) prefix and must not be
	// there. "The signature is contained in an untagged COSE_Sign1 structure".
	if readerAuth[0] == 0xd2 {
		t.Error("readerAuth is tag-18 wrapped; 9.1.4.4 requires an untagged COSE_Sign1")
	}

	// Four-element array.
	var raw []cbor.RawMessage
	if err := mdocDecMode.Unmarshal(readerAuth, &raw); err != nil {
		t.Fatalf("decode readerAuth as an array: %v", err)
	}
	if len(raw) != 4 {
		t.Fatalf("readerAuth has %d elements, want 4 (COSE_Sign1)", len(raw))
	}

	// Payload null: "Within the COSE_Sign1 structure, the payload shall have a
	// null value."
	var payload any
	if err := mdocDecMode.Unmarshal(raw[2], &payload); err != nil {
		t.Fatalf("decode readerAuth payload: %v", err)
	}
	if payload != nil {
		t.Errorf("readerAuth payload is %v, want null: the detached content is ReaderAuthenticationBytes", payload)
	}

	msg, err := decodeCoseSign1(readerAuth)
	if err != nil {
		t.Fatalf("decodeCoseSign1: %v", err)
	}
	algorithm, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		t.Fatalf("readerAuth has no alg in its protected header, which 9.1.4.4 requires: %v", err)
	}
	if algorithm != cose.AlgorithmES256 {
		t.Errorf("alg = %v, want %v", algorithm, cose.AlgorithmES256)
	}
	if _, present := msg.Headers.Unprotected[int64(33)]; !present {
		t.Error("no x5chain at unprotected header 33, which 9.1.4.4 requires")
	}
	if _, present := msg.Headers.Protected[int64(33)]; present {
		t.Error("x5chain is in the protected header; 9.1.4.4 says it shall be an unprotected header element")
	}
}

// TestReaderAuthenticationStructure pins the signed structure itself, which never
// travels: ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes].
func TestReaderAuthenticationStructure(t *testing.T) {
	transcript := testReaderTranscript("a")
	docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}

	wrapped, err := readerAuthenticationBytes(transcript, docRequest.ItemsRequest)
	if err != nil {
		t.Fatalf("readerAuthenticationBytes: %v", err)
	}

	inner := unwrapTag24Generic(t, wrapped)
	var elements []cbor.RawMessage
	if err := mdocDecMode.Unmarshal(inner, &elements); err != nil {
		t.Fatalf("decode ReaderAuthentication as an array: %v", err)
	}
	if len(elements) != 3 {
		t.Fatalf("ReaderAuthentication has %d elements, want 3", len(elements))
	}

	var context string
	if err := mdocDecMode.Unmarshal(elements[0], &context); err != nil {
		t.Fatalf("decode context string: %v", err)
	}
	if context != "ReaderAuthentication" {
		t.Errorf("context = %q, want %q", context, "ReaderAuthentication")
	}

	// The ItemsRequestBytes slot holds the tag-24 item inline, byte for byte as
	// the DocRequest carries it. "The ItemsRequestBytes shall contain the same
	// data as in the mdoc request structure."
	if string(elements[2]) != string(docRequest.ItemsRequest) {
		t.Error("ItemsRequestBytes in ReaderAuthentication differs from the DocRequest's bytes")
	}
}

// TestReaderAuthZeroLengthExternalAAD checks the one requirement a round trip
// cannot: "The `external_aad' fields shall be a bytestring of size zero."
//
// A signature produced over a NON-empty external_aad must fail, and one produced
// over an explicitly empty one must pass — which together pin the value rather
// than just the fact that both sides agree.
func TestReaderAuthZeroLengthExternalAAD(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{})
	transcript := testReaderTranscript("a")
	docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	payload, err := readerAuthenticationBytes(transcript, docRequest.ItemsRequest)
	if err != nil {
		t.Fatalf("readerAuthenticationBytes: %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, pki.key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	sign := func(external []byte) []byte {
		t.Helper()
		msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers, Payload: payload}
		msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
		msg.Headers.Unprotected[int64(33)] = [][]byte{pki.cert.Raw, pki.rootCert.Raw}
		if err := msg.Sign(rand.Reader, external, signer); err != nil {
			t.Fatalf("sign with external_aad %v: %v", external, err)
		}
		msg.Payload = nil
		encoded, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return encoded
	}

	verifier := pki.verifier()

	// Explicitly zero-length rather than nil: this is the value the clause names,
	// and it must verify.
	docRequest.ReaderAuth = sign([]byte{})
	if _, err := verifier.VerifyReaderAuth(docRequest, transcript); err != nil {
		t.Errorf("a signature over a zero-length external_aad was refused: %v", err)
	}

	// Non-empty: must fail, or this implementation is not using a zero-length
	// external_aad at all.
	docRequest.ReaderAuth = sign([]byte("not empty"))
	if _, err := verifier.VerifyReaderAuth(docRequest, transcript); err == nil {
		t.Error("a signature over a non-empty external_aad verified; 9.1.4.4 requires a bytestring of size zero")
	}
}

// 9.1.4.4: the reader "shall use ... the ECDSA or EdDSA curves from Table 22 for
// the mdoc reader authentication key". That key is chosen by the READER and is
// independent of the session curve (which the mdoc picks), so the wallet has no
// say in which of the four it meets — every one of them has to verify.
//
// Ed25519 is the case worth having explicitly: it is not an EC2 key, it reaches
// cose.NewVerifier as an ed25519.PublicKey rather than an *ecdsa.PublicKey, and
// nothing else in this package exercises that branch. Ed448 and the brainpool
// curves would fail here — neither has Go standard library support — and that
// remains an open dependency decision rather than a bug.
func TestReaderAuthAllPermittedAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		name      string
		curve     elliptic.Curve
		ed25519   bool
		algorithm cose.Algorithm
	}{
		{"ES256/P-256", elliptic.P256(), false, cose.AlgorithmES256},
		{"ES384/P-384", elliptic.P384(), false, cose.AlgorithmES384},
		{"ES512/P-521", elliptic.P521(), false, cose.AlgorithmES512},
		{"EdDSA/Ed25519", nil, true, cose.AlgorithmEdDSA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newReaderPKI(t, readerPKIOptions{curve: tc.curve, ed25519: tc.ed25519})
			transcript := testReaderTranscript("a")
			docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
			if err != nil {
				t.Fatalf("NewDocRequest: %v", err)
			}
			readerAuth, err := SignReaderAuth(pki.key, tc.algorithm, pki.chain(), transcript, docRequest.ItemsRequest)
			if err != nil {
				t.Fatalf("SignReaderAuth: %v", err)
			}
			docRequest.ReaderAuth = readerAuth
			if _, err := pki.verifier().VerifyReaderAuth(docRequest, transcript); err != nil {
				t.Errorf("VerifyReaderAuth: %v", err)
			}
		})
	}
}

// TestReaderAuthRejectsDisallowedAlgorithm covers the allow-list rather than
// go-cose's own support: RSA-PSS is implemented by the library and permitted by
// neither 9.1.4.4 nor Table 22.
func TestReaderAuthRejectsDisallowedAlgorithm(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{})
	transcript := testReaderTranscript("a")
	docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	_, err = SignReaderAuth(pki.key, cose.AlgorithmPS256, pki.chain(), transcript, docRequest.ItemsRequest)
	if err == nil {
		t.Fatal("SignReaderAuth accepted PS256, which 9.1.4.4 does not name")
	}
	if !strings.Contains(err.Error(), "ES256") {
		t.Errorf("error does not name the permitted algorithms: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Session binding and request binding
// ---------------------------------------------------------------------------

// TestReaderAuthBindsToSession is the replay test. The readerAuth is genuine and
// its certificate is trusted; it was simply produced in a different session.
//
// The wallet verifies against ITS OWN transcript, which is why this fails: the
// transmitted payload is null, so the transcript the wallet supplies is the only
// source of the bytes fed into Sig_structure.
func TestReaderAuthBindsToSession(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{})
	signedIn := testReaderTranscript("session-a")
	verifiedIn := testReaderTranscript("session-b")

	docRequest := signedDocRequest(t, pki, signedIn, testItemsRequest(AgeVerificationDocType))

	if _, err := pki.verifier().VerifyReaderAuth(docRequest, signedIn); err != nil {
		t.Fatalf("sanity: the same transcript should verify: %v", err)
	}
	_, err := pki.verifier().VerifyReaderAuth(docRequest, verifiedIn)
	if err == nil {
		t.Fatal("a readerAuth from another session verified; reader authentication does not bind to the session")
	}
	if !strings.Contains(err.Error(), "this session") {
		t.Errorf("error does not identify the session as the mismatch: %v", err)
	}
}

// TestReaderAuthBindsToRequest is the tampering test: the reader signed a request
// for age_over_18 and the request now asks for more. Only the ItemsRequestBytes
// are swapped, so the signature is untouched and genuinely the reader's.
func TestReaderAuthBindsToRequest(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{})
	transcript := testReaderTranscript("a")
	docRequest := signedDocRequest(t, pki, transcript, testItemsRequest(AgeVerificationDocType, "age_over_18"))

	widened, err := NewDocRequest(
		testItemsRequest(AgeVerificationDocType, "age_over_18", "age_over_21", "portrait"), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	tampered := DocRequest{ItemsRequest: widened.ItemsRequest, ReaderAuth: docRequest.ReaderAuth}

	if _, err := pki.verifier().VerifyReaderAuth(tampered, transcript); err == nil {
		t.Fatal("a widened ItemsRequest verified against the original signature; reader authentication does not bind to the request")
	}
}

// TestReaderAuthPerDocRequestBinding covers a DeviceRequest with two
// docRequests. Each readerAuth covers its own ItemsRequestBytes, so swapping the
// two signatures must fail even though both are genuine and both certificates
// are trusted.
//
// Worth pinning because 18013-5:2021 has exactly one readerAuth per DocRequest —
// there is no request-wide signature in this edition (Multipaz implements a
// readerAuthAll, which is not from this document).
func TestReaderAuthPerDocRequestBinding(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{})
	transcript := testReaderTranscript("a")

	first := signedDocRequest(t, pki, transcript, testItemsRequest(AgeVerificationDocType, "age_over_18"))
	second := signedDocRequest(t, pki, transcript, testItemsRequest("eu.europa.ec.eudi.pid.1", "family_name"))

	verifier := pki.verifier()
	if _, err := verifier.VerifyReaderAuth(first, transcript); err != nil {
		t.Fatalf("first docRequest: %v", err)
	}
	if _, err := verifier.VerifyReaderAuth(second, transcript); err != nil {
		t.Fatalf("second docRequest: %v", err)
	}

	swapped := DocRequest{ItemsRequest: first.ItemsRequest, ReaderAuth: second.ReaderAuth}
	if _, err := verifier.VerifyReaderAuth(swapped, transcript); err == nil {
		t.Error("a readerAuth from a different docRequest verified; the signature is not bound per document request")
	}
}

// TestReaderAuthRejectsForeignKey covers the certificate actually being used: a
// signature made with one reader's key but shipping another reader's certificate.
// Both certificates chain to the trusted CA, so only the signature check can
// catch it.
func TestReaderAuthRejectsForeignKey(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{commonName: "Real Reader"})
	imposterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate imposter key: %v", err)
	}

	transcript := testReaderTranscript("a")
	docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	// Signed by the imposter, presented under the real reader's certificate.
	readerAuth, err := SignReaderAuth(imposterKey, cose.AlgorithmES256, pki.chain(), transcript, docRequest.ItemsRequest)
	if err != nil {
		t.Fatalf("SignReaderAuth: %v", err)
	}
	docRequest.ReaderAuth = readerAuth

	if _, err := pki.verifier().VerifyReaderAuth(docRequest, transcript); err == nil {
		t.Error("a signature made with a key other than the certificate's verified")
	}
}

// ---------------------------------------------------------------------------
// Absence, and the malformed cases
// ---------------------------------------------------------------------------

// TestReaderAuthAbsenceIsDistinguishable matters because 18013-5 permits a
// request with no readerAuth at all. "The reader did not authenticate itself" and
// "the reader tried and failed" are different events and the caller applying the
// wallet policy has to be able to tell them apart.
func TestReaderAuthAbsenceIsDistinguishable(t *testing.T) {
	docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	if len(docRequest.ReaderAuth) != 0 {
		t.Fatal("sanity: NewDocRequest with nil readerAuth should leave the field empty")
	}

	pki := newReaderPKI(t, readerPKIOptions{})
	result, err := pki.verifier().VerifyReaderAuth(docRequest, testReaderTranscript("a"))
	if !errors.Is(err, ErrNoReaderAuth) {
		t.Errorf("err = %v, want ErrNoReaderAuth", err)
	}
	if result != nil {
		t.Error("a result was returned for a request that carried no readerAuth")
	}
}

// TestReaderAuthRejectsTransmittedPayload covers "the payload shall have a null
// value". Honouring a transmitted payload would let the reader choose what its
// own signature is checked against, which is the whole point of rebuilding it.
func TestReaderAuthRejectsTransmittedPayload(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{})
	transcript := testReaderTranscript("a")
	docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	payload, err := readerAuthenticationBytes(transcript, docRequest.ItemsRequest)
	if err != nil {
		t.Fatalf("readerAuthenticationBytes: %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, pki.key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers, Payload: payload}
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Unprotected[int64(33)] = [][]byte{pki.cert.Raw, pki.rootCert.Raw}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Deliberately NOT detached.
	attached, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	docRequest.ReaderAuth = attached

	_, err = pki.verifier().VerifyReaderAuth(docRequest, transcript)
	if err == nil {
		t.Fatal("a readerAuth carrying its payload was accepted; 9.1.4.4 requires a null payload")
	}
	if !strings.Contains(err.Error(), "null payload") {
		t.Errorf("error does not name the payload requirement: %v", err)
	}
}

func TestReaderAuthRejectsMalformedCOSE(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{})
	docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	docRequest.ReaderAuth = cbor.RawMessage{0xa1, 0x01, 0x02} // a CBOR map, not a COSE_Sign1 array

	if _, err := pki.verifier().VerifyReaderAuth(docRequest, testReaderTranscript("a")); err == nil {
		t.Error("a CBOR map was accepted as a readerAuth COSE_Sign1")
	}
}

// TestReaderAuthRefusesUnwrappedItemsRequest guards the tag-24 trap this package
// has hit before: the slot holds the complete #6.24 item, not its contents.
// Getting it wrong on both sides would round trip happily and be incompatible
// with every other implementation.
func TestReaderAuthRefusesUnwrappedItemsRequest(t *testing.T) {
	transcript := testReaderTranscript("a")
	items := testItemsRequest(AgeVerificationDocType)
	bare, err := cbor.Marshal(items) // the contents, with no tag-24 wrapper
	if err != nil {
		t.Fatalf("marshal ItemsRequest: %v", err)
	}

	if _, err := readerAuthenticationBytes(transcript, bare); err == nil {
		t.Error("readerAuthenticationBytes accepted an unwrapped ItemsRequest")
	}

	pki := newReaderPKI(t, readerPKIOptions{})
	if _, err := SignReaderAuth(pki.key, cose.AlgorithmES256, pki.chain(), transcript, bare); err == nil {
		t.Error("SignReaderAuth accepted an unwrapped ItemsRequest")
	}
}

// ---------------------------------------------------------------------------
// x5chain handling
// ---------------------------------------------------------------------------

func TestReaderAuthRequiresX5Chain(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{})
	transcript := testReaderTranscript("a")
	docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}

	// Signing refuses an empty chain outright — 9.1.4.4 makes at least one
	// certificate mandatory.
	if _, err := SignReaderAuth(pki.key, cose.AlgorithmES256, nil, transcript, docRequest.ItemsRequest); err == nil {
		t.Error("SignReaderAuth accepted an empty x5chain")
	}

	// And a signature whose header 33 was stripped afterwards is unverifiable:
	// there is no public key to check it with.
	payload, err := readerAuthenticationBytes(transcript, docRequest.ItemsRequest)
	if err != nil {
		t.Fatalf("readerAuthenticationBytes: %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, pki.key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers, Payload: payload}
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	msg.Payload = nil
	stripped, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	docRequest.ReaderAuth = stripped

	_, err = pki.verifier().VerifyReaderAuth(docRequest, transcript)
	if err == nil {
		t.Fatal("a readerAuth with no x5chain verified")
	}
	if !strings.Contains(err.Error(), "x5chain") {
		t.Errorf("error does not name x5chain: %v", err)
	}
}

// TestReaderAuthLeafOnlyChainNeedsPinnedIntermediate is the deployment shape the
// document signer path already handles: a reader that ships only its own
// certificate is verifiable exactly when the wallet's trust model carries the
// issuing CA as an intermediate.
func TestReaderAuthLeafOnlyChainNeedsPinnedIntermediate(t *testing.T) {
	// Three levels, so the CA that signs the reader is not itself the anchor.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Requestors Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Relying Parties CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}

	readerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate reader key: %v", err)
	}
	readerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0xEADE13),
		Subject:               pkix.Name{CommonName: "Reader under intermediate"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{isoMdocReaderAuthEKU},
	}
	readerDER, err := x509.CreateCertificate(rand.Reader, readerTemplate, interCert, &readerKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("create reader cert: %v", err)
	}
	readerCert, err := x509.ParseCertificate(readerDER)
	if err != nil {
		t.Fatalf("parse reader cert: %v", err)
	}

	transcript := testReaderTranscript("a")
	docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	// Leaf only — the intermediate is deliberately not shipped.
	readerAuth, err := SignReaderAuth(
		readerKey, cose.AlgorithmES256, []*x509.Certificate{readerCert}, transcript, docRequest.ItemsRequest)
	if err != nil {
		t.Fatalf("SignReaderAuth: %v", err)
	}
	docRequest.ReaderAuth = readerAuth

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	// Root alone: no path exists.
	rootOnly := NewVerifierFromOptions(func() x509.VerifyOptions {
		return x509.VerifyOptions{Roots: roots}
	})
	if _, err := rootOnly.VerifyReaderAuth(docRequest, transcript); err == nil {
		t.Error("a leaf-only chain verified without the pinned intermediate")
	}

	// Root plus pinned intermediate, which is how the wallet's trust model splits
	// a pinned chain.
	intermediates := x509.NewCertPool()
	intermediates.AddCert(interCert)
	pinned := NewVerifierFromOptions(func() x509.VerifyOptions {
		return x509.VerifyOptions{Roots: roots, Intermediates: intermediates}
	})
	if _, err := pinned.VerifyReaderAuth(docRequest, transcript); err != nil {
		t.Errorf("a leaf-only chain failed with the intermediate pinned: %v", err)
	}
}

// TestReaderAuthAcceptsBareSingleCertificate covers a reader that puts one
// certificate at header 33 unwrapped rather than as a one-element array. The
// COSE x5chain definition allows it and refusing would reject a conformant
// reader over an encoding choice with no security meaning.
func TestReaderAuthAcceptsBareSingleCertificate(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{})
	transcript := testReaderTranscript("a")
	docRequest, err := NewDocRequest(testItemsRequest(AgeVerificationDocType), nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	payload, err := readerAuthenticationBytes(transcript, docRequest.ItemsRequest)
	if err != nil {
		t.Fatalf("readerAuthenticationBytes: %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, pki.key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers, Payload: payload}
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Unprotected[int64(33)] = pki.cert.Raw // bare bstr, not an array
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	msg.Payload = nil
	encoded, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	docRequest.ReaderAuth = encoded

	result, err := pki.verifier().VerifyReaderAuth(docRequest, transcript)
	if err != nil {
		t.Fatalf("a bare single certificate at header 33 was refused: %v", err)
	}
	if len(result.Chain) != 1 {
		t.Errorf("Chain length = %d, want 1", len(result.Chain))
	}
}

// ---------------------------------------------------------------------------
// Trust: anchors, dates, revocation
// ---------------------------------------------------------------------------

func TestReaderAuthRejectsUntrustedCA(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{untrustedCA: true, commonName: "Rogue Reader"})
	transcript := testReaderTranscript("a")
	docRequest := signedDocRequest(t, pki, transcript, testItemsRequest(AgeVerificationDocType))

	_, err := pki.verifier().VerifyReaderAuth(docRequest, transcript)
	if err == nil {
		t.Fatal("a reader certificate from an untrusted CA verified")
	}
	// The diagnosis has to name the reader: "not pinned at all" and "missing an
	// intermediate" look identical in the bare x509 error.
	for _, want := range []string{"chain verification failed", "Rogue Reader"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not contain %q: %v", want, err)
		}
	}
}

func TestReaderAuthRejectsExpiredCertificate(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{
		notBefore: time.Now().Add(-48 * time.Hour),
		notAfter:  time.Now().Add(-24 * time.Hour),
	})
	transcript := testReaderTranscript("a")
	docRequest := signedDocRequest(t, pki, transcript, testItemsRequest(AgeVerificationDocType))

	if _, err := pki.verifier().VerifyReaderAuth(docRequest, transcript); err == nil {
		t.Error("an expired reader certificate verified")
	}

	// The same certificate inside its validity window, to prove the rejection was
	// about dates and not about the fixture.
	past := NewVerifierWithClock([]*x509.Certificate{pki.rootCert}, time.Now().Add(-36*time.Hour))
	if _, err := past.VerifyReaderAuth(docRequest, transcript); err != nil {
		t.Errorf("the certificate failed inside its own validity window: %v", err)
	}
}

// TestReaderAuthRejectsRevokedReader is the 9.1.4 half of the 9.3.3 requirement
// that a party performing path validation have "access to certificate revocation
// information". The reader is entirely genuine — real chain, valid dates, real
// signature — and has simply been withdrawn.
//
// This is the case the wallet exists offline for, and the one the CRL-deletion
// defect in eudi/trustmodel.go would silently fail open on.
func TestReaderAuthRevocation(t *testing.T) {
	pki := newReaderPKI(t, readerPKIOptions{commonName: "Withdrawn Reader"})
	transcript := testReaderTranscript("a")
	docRequest := signedDocRequest(t, pki, transcript, testItemsRequest(AgeVerificationDocType))

	// An empty CRL set: nothing is revoked, so this must pass and proves the
	// fixture is good.
	clean := NewVerifierFromTrustSource(staticTrustSource{roots: pki.roots()})
	if _, err := clean.VerifyReaderAuth(docRequest, transcript); err != nil {
		t.Fatalf("sanity: an unrevoked reader should verify: %v", err)
	}

	crl := revokeCert(t, pki.rootCert, pki.rootKey, pki.cert)
	revoked := NewVerifierFromTrustSource(staticTrustSource{
		roots: pki.roots(),
		crls:  []*x509.RevocationList{crl},
	})
	_, err := revoked.VerifyReaderAuth(docRequest, transcript)
	if err == nil {
		t.Fatal("a revoked reader certificate verified")
	}
	// The role has to be named correctly: reporting a withdrawn reader as a
	// withdrawn document signer sends the operator after the wrong certificate.
	if !strings.Contains(err.Error(), "mdoc reader's chain is revoked") {
		t.Errorf("revocation error does not identify the reader's chain: %v", err)
	}
	if strings.Contains(err.Error(), "document signer") {
		t.Errorf("revocation error blames the document signer for a reader certificate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The Table B.6 extended key usage: reported, not enforced
// ---------------------------------------------------------------------------

// TestReaderAuthEKUIsReportedNotEnforced pins the deliberate difference from the
// document signer check. Annex B.1.7 says the reader *should* use the Table B.6
// profile, and Yivi's own relying party certificates carry clientAuth and the
// Yivi scheme extension with no ISO usage at all — a hard gate here would refuse
// every reader the wallet can currently talk to, and report it as though the
// reader were untrustworthy.
func TestReaderAuthEKUIsReportedNotEnforced(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options readerPKIOptions
		wantEKU bool
	}{
		{
			name:    "ISO 18013-5 mdlReaderAuth",
			options: readerPKIOptions{unknownEKU: []asn1.ObjectIdentifier{isoMdocReaderAuthEKU}},
			wantEKU: true,
		},
		{
			name:    "ISO 23220-4 mdoc reader auth",
			options: readerPKIOptions{unknownEKU: []asn1.ObjectIdentifier{isoGenericMdocReaderAuthEKU}},
			wantEKU: true,
		},
		{
			// What a Yivi relying party certificate actually carries today.
			name: "clientAuth only, as Yivi issues",
			options: readerPKIOptions{
				noUnknown: true,
				eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			wantEKU: false,
		},
		{
			name:    "no extended key usage at all",
			options: readerPKIOptions{noUnknown: true},
			wantEKU: false,
		},
		{
			name:    "anyExtendedKeyUsage",
			options: readerPKIOptions{noUnknown: true, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
			wantEKU: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newReaderPKI(t, tc.options)
			transcript := testReaderTranscript("a")
			docRequest := signedDocRequest(t, pki, transcript, testItemsRequest(AgeVerificationDocType))

			result, err := pki.verifier().VerifyReaderAuth(docRequest, transcript)
			if err != nil {
				t.Fatalf("verification failed on the extended key usage, which is reported and not enforced: %v", err)
			}
			if result.HasReaderAuthEKU != tc.wantEKU {
				t.Errorf("HasReaderAuthEKU = %v, want %v", result.HasReaderAuthEKU, tc.wantEKU)
			}
		})
	}
}

// TestCheckReaderAuthEKUDiagnostics covers the message a deployment that DOES
// require the usage would show. Naming what the certificate carries is the whole
// diagnosis: clientAuth means a TLS profile needs amending, an unregistered OID
// means a reference implementation invented a usage.
func TestCheckReaderAuthEKUDiagnostics(t *testing.T) {
	withClientAuth := newReaderPKI(t, readerPKIOptions{
		noUnknown: true,
		eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	err := checkReaderAuthEKU(withClientAuth.cert)
	if err == nil {
		t.Fatal("checkReaderAuthEKU accepted a clientAuth-only certificate")
	}
	for _, want := range []string{"1.0.18013.5.1.6", "clientAuth"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}

	none := newReaderPKI(t, readerPKIOptions{noUnknown: true})
	err = checkReaderAuthEKU(none.cert)
	if err == nil {
		t.Fatal("checkReaderAuthEKU accepted a certificate with no extended key usage")
	}
	if !strings.Contains(err.Error(), "no extended key usage") {
		t.Errorf("error does not identify the absent extension: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The mDL carve-out of 7.2.1
// ---------------------------------------------------------------------------

// TestReleasableWithoutReaderAuthMDL is the clause that stops the wallet's
// hard-fail policy from being applied blindly: "An mDL shall not require mdoc
// reader authentication as a precondition for the release of any of the
// mandatory data elements", while "An mDL may require mdoc reader authentication
// before releasing data elements not marked as mandatory in Table 5."
//
// So a request mixing both must split, not fail.
func TestReleasableWithoutReaderAuthMDL(t *testing.T) {
	items := ItemsRequest{
		DocType: MDLDocType,
		NameSpaces: map[string]DataElements{
			MDLNameSpace: {
				// Mandatory in Table 5 — shall not be gated on reader auth.
				"family_name": false,
				"birth_date":  false,
				"portrait":    true,
				// Optional in Table 5 — may be refused without reader auth.
				"age_over_18":      false,
				"nationality":      false,
				"resident_address": true,
			},
		},
	}

	releasable, withheld := ReleasableWithoutReaderAuth(items)

	got := releasable[MDLNameSpace]
	if len(got) != 3 {
		t.Fatalf("releasable has %d elements, want 3: %v", len(got), got)
	}
	for _, element := range []string{"family_name", "birth_date", "portrait"} {
		if _, present := got[element]; !present {
			t.Errorf("%s is mandatory in Table 5 but was withheld from an unauthenticated reader", element)
		}
	}

	// IntentToRetain has to survive the split: it changes what the holder is
	// being asked to agree to.
	if !got["portrait"] {
		t.Error("IntentToRetain was dropped for portrait")
	}
	if got["family_name"] {
		t.Error("IntentToRetain was invented for family_name")
	}

	want := []string{"age_over_18", "nationality", "resident_address"}
	if len(withheld[MDLNameSpace]) != len(want) {
		t.Fatalf("withheld = %v, want %v", withheld[MDLNameSpace], want)
	}
	for i, element := range want {
		// Sorted output, so this is an exact comparison rather than a set check.
		if withheld[MDLNameSpace][i] != element {
			t.Errorf("withheld[%d] = %q, want %q (is the result sorted?)", i, withheld[MDLNameSpace][i], element)
		}
	}
}

// TestReleasableWithoutReaderAuthMDLMandatoryOnly is the case NOTE 3 is about:
// a reader with no reader authentication asking only for what Table 5 makes
// mandatory. Nothing may be withheld, so the wallet must not terminate — the
// holder is "always able to use the mDL as a driving licence".
func TestReleasableWithoutReaderAuthMDLMandatoryOnly(t *testing.T) {
	elements := DataElements{}
	for element := range mdlMandatoryElements {
		elements[element] = false
	}
	items := ItemsRequest{DocType: MDLDocType, NameSpaces: map[string]DataElements{MDLNameSpace: elements}}

	releasable, withheld := ReleasableWithoutReaderAuth(items)

	if len(releasable[MDLNameSpace]) != len(mdlMandatoryElements) {
		t.Errorf("releasable has %d of %d mandatory elements",
			len(releasable[MDLNameSpace]), len(mdlMandatoryElements))
	}
	if len(withheld) != 0 {
		t.Errorf("withheld = %v; 7.2.1 forbids gating any mandatory element on reader authentication", withheld)
	}
}

// TestMDLMandatoryElementsMatchTable5 pins the set itself. A missing entry
// silently narrows the carve-out — the wallet would refuse an element the
// standard says it shall not refuse — and no other test would notice.
func TestMDLMandatoryElementsMatchTable5(t *testing.T) {
	// The "Presence: M" rows of Table 5, in the order the table prints them.
	want := []string{
		"family_name",
		"given_name",
		"birth_date",
		"issue_date",
		"expiry_date",
		"issuing_country",
		"issuing_authority",
		"document_number",
		"portrait",
		"driving_privileges",
		"un_distinguishing_sign",
	}
	if len(mdlMandatoryElements) != len(want) {
		t.Errorf("mdlMandatoryElements has %d entries, Table 5 marks %d mandatory",
			len(mdlMandatoryElements), len(want))
	}
	for _, element := range want {
		if !mdlMandatoryElements[element] {
			t.Errorf("%q is mandatory in Table 5 but missing from mdlMandatoryElements", element)
		}
	}
	// Elements that are Optional in Table 5 and must not have crept in.
	for _, element := range []string{"age_over_18", "sex", "height", "nationality", "birth_place"} {
		if mdlMandatoryElements[element] {
			t.Errorf("%q is optional in Table 5 but is listed as mandatory", element)
		}
	}
}

// TestReleasableWithoutReaderAuthIsMDLOnly keeps the carve-out from leaking. For
// every other docType nothing is releasable, which is what makes the wallet's
// hard-fail policy the operative rule there.
func TestReleasableWithoutReaderAuthIsMDLOnly(t *testing.T) {
	for _, docType := range []string{
		AgeVerificationDocType,
		"eu.europa.ec.eudi.pid.1",
		"com.example.unknown",
	} {
		t.Run(docType, func(t *testing.T) {
			items := testItemsRequest(docType, "family_name", "portrait", "age_over_18")
			releasable, withheld := ReleasableWithoutReaderAuth(items)
			if len(releasable) != 0 {
				t.Errorf("releasable = %v for docType %q; only the mDL has a carve-out", releasable, docType)
			}
			if len(withheld[docType]) != 3 {
				t.Errorf("withheld = %v, want all three elements", withheld[docType])
			}
		})
	}
}

// TestReleasableWithoutReaderAuthForeignNamespace covers an issuing authority's
// own namespace on an mDL. Table 5's presence column says nothing about an
// element of the same name in a domestic namespace, so the carve-out does not
// extend to it and such an element stays refusable.
func TestReleasableWithoutReaderAuthForeignNamespace(t *testing.T) {
	items := ItemsRequest{
		DocType: MDLDocType,
		NameSpaces: map[string]DataElements{
			MDLNameSpace:             {"family_name": false},
			"org.example.domestic.1": {"family_name": false, "portrait": false},
		},
	}

	releasable, withheld := ReleasableWithoutReaderAuth(items)

	if _, present := releasable[MDLNameSpace]["family_name"]; !present {
		t.Error("family_name in the mDL namespace should be releasable")
	}
	if len(releasable["org.example.domestic.1"]) != 0 {
		t.Errorf("elements of a domestic namespace were released: %v", releasable["org.example.domestic.1"])
	}
	if len(withheld["org.example.domestic.1"]) != 2 {
		t.Errorf("withheld = %v, want both domestic elements", withheld["org.example.domestic.1"])
	}
}
