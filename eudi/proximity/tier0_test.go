package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// TIER 0: THE WHOLE TRANSACTION, NO RADIO
// ============================================================
//
// Session and Reader run against each other over net.Pipe, with the real BLE
// framing of 8.3.3.1.1.6 in between. Every clause from engagement to termination
// is exercised by bytes actually crossing a connection, which is what the
// per-clause unit tests in eudi/credentials/mdoc cannot do: they can only assert
// that this package agrees with itself.
//
// The MTU is deliberately small so that every message is split into several parts
// and reassembled. A transaction that only ever fits in one chunk does not test
// the framing at all, and chunk reassembly is exactly the kind of thing that works
// until a portrait is requested.

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// testMTU is small enough to force multi-part messages. Real BLE negotiates
// something in the hundreds; 48 keeps the payload at 45 bytes a part, so even a
// bare DeviceRequest arrives in pieces.
const testMTU = 48

// link is one end of the byte pipe, with the BLE chunking of 8.3.3.1.1.6 over it.
//
// The uint16 length prefix is not part of 18013-5. It stands in for the message
// boundary that BLE provides for free: each part is one GATT write or one
// notification, so a real transport never has to be told where a part ends. A
// stream does.
type link struct {
	conn      net.Conn
	assembler mdoc.MessageAssembler
}

func (l *link) send(message []byte) error {
	parts, err := mdoc.ChunkMessage(message, testMTU)
	if err != nil {
		return err
	}
	for _, part := range parts {
		if err := binary.Write(l.conn, binary.BigEndian, uint16(len(part))); err != nil {
			return err
		}
		if _, err := l.conn.Write(part); err != nil {
			return err
		}
	}
	return nil
}

func (l *link) receive() ([]byte, error) {
	for {
		var size uint16
		if err := binary.Read(l.conn, binary.BigEndian, &size); err != nil {
			return nil, err
		}
		part := make([]byte, size)
		if _, err := io.ReadFull(l.conn, part); err != nil {
			return nil, err
		}
		message, complete, err := l.assembler.Add(part)
		if err != nil {
			return nil, err
		}
		if complete {
			return message, nil
		}
	}
}

// ---------------------------------------------------------------------------
// The wallet under test
// ---------------------------------------------------------------------------

// wallet is a minimal but honest Discloser and DeviceKeyBinder: it holds issued
// credentials and releases whatever of them the (already narrowed) request asks
// for.
//
// It does no candidate ranking and shows nothing to a user, because those are the
// parts Session deliberately does not own. What it must get right is the part the
// response depends on: revealing only elements it actually holds, so that the
// errors machinery has something real to report.
type wallet struct {
	credentials map[string]mdoc.MDoc // docType -> issued credential
	holders     map[string]mdoc.Holder

	// namespaces maps docType to the namespace that credential's elements live in.
	// Not one value: an mDL's elements are in org.iso.18013.5.1 while an age
	// verification credential's are in its own, and the 7.2.1 carve-out is scoped
	// to the namespace as well as the element.
	namespaces map[string]string

	// refuse makes the user decline everything, for the consent-refusal path.
	refuse bool

	// breakSigning makes device key resolution fail, so the response cannot be
	// assembled. Used to prove that a credential instance is NOT spent when a step
	// after consent fails.
	breakSigning bool

	// commits counts Commit calls. A real wallet spends a single-use credential
	// instance there, so this standing in for "how many instances were burned" is
	// the property the ordering tests are really about.
	commits int

	// lastRequest records what the wallet was asked, so tests can assert on the
	// narrowing that happened before consent.
	lastRequest DisclosureRequest

	// answer replaces the selection logic below, for the tests whose whole subject
	// is WHICH request a selection answers. The loop below cannot express that: it
	// is keyed by docType and so can never return two selections of one.
	answer func(DisclosureRequest) ([]Selection, error)
}

func (w *wallet) Disclose(request DisclosureRequest) ([]Selection, error) {
	w.lastRequest = request
	if w.refuse {
		return nil, nil
	}
	if w.answer != nil {
		return w.answer(request)
	}

	var selections []Selection
	for _, document := range request.Documents {
		credential, ok := w.credentials[document.DocType]
		if !ok {
			continue
		}
		namespace := w.namespaces[document.DocType]

		held, err := credential.DisclosedElements()
		if err != nil {
			return nil, err
		}
		available := make(map[string]bool, len(held[namespace]))
		for _, identifier := range held[namespace] {
			available[identifier] = true
		}

		// Only what is both permitted and actually held. Asking for an element the
		// wallet does not have is not an error here — it becomes a Table 9 error in
		// the response, which is the behaviour 8.3.2.1.2.1 asks for.
		var reveal []string
		for _, elements := range document.Permitted.NameSpaces {
			for identifier := range elements {
				if available[identifier] {
					reveal = append(reveal, identifier)
				}
			}
		}
		if len(reveal) == 0 {
			continue
		}

		selections = append(selections, Selection{
			Document: credential,
			Reveal:   map[string][]string{namespace: reveal},
		})
	}
	return selections, nil
}

// Commit stands in for spending the reserved single-use instances.
func (w *wallet) Commit() error {
	w.commits++
	return nil
}

func (w *wallet) HolderForDeviceKey(deviceKey *ecdsa.PublicKey) (mdoc.Holder, error) {
	if w.breakSigning {
		return nil, fmt.Errorf("no device key (test)")
	}
	for _, holder := range w.holders {
		if holder.PublicKey().Equal(deviceKey) {
			return holder, nil
		}
	}
	return nil, io.EOF // any error; the session only reports it
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const (
	testNamespace = mdoc.AgeVerificationDocType
	testDocType   = mdoc.AgeVerificationDocType
)

// issueInto mints a credential of docType into the wallet.
func issueInto(t *testing.T, w *wallet, issuer *mdoc.Issuer, docType, namespace string, claims map[string]any) {
	t.Helper()

	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	credential, err := issuer.Issue(docType, namespace, claims, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue %s: %v", docType, err)
	}
	w.credentials[docType] = *credential
	w.holders[docType] = holder
	w.namespaces[docType] = namespace
}

// newWallet builds a wallet holding one age verification credential.
func newWallet(t *testing.T) (*wallet, *mdoc.Issuer) {
	t.Helper()

	issuer, err := mdoc.NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	w := &wallet{
		credentials: map[string]mdoc.MDoc{},
		holders:     map[string]mdoc.Holder{},
		namespaces:  map[string]string{},
	}
	issueInto(t, w, issuer, testDocType, testNamespace, map[string]any{
		"age_over_18": true,
		"age_over_21": false,
	})
	return w, issuer
}

// readerPKI is a reader identity and the CA a wallet trusts it through.
type readerPKI struct {
	rootCert *x509.Certificate
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
}

func (p readerPKI) chain() []*x509.Certificate {
	return []*x509.Certificate{p.cert, p.rootCert}
}

func (p readerPKI) trust() *mdoc.Verifier {
	pool := x509.NewCertPool()
	pool.AddCert(p.rootCert)
	return mdoc.NewVerifierFromPool(pool)
}

func newReaderPKI(t *testing.T) readerPKI {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate reader CA key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0x0CA),
		Subject:               pkix.Name{CommonName: "Tier 0 Reader CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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

	readerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate reader key: %v", err)
	}
	readerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0xEADE12),
		Subject:               pkix.Name{CommonName: "Tier 0 mdoc Reader"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	readerDER, err := x509.CreateCertificate(rand.Reader, readerTemplate, rootCert, &readerKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create reader cert: %v", err)
	}
	readerCert, err := x509.ParseCertificate(readerDER)
	if err != nil {
		t.Fatalf("parse reader cert: %v", err)
	}

	return readerPKI{rootCert: rootCert, cert: readerCert, key: readerKey}
}

func itemsFor(docType, namespace string, elements ...string) mdoc.ItemsRequest {
	requested := mdoc.DataElements{}
	for _, element := range elements {
		requested[element] = false // intentToRetain
	}
	return mdoc.ItemsRequest{
		DocType:    docType,
		NameSpaces: map[string]mdoc.DataElements{namespace: requested},
	}
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

// transaction wires a Session and a Reader together over net.Pipe and runs the
// wallet in its own goroutine, because net.Pipe is unbuffered: a send blocks until
// the other side reads, so both parties cannot live on one goroutine.
type transaction struct {
	session *Session
	reader  *Reader
	readerL *link

	walletErr chan error

	// expectWalletErr inverts the cleanup assertion, for tests that deliberately
	// make the wallet side fail.
	expectWalletErr bool
}

func newTransaction(t *testing.T, w *wallet, cfg SessionConfig, readerCfg ReaderConfig) *transaction {
	t.Helper()

	cfg.Discloser = w
	cfg.DeviceKeys = w

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	qr, err := session.EngagementQR()
	if err != nil {
		t.Fatalf("EngagementQR: %v", err)
	}

	reader := NewReader(readerCfg)
	if err := reader.Engage(qr); err != nil {
		t.Fatalf("Engage: %v", err)
	}

	walletEnd, readerEnd := net.Pipe()
	tx := &transaction{
		session:   session,
		reader:    reader,
		readerL:   &link{conn: readerEnd},
		walletErr: make(chan error, 1),
	}

	go func() {
		defer close(tx.walletErr)
		defer walletEnd.Close()
		wl := &link{conn: walletEnd}
		for {
			message, err := wl.receive()
			if err != nil {
				return // pipe closed: the reader is done
			}
			reply, err := session.Handle(message)
			if err != nil {
				tx.walletErr <- err
				return
			}
			if reply != nil {
				if err := wl.send(reply); err != nil {
					return
				}
			}
			if session.Terminated() {
				return
			}
		}
	}()

	t.Cleanup(func() {
		readerEnd.Close()
		err := <-tx.walletErr
		switch {
		case tx.expectWalletErr && err == nil:
			t.Errorf("expected the wallet session to fail, but it did not")
		case !tx.expectWalletErr && err != nil:
			t.Errorf("wallet session failed: %v", err)
		}
	})

	return tx
}

// exchange sends one message and reads the reply.
func (tx *transaction) exchange(t *testing.T, message []byte) []byte {
	t.Helper()
	if err := tx.readerL.send(message); err != nil {
		t.Fatalf("send: %v", err)
	}
	reply, err := tx.readerL.receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	return reply
}

// ---------------------------------------------------------------------------
// The transaction
// ---------------------------------------------------------------------------

// TestTier0FullTransaction is the one that matters: a complete device retrieval
// between two independent implementations, ending in a response the reader
// verifies against its own transcript.
func TestTier0FullTransaction(t *testing.T) {
	w, issuer := newWallet(t)
	pki := newReaderPKI(t)

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{
			Signer:    pki.key,
			Algorithm: cose.AlgorithmES256,
			Chain:     pki.chain(),
			Issuers:   mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
		})

	request, err := tx.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}

	response, err := tx.reader.ReadResponse(tx.exchange(t, request))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	if response.Status != mdoc.ResponseStatusOK {
		t.Fatalf("response status = %d, want 0", response.Status)
	}
	if len(response.Documents) != 1 {
		t.Fatalf("got %d documents, want 1", len(response.Documents))
	}

	// The verification that proves the whole chain: issuer signature, certificate
	// path, AND the device signature over a transcript the reader built itself from
	// the QR it scanned and the ephemeral key it generated.
	results, err := tx.reader.Verify(response, testNamespace, testDocType)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d verification results, want 1", len(results))
	}
	if !results[0].Valid || !results[0].DeviceAuthValid {
		t.Fatalf("verification failed: %+v", results[0])
	}

	claims := results[0].Attributes
	if value, ok := claims["age_over_18"]; !ok || value != true {
		t.Errorf("age_over_18 = %v (present: %t), want true", value, ok)
	}
	// Selective disclosure really happened: an element the reader did not ask for
	// must not be in the response, even though the credential carries it.
	if _, ok := claims["age_over_21"]; ok {
		t.Errorf("age_over_21 was disclosed but never requested: %v", claims)
	}
}

// TestTier0BothSidesDeriveTheSameTranscript is the check that would catch a
// tag-24 or byte-preservation mistake before it showed up as an opaque decryption
// failure. If the transcripts differed, nothing later in the flow could work.
func TestTier0BothSidesDeriveTheSameTranscript(t *testing.T) {
	w, issuer := newWallet(t)
	pki := newReaderPKI(t)

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{
			Signer:    pki.key,
			Algorithm: cose.AlgorithmES256,
			Chain:     pki.chain(),
			Issuers:   mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
		})

	request, err := tx.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if _, err := tx.reader.ReadResponse(tx.exchange(t, request)); err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	// Proven transitively and more strongly than by comparing structs: the session
	// keys are derived from SHA-256(SessionTranscriptBytes), the readerAuth was
	// verified by the wallet against its own transcript, and the deviceAuth was
	// verified by the reader against its own. Three independent uses agreeing is
	// what a struct comparison would not establish.
	if tx.reader.Transcript().Handover != nil {
		t.Errorf("QRHandover must be null (9.1.5.1), got %#v", tx.reader.Transcript().Handover)
	}
}

// ---------------------------------------------------------------------------
// 7.2.1: what an unauthenticated reader gets
// ---------------------------------------------------------------------------

// TestTier0UnauthenticatedReaderGetsNothing covers the mandatory-reader-auth
// policy for every docType that is not an mDL: nothing is released, and the reader
// is told so with a documentError rather than by having the session dropped.
func TestTier0UnauthenticatedReaderGetsNothing(t *testing.T) {
	w, issuer := newWallet(t)
	pki := newReaderPKI(t)

	// No Signer: a reader that sends no readerAuth at all, which 9.1.4.4's
	// `? "readerAuth"` permits it to be.
	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{Issuers: mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})})

	request, err := tx.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	response, err := tx.reader.ReadResponse(tx.exchange(t, request))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	if len(response.Documents) != 0 {
		t.Errorf("an unauthenticated reader received %d documents, want 0", len(response.Documents))
	}
	if len(response.DocumentErrors) != 1 {
		t.Fatalf("got %d documentErrors, want 1", len(response.DocumentErrors))
	}
	if _, ok := response.DocumentErrors[0][testDocType]; !ok {
		t.Errorf("documentError does not name %s: %v", testDocType, response.DocumentErrors[0])
	}
	// 8.3.2.1.2.3: documents withheld is not a failed response. The status stays 0
	// so that a mixed request can still return what it is allowed to.
	if response.Status != mdoc.ResponseStatusOK {
		t.Errorf("status = %d, want 0: withholding a document is not a response-level error", response.Status)
	}

	// And the user was never asked, because there was nothing releasable to ask
	// about.
	if w.lastRequest.Documents != nil {
		t.Errorf("the wallet was asked for consent on a request that could release nothing")
	}
}

// TestTier0UnauthenticatedReaderStillGetsMDLMandatoryElements is the 7.2.1
// carve-out, end to end: "An mDL shall not require mdoc reader authentication as a
// precondition for the release of any of the mandatory data elements."
//
// This is the case that makes a session-level hard fail wrong. A wallet that
// terminated here would be refusing to work as a driving licence for a reader that
// simply does not authenticate, which NOTE 3 says the holder must always be able
// to do.
func TestTier0UnauthenticatedReaderStillGetsMDLMandatoryElements(t *testing.T) {
	w, issuer := newWallet(t)
	issueInto(t, w, issuer, mdoc.MDLDocType, mdoc.MDLNameSpace, map[string]any{
		"family_name":     "de Vries",  // mandatory in Table 5
		"document_number": "NL1234567", // mandatory in Table 5
		"age_over_18":     true,        // NOT mandatory
	})
	pki := newReaderPKI(t)

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{Issuers: mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})})

	request, err := tx.reader.Request(
		itemsFor(mdoc.MDLDocType, mdoc.MDLNameSpace, "family_name", "document_number", "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	response, err := tx.reader.ReadResponse(tx.exchange(t, request))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	if len(response.Documents) != 1 {
		t.Fatalf("got %d documents, want 1: 7.2.1 forbids withholding the mandatory elements", len(response.Documents))
	}

	disclosed, err := response.Documents[0].DisclosedElements()
	if err != nil {
		t.Fatalf("DisclosedElements: %v", err)
	}
	got := map[string]bool{}
	for _, identifier := range disclosed[mdoc.MDLNameSpace] {
		got[identifier] = true
	}

	for _, mandatory := range []string{"family_name", "document_number"} {
		if !got[mandatory] {
			t.Errorf("%s was withheld from an unauthenticated reader, which 7.2.1 forbids", mandatory)
		}
	}
	// The optional element is the half that IS withheld: 7.2.1's "An mDL may require
	// mdoc reader authentication before releasing data elements not marked as
	// mandatory".
	if got["age_over_18"] {
		t.Errorf("age_over_18 is not mandatory in Table 5 and should have been withheld")
	}

	// And it is reported rather than silently dropped.
	errs := response.Documents[0].Errors
	if code, ok := errs[mdoc.MDLNameSpace]["age_over_18"]; !ok {
		t.Errorf("withheld age_over_18 was not reported in errors: %v", errs)
	} else if code != mdoc.ErrorCodeDataNotReturned {
		t.Errorf("error code = %d, want %d", code, mdoc.ErrorCodeDataNotReturned)
	}
}

// ---------------------------------------------------------------------------
// Partial satisfaction
// ---------------------------------------------------------------------------

// TestTier0PartialSatisfaction closes the gap DcqlQueryFromDeviceRequest
// documents and defers to the response-building step.
//
// 8.3.2.1.2.1: "The mdoc shall ignore all unknown data elements in a device
// retrieval mdoc request when processing the request."
//
// # Read this before trusting what it proves
//
// It covers ONE HALF of partial satisfaction: that once a document is being
// returned, everything requested and missing from it is reported with Table 9's
// code, computed against the original request rather than the narrowed one.
//
// It does NOT prove the reader gets a document at all, because the wallet here is
// a fake that answers straight out of document.Permitted and never runs a DCQL
// query. The real wallet does, and DCQL is all-or-nothing: a credential that
// cannot satisfy every claim is not a candidate, so a request naming one unheld
// element currently yields nothing. That half is still open and is pinned by
// TestIntegrationPartialSatisfactionIsSTILLOpenThroughDCQL, against the real
// candidate-selection path this test bypasses.
func TestTier0PartialSatisfaction(t *testing.T) {
	w, issuer := newWallet(t)
	pki := newReaderPKI(t)

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{
			Signer:    pki.key,
			Algorithm: cose.AlgorithmES256,
			Chain:     pki.chain(),
			Issuers:   mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
		})

	// age_over_99 is not in this credential.
	request, err := tx.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18", "age_over_99"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	response, err := tx.reader.ReadResponse(tx.exchange(t, request))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	if len(response.Documents) != 1 {
		t.Fatalf("got %d documents, want 1: the rest of the request is still answerable", len(response.Documents))
	}
	if response.Status != mdoc.ResponseStatusOK {
		t.Errorf("status = %d, want 0: a missing element is not a response-level error", response.Status)
	}

	document := response.Documents[0]
	disclosed, err := document.DisclosedElements()
	if err != nil {
		t.Fatalf("DisclosedElements: %v", err)
	}
	if len(disclosed[testNamespace]) != 1 || disclosed[testNamespace][0] != "age_over_18" {
		t.Errorf("disclosed %v, want just age_over_18", disclosed[testNamespace])
	}
	if code, ok := document.Errors[testNamespace]["age_over_99"]; !ok {
		t.Errorf("the element the wallet does not hold was not reported: %v", document.Errors)
	} else if code != mdoc.ErrorCodeDataNotReturned {
		t.Errorf("error code = %d, want %d", code, mdoc.ErrorCodeDataNotReturned)
	}
}

// TestTier0ConsentRefusal: the user says no. The reader is told, the session stays
// well-formed, and nothing leaks.
func TestTier0ConsentRefusal(t *testing.T) {
	w, issuer := newWallet(t)
	w.refuse = true
	pki := newReaderPKI(t)

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{
			Signer:    pki.key,
			Algorithm: cose.AlgorithmES256,
			Chain:     pki.chain(),
			Issuers:   mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
		})

	request, err := tx.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	response, err := tx.reader.ReadResponse(tx.exchange(t, request))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	if len(response.Documents) != 0 {
		t.Errorf("a refused request returned %d documents", len(response.Documents))
	}
	if len(response.DocumentErrors) != 1 {
		t.Errorf("got %d documentErrors, want 1", len(response.DocumentErrors))
	}
}

// ---------------------------------------------------------------------------
// Hostile readers
// ---------------------------------------------------------------------------

// TestTier0ReplayedReaderAuthIsRejected is the attack the transcript exists to
// stop: a genuine, correctly signed readerAuth from a DIFFERENT session.
//
// The wallet verifies against its own transcript, and its own transcript contains
// its own ephemeral key, so the signature cannot verify no matter how valid it was
// where it came from. The reader is then unauthenticated and gets the 7.2.1
// treatment rather than the data.
func TestTier0ReplayedReaderAuthIsRejected(t *testing.T) {
	w, issuer := newWallet(t)
	pki := newReaderPKI(t)
	issuers := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	readerCfg := ReaderConfig{
		Signer:    pki.key,
		Algorithm: cose.AlgorithmES256,
		Chain:     pki.chain(),
		Issuers:   issuers,
	}

	// A complete, genuine request built against one session...
	victim := newTransaction(t, w, SessionConfig{Readers: pki.trust()}, readerCfg)
	stolen, err := victim.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}

	// ...replayed at a second, which has a different EDeviceKey and so a different
	// transcript. It cannot even be decrypted, so the wallet reports Table 20's
	// session encryption error and terminates — the replay never reaches reader
	// authentication at all, which is a stronger rejection than failing it.
	target := newTransaction(t, w, SessionConfig{Readers: pki.trust()}, readerCfg)
	reply := target.exchange(t, stolen)

	data, err := mdoc.DecodeSessionData(reply)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if data.Status == nil {
		t.Fatalf("replayed request produced a response instead of a status")
	}
	if *data.Status != mdoc.StatusErrorSessionEncryption {
		t.Errorf("status = %d, want %d (session encryption error)", *data.Status, mdoc.StatusErrorSessionEncryption)
	}
	if !target.session.Terminated() {
		t.Errorf("session should be terminated after an undecryptable message")
	}
}

// TestTier0UntrustedReaderIsNotAuthenticated: the readerAuth verifies
// cryptographically, but the certificate chains to a CA the wallet does not hold.
// That is not authentication, and the 7.2.1 narrowing applies.
func TestTier0UntrustedReaderIsNotAuthenticated(t *testing.T) {
	w, issuer := newWallet(t)
	pki := newReaderPKI(t)
	stranger := newReaderPKI(t) // a perfectly good PKI the wallet has never heard of

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()}, // trusts pki, not stranger
		ReaderConfig{
			Signer:    stranger.key,
			Algorithm: cose.AlgorithmES256,
			Chain:     stranger.chain(),
			Issuers:   mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
		})

	request, err := tx.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	response, err := tx.reader.ReadResponse(tx.exchange(t, request))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	if len(response.Documents) != 0 {
		t.Errorf("a reader from an untrusted CA received %d documents", len(response.Documents))
	}
	if len(response.DocumentErrors) != 1 {
		t.Errorf("got %d documentErrors, want 1", len(response.DocumentErrors))
	}
}

// TestTier0GarbageIsRefusedWithoutCrashing: a first message that is not a
// SessionEstablishment at all.
func TestTier0GarbageIsRefusedWithoutCrashing(t *testing.T) {
	w, issuer := newWallet(t)
	pki := newReaderPKI(t)

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{Issuers: mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})})

	reply := tx.exchange(t, []byte{0xff, 0xff, 0xff, 0xff})

	data, err := mdoc.DecodeSessionData(reply)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if data.Status == nil || *data.Status != mdoc.StatusErrorCBORDecoding {
		t.Errorf("want Table 20 status %d for undecodable CBOR, got %v", mdoc.StatusErrorCBORDecoding, data.Status)
	}
	if !tx.session.Terminated() {
		t.Errorf("session should be terminated after an undecodable message")
	}
}

// ---------------------------------------------------------------------------
// Termination
// ---------------------------------------------------------------------------

// TestTier0TerminationEndsTheSession covers 9.1.1.4's requirement that both
// parties destroy their key material, from the reader's side.
func TestTier0TerminationEndsTheSession(t *testing.T) {
	w, issuer := newWallet(t)
	pki := newReaderPKI(t)

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{
			Signer:    pki.key,
			Algorithm: cose.AlgorithmES256,
			Chain:     pki.chain(),
			Issuers:   mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
		})

	request, err := tx.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if _, err := tx.reader.ReadResponse(tx.exchange(t, request)); err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	termination, err := tx.reader.Terminate()
	if err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	// A termination is not answered — there is nothing to say and the peer has
	// stopped reading — so this send is not followed by a receive.
	if err := tx.readerL.send(termination); err != nil {
		t.Fatalf("send termination: %v", err)
	}

	// Give the wallet goroutine the message before asserting on its state. The
	// pipe is synchronous, so a completed send means the bytes were read; the
	// wallet still has to act on them.
	deadline := time.Now().Add(2 * time.Second)
	for !tx.session.Terminated() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !tx.session.Terminated() {
		t.Fatalf("wallet did not terminate on receiving status %d", mdoc.StatusSessionTermination)
	}

	// And a terminated session refuses further work rather than quietly resuming.
	if _, err := tx.session.Handle([]byte{0x00}); err == nil {
		t.Errorf("a terminated session accepted another message")
	} else if !strings.Contains(err.Error(), "terminated") {
		t.Errorf("unexpected error from terminated session: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Spending a single-use instance
// ---------------------------------------------------------------------------
//
// An mdoc credential is stored as a batch of interchangeable single-use
// instances, and the wallet burns one per presentation
// (services.MdocInstanceSelector.Spend). WHEN it burns matters: a credential that
// loses a use on a disclosure that then failed has been spent for nothing, and
// nothing about the wallet looks broken afterwards. Session therefore calls
// Committer.Commit only once the response is assembled and nothing further can
// fail. These three tests pin that.

// TestTier0InstanceSpentOnSuccess: the ordinary case, exactly one commit.
func TestTier0InstanceSpentOnSuccess(t *testing.T) {
	w, issuer := newWallet(t)
	pki := newReaderPKI(t)

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{
			Signer:    pki.key,
			Algorithm: cose.AlgorithmES256,
			Chain:     pki.chain(),
			Issuers:   mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
		})

	request, err := tx.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	response, err := tx.reader.ReadResponse(tx.exchange(t, request))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if len(response.Documents) != 1 {
		t.Fatalf("got %d documents, want 1", len(response.Documents))
	}
	if w.commits != 1 {
		t.Errorf("commits = %d, want 1: a presented instance must be spent exactly once", w.commits)
	}
}

// TestTier0NothingSpentOnRefusal: the user declined, so no instance is consumed.
func TestTier0NothingSpentOnRefusal(t *testing.T) {
	w, issuer := newWallet(t)
	w.refuse = true
	pki := newReaderPKI(t)

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{
			Signer:    pki.key,
			Algorithm: cose.AlgorithmES256,
			Chain:     pki.chain(),
			Issuers:   mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
		})

	request, err := tx.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if _, err := tx.reader.ReadResponse(tx.exchange(t, request)); err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if w.commits != 0 {
		t.Errorf("commits = %d, want 0: a refused disclosure must not spend anything", w.commits)
	}
}

// TestTier0NothingSpentWhenAssemblyFails is the ordering test proper: consent was
// given and the instance was chosen, but signing fails afterwards. Nothing may be
// spent, because the reader never receives a presentation.
func TestTier0NothingSpentWhenAssemblyFails(t *testing.T) {
	w, issuer := newWallet(t)
	w.breakSigning = true
	pki := newReaderPKI(t)

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{
			Signer:    pki.key,
			Algorithm: cose.AlgorithmES256,
			Chain:     pki.chain(),
			Issuers:   mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
		})
	tx.expectWalletErr = true

	request, err := tx.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	// The wallet fails locally and sends nothing, so the reader's read ends when
	// the pipe closes rather than with a reply. That is the correct shape: a fault
	// the reader cannot be told about is not reported as a protocol status.
	if err := tx.readerL.send(request); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := tx.readerL.receive(); err == nil {
		t.Errorf("expected no reply after a local wallet failure")
	}

	if w.commits != 0 {
		t.Errorf("commits = %d, want 0: an instance must not be spent when the response cannot be built", w.commits)
	}
}
