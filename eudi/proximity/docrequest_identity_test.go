package proximity

import (
	"crypto/x509"
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// TWO DOCREQUESTS, ONE DOCTYPE
// ============================================================
//
// 8.3.2.1.2.1 says a DeviceRequest carries docRequests, plural, and says nothing
// about their docTypes being distinct. A reader is free to send two for the same
// one — the portrait and age_over_18 are different questions, and splitting them
// is how a reader asks for the second without the first being implied.
//
// The response then has to keep them apart. Each returned document is stripped
// against, and has its `errors` computed against, the ItemsRequest of the request
// it answers; each request that is NOT answered gets a documentError. Joining a
// returned document back to its request by docType alone gets both wrong at once:
// the document is measured against the wrong ItemsRequest, and the other request
// looks served when nothing was returned for it.
//
// These tests are what pins that join to the query id instead.

// TestDuplicateDocTypeRequestsAreAnsweredIndividually is the whole thing end to
// end: two requests for one docType, one of them answered.
func TestDuplicateDocTypeRequestsAreAnsweredIndividually(t *testing.T) {
	w, issuer := newWallet(t)
	pki := newReaderPKI(t)

	// Answer the SECOND request only, naming it by its query id. doc1 is what
	// DcqlQueryFromDeviceRequest called the second docRequest.
	w.answer = func(request DisclosureRequest) ([]Selection, error) {
		return []Selection{{
			QueryId:  "doc1",
			Document: w.credentials[testDocType],
			Reveal:   map[string][]string{testNamespace: {"age_over_21"}},
		}}, nil
	}

	tx := newTransaction(t, w,
		SessionConfig{Readers: pki.trust()},
		ReaderConfig{
			Signer:    pki.key,
			Algorithm: cose.AlgorithmES256,
			Chain:     pki.chain(),
			Issuers:   mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
		})

	request, err := tx.reader.Request(
		itemsFor(testDocType, testNamespace, "age_over_18"),
		itemsFor(testDocType, testNamespace, "age_over_21"),
	)
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
	document := response.Documents[0]

	disclosed, err := document.DisclosedElements()
	if err != nil {
		t.Fatalf("DisclosedElements: %v", err)
	}
	if len(disclosed[testNamespace]) != 1 || disclosed[testNamespace][0] != "age_over_21" {
		t.Errorf("disclosed %v, want just age_over_21", disclosed[testNamespace])
	}

	// The document answers the second request, and that request is satisfied in
	// full. Measured against the FIRST request it would carry an error for
	// age_over_18 — an element this document was never asked for.
	if len(document.Errors) != 0 {
		t.Errorf("document reports %v, but the request it answers was satisfied in full", document.Errors)
	}

	// And the first request, which nothing was returned for, is reported. Keyed by
	// docType it looked served by the second request's document.
	if len(response.DocumentErrors) != 1 {
		t.Fatalf("got %d documentErrors, want 1 for the unanswered request", len(response.DocumentErrors))
	}
	if code, ok := response.DocumentErrors[0][testDocType]; !ok {
		t.Errorf("documentError names %v, want %s", response.DocumentErrors[0], testDocType)
	} else if code != mdoc.ErrorCodeDataNotReturned {
		t.Errorf("documentError code = %d, want %d", code, mdoc.ErrorCodeDataNotReturned)
	}
}

// TestUnansweredDuplicateDocTypesAreReportedOnce: both requests unanswered. A
// DocumentError can only name a docType, so there is nothing to tell two of them
// apart — saying it twice would not say more.
func TestUnansweredDuplicateDocTypesAreReportedOnce(t *testing.T) {
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

	request, err := tx.reader.Request(
		itemsFor(testDocType, testNamespace, "age_over_18"),
		itemsFor(testDocType, testNamespace, "age_over_21"),
	)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	response, err := tx.reader.ReadResponse(tx.exchange(t, request))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	if len(response.DocumentErrors) != 1 {
		t.Errorf("got %d documentErrors, want 1: a docType is all a DocumentError can name",
			len(response.DocumentErrors))
	}
}

// ---------------------------------------------------------------------------
// The join itself
// ---------------------------------------------------------------------------

// TestQueryIndexRoundTrips: queryId and queryIndex are inverses, and an id from
// somewhere else is reported as unusable rather than guessed at.
func TestQueryIndexRoundTrips(t *testing.T) {
	for _, index := range []int{0, 1, 7, 42} {
		back, ok := queryIndex(queryId(index))
		if !ok || back != index {
			t.Errorf("queryIndex(queryId(%d)) = %d, %v; want %d, true", index, back, ok, index)
		}
	}

	for _, id := range []string{"", "doc", "credential0", "doc-1", "docx", "0", "doc1x"} {
		if index, ok := queryIndex(id); ok {
			t.Errorf("queryIndex(%q) = %d, true; an id this package did not mint is not an index", id, index)
		}
	}
}

// TestRequestedForUsesTheQueryIdOverTheDocType is the resolution rule in
// isolation: the id wins, and it is read past the documents consent filtered out.
func TestRequestedForUsesTheQueryIdOverTheDocType(t *testing.T) {
	documents := []RequestedDocument{
		{DocType: testDocType, Requested: itemsFor(testDocType, testNamespace, "age_over_18")},
		{DocType: mdoc.MDLDocType, Requested: itemsFor(mdoc.MDLDocType, mdoc.MDLNameSpace, "portrait")},
		{DocType: testDocType, Requested: itemsFor(testDocType, testNamespace, "age_over_21")},
	}
	// The mDL was not servable, so the wallet was offered documents 0 and 2, as
	// queries doc0 and doc1.
	offered := []int{0, 2}
	served := make([]bool, len(documents))

	index, err := requestedFor(documents, offered, served,
		Selection{QueryId: "doc1", Document: mdoc.MDoc{DocType: testDocType}})
	if err != nil {
		t.Fatalf("requestedFor: %v", err)
	}
	if index != 2 {
		t.Errorf("query doc1 resolved to document %d, want 2 — the offer list skips the unservable mDL", index)
	}

	// An id no query in this request has.
	if _, err := requestedFor(documents, offered, served,
		Selection{QueryId: "doc9", Document: mdoc.MDoc{DocType: testDocType}}); err == nil {
		t.Error("a selection naming a query this request does not have was accepted")
	}

	// The right query, the wrong credential. Presenting it would send a document no
	// DocRequest asked for, so it is refused rather than quietly reassigned.
	if _, err := requestedFor(documents, offered, served,
		Selection{QueryId: "doc0", Document: mdoc.MDoc{DocType: mdoc.MDLDocType}}); err == nil {
		t.Error("a selection answering a query with the wrong docType was accepted")
	}
}

// TestRequestedForFallsBackToTheFirstUnservedRequest: a Discloser that carries no
// query ids still gets a sensible join — each selection takes the next unanswered
// request of its docType rather than all of them taking the first.
func TestRequestedForFallsBackToTheFirstUnservedRequest(t *testing.T) {
	documents := []RequestedDocument{
		{DocType: testDocType, Requested: itemsFor(testDocType, testNamespace, "age_over_18")},
		{DocType: testDocType, Requested: itemsFor(testDocType, testNamespace, "age_over_21")},
	}
	offered := []int{0, 1}
	served := make([]bool, len(documents))
	selection := Selection{Document: mdoc.MDoc{DocType: testDocType}} // no QueryId

	first, err := requestedFor(documents, offered, served, selection)
	if err != nil {
		t.Fatalf("requestedFor: %v", err)
	}
	if first != 0 {
		t.Errorf("first selection resolved to document %d, want 0", first)
	}
	served[first] = true

	second, err := requestedFor(documents, offered, served, selection)
	if err != nil {
		t.Fatalf("requestedFor: %v", err)
	}
	if second != 1 {
		t.Errorf("second selection resolved to document %d, want 1", second)
	}
	served[second] = true

	// Nothing left to answer.
	if _, err := requestedFor(documents, offered, served, selection); err == nil {
		t.Error("a third selection for a docType asked for twice was accepted")
	}
}
